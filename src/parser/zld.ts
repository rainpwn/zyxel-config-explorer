import type { FirewallConfig, Iface, Rule, RouteRule, VpnSite } from '../model'

// 255.255.255.0 -> 24; undefined if it is not a contiguous netmask.
function maskBits(mask: string): number | undefined {
  const o = mask.split('.').map(Number)
  if (o.length !== 4 || o.some(x => !(x >= 0 && x <= 255))) return undefined
  const n = ((o[0] << 24) | (o[1] << 16) | (o[2] << 8) | o[3]) >>> 0
  const bits = n.toString(2).replace(/0+$/, '')
  return bits.includes('0') ? undefined : bits.length
}

const IP = /^\d+\.\d+\.\d+\.\d+$/

// Parser for the Zyxel ZLD format (USG FLEX, ATP, VPN series): CLI blocks, a
// command at column 0 followed by its indented sub-commands.
// Secrets (keystring, password, psk) are never extracted: the parser reads
// only the known commands listed below.
export function parseZld(text: string): FirewallConfig {
  const cfg: FirewallConfig = {
    zones: [], interfaces: [],
    addresses: {}, addressGroups: {},
    services: {}, serviceGroups: {},
    rules: [], vpns: [], nats: [], routes: [], ifaceGroups: [],
  }
  const rules: (Rule & { prio: number })[] = []
  const routes: (RouteRule & { prio: number })[] = []
  const vpnPeer = new Map<string, string>() // isakmp/ikev2 policy -> peer address
  const vpnGw = new Map<string, string>() // crypto map -> isakmp/ikev2 policy
  const vpnPol = new Map<string, { local?: string; remote?: string }>()

  // Group lines into blocks: head = column-0 line, body = its indented lines.
  const blocks: { head: string[]; body: string[][] }[] = []
  for (const raw of text.split(/\r?\n/)) {
    if (!raw.trim() || raw.startsWith('!')) continue
    const t = raw.trim().split(/\s+/)
    if (/^\s/.test(raw)) blocks[blocks.length - 1]?.body.push(t)
    else blocks.push({ head: t, body: [] })
  }

  for (const { head: h, body } of blocks) {
    const sub = (k: string) => body.find(b => b[0] === k)
    const off = body.some(b => b[0] === 'deactivate' || (b[0] === 'no' && b[1] === 'activate'))

    if (h[0] === 'interface' && h[1] && !h[1].endsWith('_ppp')) {
      const name = h[1]
      const kind = name.includes(':') ? 'alias' : /^vlan/.test(name) ? 'vlan' : /^vti/.test(name) ? 'vti'
        : /^br/.test(name) ? 'bridge' : /^lag/.test(name) ? 'lag' : 'ethernet'
      const i: Iface = { name, kind, enabled: !body.some(b => b[0] === 'shutdown') }
      for (const b of body) {
        if (b[0] === 'type') i.role = b[1]
        else if (b[0] === 'description') i.description = b.slice(1).join(' ')
        else if (b[0] === 'vlan-id') i.vlanId = Number(b[1])
        else if (b[0] === 'port') i.link = b[1]
        else if (b[0] === 'ip' && b[1] === 'address' && IP.test(b[2] ?? '') && b[2] !== '0.0.0.0') {
          const bits = maskBits(b[3] ?? '')
          if (bits !== undefined) i.ip = `${b[2]}/${bits}`
        }
      }
      cfg.interfaces.push(i)
    } else if (h[0] === 'zone' && h[1]) {
      // wan1_ppp is the automatic PPPoE companion of wan1: count it as wan1
      const members = body.filter(b => b[0] === 'interface').map(b => b[1].replace(/_ppp$/, ''))
      cfg.zones.push({ name: h[1], interfaces: [...new Set(members)] })
    } else if (h[0] === 'address-object' && h[1] && h[2]) {
      const [, name, a, b] = h
      if (a === 'fqdn' || a === 'geography' || a === 'interface-subnet') {
        cfg.addresses[name] = { name, type: a, value: h.slice(3).join(' ') }
      } else if (a.includes('-')) {
        cfg.addresses[name] = { name, type: 'range', value: a }
      } else if (a.includes('/')) {
        cfg.addresses[name] = { name, type: 'cidr', value: a }
      } else if (b && maskBits(b) !== undefined) {
        cfg.addresses[name] = { name, type: 'cidr', value: `${a}/${maskBits(b)}` }
      } else {
        cfg.addresses[name] = { name, type: 'host', value: a }
      }
    } else if (h[0] === 'service-object' && h[1] && h[2]) {
      const [, name, proto, op, lo, hi] = h
      cfg.services[name] = {
        name,
        proto: proto === 'icmpv6' ? 'icmp6' : proto,
        value: op === 'eq' ? lo : op === 'range' ? `${lo}-${hi}` : h.slice(3).join(' '),
      }
    } else if (h[0] === 'object-group' && (h[1] === 'address' || h[1] === 'service') && h[2]) {
      const members = body.filter(b => b[0].endsWith('-object') || b[0] === 'object-group').map(b => b[1])
      const desc = sub('description')?.slice(1).join(' ')
      if (h[1] === 'address') cfg.addressGroups[h[2]] = { name: h[2], members, description: desc }
      else cfg.serviceGroups[h[2]] = { name: h[2], members }
    } else if (h[0] === 'secure-policy' && /^\d+$/.test(h[1] ?? '')) {
      const r: Rule & { prio: number } = {
        prio: Number(h[1]), order: 0, name: sub('name')?.[1] ?? h[1],
        // ZLD omits fields left at their default: the default is any
        from: 'any', to: 'any', sourceIp: 'any', destIp: 'any',
        service: 'any', user: 'any', schedule: 'any', action: 'allow', enabled: !off,
      }
      for (const b of body) {
        switch (b[0]) {
          case 'from': r.from = b[1]; break
          case 'to': r.to = b[1]; break
          case 'sourceip': r.sourceIp = b[1]; break
          case 'destinationip': r.destIp = b[1]; break
          case 'service': r.service = b[1]; break
          case 'user': r.user = b[1]; break
          case 'schedule': r.schedule = b[1]; break
          case 'action': r.action = b[1]; break
          case 'log': r.logging = b.slice(1).join(' '); break
          case 'description': r.description = b.slice(1).join(' '); break
        }
      }
      rules.push(r)
    } else if (h[0] === 'policy' && /^\d+$/.test(h[1] ?? '')) {
      const r: RouteRule & { prio: number } = {
        prio: Number(h[1]), order: 0, name: h[1], enabled: !off,
        from: 'any', source: 'any', destination: 'any', service: 'any',
      }
      for (const b of body) {
        if (b[0] === 'interface') r.from = b[1]
        else if (b[0] === 'source') r.source = b[1]
        else if (b[0] === 'destination') r.destination = b[1]
        else if (b[0] === 'service') r.service = b[1]
        else if (b[0] === 'next-hop') {
          r.nextHopType = b[1] === 'tunnel' ? 'ipsec-vpn' : b[1]
          r.nextHop = b[2]
        }
      }
      routes.push(r)
    } else if (h[0] === 'interface-group' && h[1]) {
      cfg.ifaceGroups.push({
        name: h[1],
        members: body.filter(b => b[0] === 'interface' && b[2]).map(b => ({ name: b[2], passive: b.includes('passive') })),
      })
    } else if (h[0] === 'system' && h[1] === 'default-interface-group' && h[2]) {
      cfg.defaultTrunk = h[2]
    } else if (h[0] === 'ip' && h[1] === 'virtual-server' && h[2]) {
      const after = (k: string) => { const i = h.indexOf(k); return i > 0 ? h[i + 1] : undefined }
      const mt = h.indexOf('map-type')
      cfg.nats.push({
        name: h[2], enabled: !h.includes('deactivate'),
        iface: after('interface'), sourceIp: after('source-ip'),
        originalIp: after('original-ip'), mapTo: after('map-to'),
        mapType: mt > 0 ? h.slice(mt + 1).filter(x => x !== 'deactivate').join(' ') : undefined,
      })
    } else if ((h[0] === 'isakmp' || h[0] === 'ikev2') && h[1] === 'policy' && h[2]) {
      const peer = sub('peer-ip')?.[1]
      if (peer && peer !== '0.0.0.0') vpnPeer.set(h[2], peer)
    } else if (h[0] === 'crypto' && h[1] === 'map' && h[2]) {
      const v: VpnSite = {
        name: h[2], enabled: body.some(b => b[0] === 'activate'),
        localTs: [], remoteTs: [], policies: [h[2]], // policy routes point at the crypto map
      }
      const gw = sub('ipsec-isakmp')?.[1]
      if (gw) vpnGw.set(h[2], gw)
      vpnPol.set(h[2], { local: sub('local-policy')?.[1], remote: sub('remote-policy')?.[1] })
      cfg.vpns.push(v)
    }
  }

  // Traffic selectors are address objects: resolve them to subnets.
  const subnet = (name?: string): string[] => {
    if (!name) return []
    const a = cfg.addresses[name]
    // "any" or a 0.0.0.0 host: a route-based tunnel, no fixed selector
    if (name === 'any' || a?.value === '0.0.0.0') return ['0.0.0.0/0']
    if (a?.type === 'cidr') return [a.value]
    if (a?.type === 'host') return [`${a.value}/32`]
    return []
  }
  for (const v of cfg.vpns) {
    const gw = vpnGw.get(v.name)
    if (gw) v.remoteAddress = vpnPeer.get(gw)
    v.localTs = subnet(vpnPol.get(v.name)?.local)
    v.remoteTs = subnet(vpnPol.get(v.name)?.remote)
  }

  cfg.rules = rules.sort((a, b) => a.prio - b.prio).map(({ prio: _, ...r }, i) => ({ ...r, order: i }))
  cfg.routes = routes.sort((a, b) => a.prio - b.prio).map(({ prio: _, ...r }, i) => ({ ...r, order: i }))
  return cfg
}
