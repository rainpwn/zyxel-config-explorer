import type {
  FirewallConfig, Zone, Iface, Rule, VpnSite, NatRule, RouteRule, InterfaceGroup,
} from '../model'

// Splits a uOS line into tokens: quoted strings (even empty) or bare words.
function tokens(line: string): string[] {
  const out: string[] = []
  const re = /"([^"]*)"|(\S+)/g
  let m: RegExpExecArray | null
  while ((m = re.exec(line))) out.push(m[1] !== undefined ? m[1] : m[2])
  return out
}

// An object line can carry several properties, in any order:
// ... address "X" "description" "D" "type" "host" "1.2.3.4" "vrf" "main"
// Returns key -> following tokens, up to the next known key.
const OBJECT_KEYS = new Set(['type', 'description', 'vrf', 'address-list', 'service-list', 'group-list'])
function objectProps(t: string[]): Record<string, string[]> {
  const out: Record<string, string[]> = {}
  let cur: string[] | undefined
  for (const tok of t.slice(5)) {
    if (OBJECT_KEYS.has(tok) && (cur === undefined || cur.length > 0)) out[tok] = cur = []
    else cur?.push(tok)
  }
  return out
}

// Parser for the flat Zyxel uOS format: one property per line.
// Secrets (psk, password, hash) are never extracted: the parser
// reads only the known paths listed below.
export function parseUos(text: string): FirewallConfig {
  const zones = new Map<string, Zone>()
  const interfaces = new Map<string, Iface>()
  const cfg: FirewallConfig = {
    zones: [], interfaces: [],
    addresses: {}, addressGroups: {},
    services: {}, serviceGroups: {},
    rules: [], vpns: [], nats: [], routes: [], ifaceGroups: [],
  }
  const rules = new Map<string, Rule>()
  const vpns = new Map<string, VpnSite>()
  const nats = new Map<string, NatRule>()
  const routes = new Map<string, RouteRule>()
  const ifaceGroups = new Map<string, InterfaceGroup>()

  for (const line of text.split(/\r?\n/)) {
    if (!line.startsWith('/')) continue
    const t = tokens(line)

    if (t[1] === 'object') {
      if (t[2] === 'zone-object' && t[3] === 'zone') {
        const z = zones.get(t[4]) ?? { name: t[4], interfaces: [] }
        zones.set(t[4], z)
        if (t[5] === 'interface-list') z.interfaces.push(t[7])
        else if (t[5] === 'description') z.description = t[6]
      } else if (t[2] === 'address-object' && t[3] === 'address') {
        const p = objectProps(t)
        const a = cfg.addresses[t[4]] ?? { name: t[4], type: '', value: '' }
        cfg.addresses[t[4]] = a
        if (p.type) { a.type = p.type[0]; a.value = p.type.slice(1).join(' ') }
        if (p.description) a.description = p.description[0]
      } else if (t[2] === 'address-object' && t[3] === 'group') {
        const p = objectProps(t)
        const g = cfg.addressGroups[t[4]] ?? { name: t[4], members: [] }
        cfg.addressGroups[t[4]] = g
        g.members.push(...(p['address-list'] ?? []), ...(p['group-list'] ?? []))
        if (p.description) g.description = p.description[0]
      } else if (t[2] === 'service-object' && t[3] === 'service') {
        const p = objectProps(t)
        if (p.type) cfg.services[t[4]] = { name: t[4], proto: p.type[0], value: p.type.slice(1).join(' ') }
      } else if (t[2] === 'service-object' && t[3] === 'group') {
        const p = objectProps(t)
        const g = cfg.serviceGroups[t[4]] ?? { name: t[4], members: [] }
        cfg.serviceGroups[t[4]] = g
        g.members.push(...(p['service-list'] ?? []), ...(p['group-list'] ?? []))
      }
      continue
    }

    if (t[1] !== 'vrf') continue

    if (t[3] === 'secure-policy' && t[4] === 'rule') {
      const name = t[5]
      let r = rules.get(name)
      if (!r) {
        r = {
          order: rules.size, name,
          // uOS doesn't always write fields left at their default: the default is any
          from: 'any', to: 'any', sourceIp: 'any', destIp: 'any',
          service: 'any', user: 'any', schedule: 'any', action: '', enabled: true,
        }
        rules.set(name, r)
      }
      const key = t[6], val = t[7]
      if (key === undefined || val === undefined) continue
      switch (key) {
        case 'from': r.from = val; break
        case 'to': r.to = val; break
        case 'source-ip': r.sourceIp = val; break
        case 'destination-ip': r.destIp = val; break
        case 'service': r.service = val; break
        case 'user': r.user = val; break
        case 'schedule': r.schedule = val; break
        case 'action': r.action = val; break
        case 'enabled': r.enabled = val === 'true'; break
        case 'logging': r.logging = val; break
        case 'description': r.description = val; break
      }
    } else if (t[3] === 'interface' && t[5] !== undefined) {
      const kind = t[4], name = t[5]
      let i = interfaces.get(name)
      if (!i) {
        i = { name, kind, enabled: true }
        interfaces.set(name, i)
      }
      if (t[6] === 'description') i.description = t[7]
      else if (t[6] === 'enabled') i.enabled = t[7] === 'true'
      else if (t[6] === 'type') i.role = t[7]
      else if (t[6] === 'vlan-id') i.vlanId = Number(t[7])
      else if (t[6] === 'link-interface') i.link = t[7]
      else if (t[6] === 'ipv4' && t[7] === 'address') i.ip = t[8]
    } else if (t[3] === 'ike' && t[4] === 'vpn' && t[5] !== undefined) {
      const name = t[5]
      let v = vpns.get(name)
      if (!v) {
        v = { name, enabled: true, localTs: [], remoteTs: [], policies: [] }
        vpns.set(name, v)
      }
      if (t[6] === 'remote-address') v.remoteAddress = t[7]
      else if (t[6] === 'enabled') v.enabled = t[7] === 'true'
      else if (t[6] === 'security-policy' && t[7] !== undefined && !v.policies.includes(t[7])) v.policies.push(t[7])
      if (t[6] === 'security-policy' && t[9] === 'subnet') {
        if (t[8] === 'local-ts') v.localTs.push(t[10])
        else if (t[8] === 'remote-ts') v.remoteTs.push(t[10])
      }
    } else if (t[3] === 'routing' && t[4] === 'policy-route' && t[5] === 'rule' && t[6] !== undefined) {
      const name = t[6]
      let r = routes.get(name)
      if (!r) {
        r = {
          order: routes.size, name, enabled: true,
          from: 'any', source: 'any', destination: 'any', service: 'any',
        }
        routes.set(name, r)
      }
      if (t[7] === 'enabled') r.enabled = t[8] === 'true'
      else if (t[7] === 'match') {
        if (t[8] === 'from') r.from = t[9]
        else if (t[8] === 'source') r.source = t[9]
        else if (t[8] === 'destination') r.destination = t[9]
        else if (t[8] === 'service') r.service = t[9]
      } else if (t[7] === 'action' && t[8] === 'next-hop') {
        r.nextHopType = t[9]
        r.nextHop = t[10]
      }
    } else if (t[3] === 'interface-group' && t[4] !== undefined && t[5] === 'interface' && t[6] !== undefined) {
      let g = ifaceGroups.get(t[4])
      if (!g) {
        g = { name: t[4], members: [] }
        ifaceGroups.set(t[4], g)
      }
      let m = g.members.find(x => x.name === t[6])
      if (!m) {
        m = { name: t[6], passive: false }
        g.members.push(m)
      }
      if (t[7] === 'passive') m.passive = t[8] === 'true'
    } else if (t[3] === 'system' && t[4] === 'default-interface-group' && t[5] === 'name') {
      cfg.defaultTrunk = t[6]
    } else if (t[3] === 'virtual-server' && t[4] === 'rule' && t[5] !== undefined) {
      const name = t[5]
      let n = nats.get(name)
      if (!n) {
        n = { name, enabled: true }
        nats.set(name, n)
      }
      if (t[6] === 'enabled') n.enabled = t[7] === 'true'
      else if (t[6] === 'interface') n.iface = t[7]
      else if (t[6] === 'source-ip') n.sourceIp = t[8] ?? t[7]
      else if (t[6] === 'original-ip') n.originalIp = t[8] ?? t[7]
      else if (t[6] === 'map-to') n.mapTo = t[8] ?? t[7]
      else if (t[6] === 'map-type') n.mapType = t.slice(7).join(' ')
    }
  }

  cfg.zones = [...zones.values()]
  cfg.interfaces = [...interfaces.values()]
  cfg.rules = [...rules.values()].sort((a, b) => a.order - b.order)
  cfg.vpns = [...vpns.values()]
  cfg.nats = [...nats.values()]
  cfg.routes = [...routes.values()].sort((a, b) => a.order - b.order)
  cfg.ifaceGroups = [...ifaceGroups.values()]
  return cfg
}
