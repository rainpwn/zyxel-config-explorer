// Analysis engines: packet simulation, failure impact, audit, diff.
// Simplifying assumptions (user/schedule = any, no NAT in matching)
// are stated in the result notes.

import type { FirewallConfig, Rule, RouteRule, NatRule } from './model'
import { ipToInt, toRange, rangesOf, ifaceZoneMap, rulesForIface, placeAddresses } from './derive'
import { loc } from './i18n'

const s = loc({
  en: {
    allPorts: 'all ports',
    firewallIp: (iface: string) => `the firewall's own IP (${iface})`,
    subnetOf: (iface: string, ip: string) => `subnet of ${iface} (${ip})`,
    tunnelRemote: (vpn: string, ts: string) => `remote subnet of tunnel ${vpn} (${ts})`,
    assumedExternal: 'no local subnet matches: assumed external',
    badSrc: (ip: string) => `Invalid source IP: ${ip}`,
    badDst: (ip: string) => `Invalid destination IP: ${ip}`,
    chosenIface: 'zone of the chosen interface',
    assumptions: 'user and schedule assumed "any"; NAT not applied to the match.',
    defaultDeny: 'No rule matches: the default deny between zones applies.',
    tunnelDown: (src: string, dst: string) => `${src} → ${dst}: next hop is the tunnel that is down`,
    remoteSubnet: (ts: string) => `Remote subnet ${ts}`,
    unreachable: 'unreachable',
    natOnIface: (orig: string, to: string) => `${orig} → ${to} published on this interface`,
    noOtherMember: 'no other member available',
    failover: (list: string) => `fails over to ${list}`,
    passive: ' (passive)',
    nextHopIface: (src: string, dst: string) => `${src} → ${dst}: next hop is this interface`,
    trunkEmpty: (trunk: string) => `trunk ${trunk} has no members left`,
    rulesAffected: (n: number) => `${n} rule${n === 1 ? '' : 's'} affected`,
    rulesAffectedDetail: 'rules that reference the subnet or its zone: no traffic while the interface is down',
    noImpact: 'No direct impact found',
    noImpactDetail: 'no NAT, route or host tied to this item',
    diff: {
      rules: 'Rules', addresses: 'Address objects', addressGroups: 'Address groups',
      services: 'Services', serviceGroups: 'Service groups', routes: 'Policy routes',
      zones: 'Zones', interfaces: 'Interfaces',
    },
  },
  it: {
    allPorts: 'tutte le porte',
    firewallIp: (iface: string) => `è l'IP del firewall stesso (${iface})`,
    subnetOf: (iface: string, ip: string) => `subnet di ${iface} (${ip})`,
    tunnelRemote: (vpn: string, ts: string) => `subnet remota del tunnel ${vpn} (${ts})`,
    assumedExternal: 'nessuna subnet locale corrisponde: presunto esterno',
    badSrc: (ip: string) => `IP sorgente non valido: ${ip}`,
    badDst: (ip: string) => `IP destinazione non valido: ${ip}`,
    chosenIface: 'zona dell’interfaccia scelta',
    assumptions: 'user e schedule assunti "any"; NAT non applicato al match.',
    defaultDeny: 'Nessuna regola corrisponde: vale il default deny tra zone.',
    tunnelDown: (src: string, dst: string) => `${src} → ${dst}: next-hop sul tunnel giù`,
    remoteSubnet: (ts: string) => `Subnet remota ${ts}`,
    unreachable: 'irraggiungibile',
    natOnIface: (orig: string, to: string) => `${orig} → ${to} pubblicato su questa interfaccia`,
    noOtherMember: 'nessun altro membro disponibile',
    failover: (list: string) => `failover su ${list}`,
    passive: ' (passivo)',
    nextHopIface: (src: string, dst: string) => `${src} → ${dst}: next-hop su questa interfaccia`,
    trunkEmpty: (trunk: string) => `il trunk ${trunk} non ha più membri`,
    rulesAffected: (n: number) => `${n} ${n === 1 ? 'regola coinvolta' : 'regole coinvolte'}`,
    rulesAffectedDetail: 'regole che citano la subnet o la sua zona: senza traffico finché l’interfaccia è giù',
    noImpact: 'Nessun impatto diretto rilevato',
    noImpactDetail: 'nessun NAT, route o host legato a questo elemento',
    diff: {
      rules: 'Regole', addresses: 'Address object', addressGroups: 'Gruppi address',
      services: 'Servizi', serviceGroups: 'Gruppi servizi', routes: 'Policy route',
      zones: 'Zone', interfaces: 'Interfacce',
    },
  },
})

export type Proto = 'icmp' | 'tcp' | 'udp'

// Service coverage

interface SvcEntry { proto: string; lo: number; hi: number }
interface SvcCover { any: boolean; entries: SvcEntry[] }

function svcEntries(cfg: FirewallConfig, name: string, seen = new Set<string>()): SvcCover {
  if (name === 'any') return { any: true, entries: [] }
  if (seen.has(name)) return { any: false, entries: [] }
  seen.add(name)
  const s = cfg.services[name]
  if (s) {
    if (s.proto === 'icmp' || s.proto === 'icmp6') {
      return { any: false, entries: [{ proto: 'icmp', lo: 0, hi: 0 }] }
    }
    if (s.proto === 'protocol') {
      return { any: false, entries: [{ proto: `ip/${s.value}`, lo: 0, hi: 0 }] }
    }
    const entries: SvcEntry[] = []
    for (const part of s.value.split(',')) {
      const [lo, hi] = part.split('-').map(Number)
      if (Number.isInteger(lo)) entries.push({ proto: s.proto, lo, hi: Number.isInteger(hi) ? hi : lo })
    }
    return { any: false, entries }
  }
  const g = cfg.serviceGroups[name]
  if (g) {
    const entries: SvcEntry[] = []
    let any = false
    for (const m of g.members) {
      const c = svcEntries(cfg, m, seen)
      any = any || c.any
      entries.push(...c.entries)
    }
    return { any, entries }
  }
  return { any: false, entries: [] }
}

export function serviceCovers(cfg: FirewallConfig, name: string, proto: Proto, port: number): boolean {
  const c = svcEntries(cfg, name)
  if (c.any) return true
  return c.entries.some(e =>
    e.proto === proto && (proto === 'icmp' || (port >= e.lo && port <= e.hi)),
  )
}

// Ports covered by a service, human-readable ("tcp/443, udp/500-501").
export function servicePorts(cfg: FirewallConfig, name: string): string {
  const c = svcEntries(cfg, name)
  if (c.any) return s.allPorts
  if (c.entries.length === 0) return name
  return c.entries
    .map(e => e.proto === 'icmp' ? 'icmp' : e.proto.startsWith('ip/') ? e.proto : `${e.proto}/${e.lo}${e.hi !== e.lo ? `-${e.hi}` : ''}`)
    .join(', ')
}

// Zone of an IP

export function wanZone(cfg: FirewallConfig): string {
  const ifZone = ifaceZoneMap(cfg)
  // First choice: the zone of the default trunk members
  const trunk = cfg.ifaceGroups.find(g => g.name === cfg.defaultTrunk)
  for (const m of trunk?.members ?? []) {
    if (ifZone[m.name]) return ifZone[m.name]
  }
  const ext = cfg.interfaces.find(i => i.role === 'external' && ifZone[i.name])
  return ext ? ifZone[ext.name] : 'WAN'
}

export function zoneOfIp(cfg: FirewallConfig, ip: number): { zone: string; how: string } {
  const ifZone = ifaceZoneMap(cfg)
  for (const i of cfg.interfaces) {
    if (!i.ip) continue
    if (ipToInt(i.ip.split('/')[0]) === ip) {
      return { zone: 'ZyWALL', how: s.firewallIp(i.name) }
    }
  }
  for (const i of cfg.interfaces) {
    if (!i.ip || !ifZone[i.name]) continue
    const r = toRange('cidr', i.ip)
    if (r && ip >= r[0] && ip <= r[1]) {
      return { zone: ifZone[i.name], how: s.subnetOf(i.name, i.ip) }
    }
  }
  const vpnZone = cfg.zones.find(z => /ipsec/i.test(z.name))?.name
  if (vpnZone) {
    for (const v of cfg.vpns) {
      for (const ts of v.remoteTs) {
        if (ts.endsWith('/0')) continue // full tunnel: says nothing about the zone
        const r = toRange('cidr', ts)
        if (r && ip >= r[0] && ip <= r[1]) {
          return { zone: vpnZone, how: s.tunnelRemote(v.name, ts) }
        }
      }
    }
  }
  return { zone: wanZone(cfg), how: s.assumedExternal }
}

// Simulator

export interface SimResult {
  ok: true
  srcIp: string
  dstIp: string
  srcZone: string
  srcHow: string
  dstZone: string
  dstHow: string
  verdict: 'allow' | 'deny'
  rule: Rule | null // null = implicit default deny
  route: RouteRule | null // null = default trunk
  notes: string[]
}

export interface SimError { ok: false; error: string }

const zoneMatch = (ruleZone: string, zone: string) => ruleZone === 'any' || ruleZone === zone

export function simulate(
  cfg: FirewallConfig,
  srcIpStr: string,
  dstIpStr: string,
  proto: Proto,
  port: number,
  srcZoneOverride?: string,
): SimResult | SimError {
  const srcIp = ipToInt(srcIpStr.trim())
  const dstIp = ipToInt(dstIpStr.trim())
  if (srcIp === null) return { ok: false, error: s.badSrc(srcIpStr) }
  if (dstIp === null) return { ok: false, error: s.badDst(dstIpStr) }

  const src = srcZoneOverride
    ? { zone: srcZoneOverride, how: s.chosenIface }
    : zoneOfIp(cfg, srcIp)
  const dst = zoneOfIp(cfg, dstIp)

  let verdict: 'allow' | 'deny' = 'deny'
  let decisive: Rule | null = null
  for (const r of cfg.rules) {
    if (!r.enabled) continue
    if (!zoneMatch(r.from, src.zone) || !zoneMatch(r.to, dst.zone)) continue
    const s = rangesOf(cfg, r.sourceIp)
    if (!s.any && !s.ranges.some(([lo, hi]) => srcIp >= lo && srcIp <= hi)) continue
    const d = rangesOf(cfg, r.destIp)
    if (!d.any && !d.ranges.some(([lo, hi]) => dstIp >= lo && dstIp <= hi)) continue
    if (!serviceCovers(cfg, r.service, proto, port)) continue
    verdict = r.action === 'allow' ? 'allow' : 'deny'
    decisive = r
    break
  }

  let route: RouteRule | null = null
  for (const r of cfg.routes) {
    if (!r.enabled) continue
    if (!zoneMatch(r.from, src.zone)) continue
    const s = rangesOf(cfg, r.source)
    if (!s.any && !s.ranges.some(([lo, hi]) => srcIp >= lo && srcIp <= hi)) continue
    const d = rangesOf(cfg, r.destination)
    if (!d.any && !d.ranges.some(([lo, hi]) => dstIp >= lo && dstIp <= hi)) continue
    if (!serviceCovers(cfg, r.service, proto, port)) continue
    route = r
    break
  }

  const notes = [s.assumptions]
  if (!decisive) notes.push(s.defaultDeny)

  return {
    ok: true,
    srcIp: srcIpStr.trim(), dstIp: dstIpStr.trim(),
    srcZone: src.zone, srcHow: src.how,
    dstZone: dst.zone, dstHow: dst.how,
    verdict, rule: decisive, route, notes,
  }
}

// Failure impact

export interface ImpactItem {
  severity: 'rotto' | 'degradato' | 'info'
  label: string
  detail: string
}

export interface Impact {
  target: { kind: 'iface' | 'vpn'; name: string }
  items: ImpactItem[]
  mapIds: string[]
  zones: string[] // zones whose traffic is affected, for map highlighting
}

export function impactOfDown(cfg: FirewallConfig, kind: 'iface' | 'vpn', name: string): Impact {
  const items: ImpactItem[] = []
  const mapIds: string[] = []
  const zones = new Set<string>()
  const ifZone = ifaceZoneMap(cfg)
  // A route's `from`/`source` can be a ZONE or an INTERFACE
  // (e.g. rule43 from "dmz-ext"): either way, resolve it to the zone.
  const addZone = (z?: string) => {
    if (!z || z === 'any') return
    if (cfg.zones.some(x => x.name === z)) zones.add(z)
    else if (ifZone[z]) zones.add(ifZone[z])
  }

  if (kind === 'vpn') {
    const v = cfg.vpns.find(x => x.name === name)
    mapIds.push('vpn', `v:${name}`)
    for (const r of cfg.routes) {
      if (!r.enabled || r.nextHopType !== 'ipsec-vpn' || r.nextHop === undefined) continue
      if (!v?.policies.includes(r.nextHop)) continue
      addZone(r.from)
      items.push({
        severity: 'rotto',
        label: `Policy-route ${r.name}`,
        detail: s.tunnelDown(r.source, r.destination),
      })
    }
    for (const ts of v?.remoteTs ?? []) {
      items.push({ severity: 'rotto', label: s.remoteSubnet(ts), detail: s.unreachable })
    }
    return { target: { kind, name }, items, mapIds, zones: [...zones] }
  }

  // Interface down
  mapIds.push(`i:${name}`)
  const zone = ifZone[name]
  addZone(zone) // the zone losing this interface is always affected
  const placed = placeAddresses(cfg)

  for (const n of cfg.nats) {
    if (!n.enabled || n.iface !== name) continue
    // the published service lives in an internal zone, which is affected too
    if (n.mapTo) addZone(placed[n.mapTo])
    items.push({
      severity: 'rotto',
      label: `NAT ${n.name}`,
      detail: s.natOnIface(n.originalIp ?? '?', n.mapTo ?? '?'),
    })
    mapIds.push(`n:${n.name}`)
  }

  const brokenTrunks = new Set<string>()
  for (const g of cfg.ifaceGroups) {
    if (!g.members.some(m => m.name === name)) continue
    const others = g.members.filter(m => m.name !== name)
    if (others.length === 0) {
      brokenTrunks.add(g.name)
      items.push({ severity: 'rotto', label: `Trunk ${g.name}`, detail: s.noOtherMember })
    } else {
      items.push({
        severity: 'degradato',
        label: `Trunk ${g.name}`,
        detail: s.failover(others.map(m => m.name + (m.passive ? s.passive : '')).join(', ')),
      })
    }
  }

  for (const r of cfg.routes) {
    if (!r.enabled) continue
    if (r.nextHopType === 'interface' && r.nextHop === name) {
      addZone(r.from)
      items.push({ severity: 'rotto', label: `Policy-route ${r.name}`, detail: s.nextHopIface(r.source, r.destination) })
    } else if (r.nextHopType === 'trunk' && r.nextHop !== undefined && brokenTrunks.has(r.nextHop)) {
      addZone(r.from)
      items.push({ severity: 'rotto', label: `Policy-route ${r.name}`, detail: s.trunkEmpty(r.nextHop) })
    }
  }

  if (zone) {
    const i = cfg.interfaces.find(x => x.name === name)
    if (i?.ip && i.role !== 'external') {
      const r = toRange('cidr', i.ip)
      if (r) {
        const hosts = Object.values(cfg.addresses).filter(a => {
          const c = rangesOf(cfg, a.name)
          return c.ranges.some(([lo, hi]) => lo >= r[0] && hi <= r[1])
        })
        for (const h of hosts) mapIds.push(`a:${h.name}`)
        if (hosts.length > 0) {
          items.push({
            severity: 'rotto',
            label: `${hosts.length} host in ${i.ip}`,
            detail: hosts.slice(0, 8).map(h => h.name).join(', ') + (hosts.length > 8 ? '…' : ''),
          })
        }
        const rules = rulesForIface(cfg, name).filter(x => x.enabled)
        if (rules.length > 0) {
          items.push({
            severity: 'info',
            label: s.rulesAffected(rules.length),
            detail: s.rulesAffectedDetail,
          })
        }
      }
    }
  }

  if (items.length === 0) {
    items.push({ severity: 'info', label: s.noImpact, detail: s.noImpactDetail })
  }
  return { target: { kind, name }, items, mapIds, zones: [...zones] }
}

// Audit: shadowed rules

function mergeRanges(ranges: [number, number][]): [number, number][] {
  const sorted = [...ranges].sort((a, b) => a[0] - b[0])
  const out: [number, number][] = []
  for (const r of sorted) {
    const last = out[out.length - 1]
    if (last && r[0] <= last[1] + 1) last[1] = Math.max(last[1], r[1])
    else out.push([...r])
  }
  return out
}

// true if aName's coverage includes all of bName's
function addrSubset(cfg: FirewallConfig, aName: string, bName: string): boolean {
  const a = rangesOf(cfg, aName)
  if (a.any) return true
  const b = rangesOf(cfg, bName)
  if (b.any || b.ranges.length === 0) return false // any or fqdn/geography: not comparable
  const merged = mergeRanges(a.ranges)
  return b.ranges.every(([lo, hi]) => merged.some(([mlo, mhi]) => lo >= mlo && hi <= mhi))
}

function svcSubset(cfg: FirewallConfig, aName: string, bName: string): boolean {
  const a = svcEntries(cfg, aName)
  if (a.any) return true
  const b = svcEntries(cfg, bName)
  if (b.any || b.entries.length === 0) return false
  return b.entries.every(be =>
    a.entries.some(ae => ae.proto === be.proto && be.lo >= ae.lo && be.hi <= ae.hi),
  )
}

// true if the two services share at least one port; a service we cannot
// parse counts as overlapping, so we don't invent gaps
function svcOverlap(cfg: FirewallConfig, aName: string, bName: string): boolean {
  const a = svcEntries(cfg, aName), b = svcEntries(cfg, bName)
  if (a.any || b.any || a.entries.length === 0 || b.entries.length === 0) return true
  return a.entries.some(ae => b.entries.some(be => ae.proto === be.proto && ae.lo <= be.hi && be.lo <= ae.hi))
}

export interface Shadow { rule: Rule; by: Rule; kind: 'ridondante' | 'conflitto' }

export function shadowedRules(cfg: FirewallConfig): Shadow[] {
  const enabled = cfg.rules.filter(r => r.enabled)
  const out: Shadow[] = []
  const zoneCover = (a: string, b: string) => a === 'any' || a === b
  for (let j = 1; j < enabled.length; j++) {
    const b = enabled[j]
    for (let i = 0; i < j; i++) {
      const a = enabled[i]
      if (a.user !== 'any' || a.schedule !== 'any') continue
      if (!zoneCover(a.from, b.from) || !zoneCover(a.to, b.to)) continue
      if (!addrSubset(cfg, a.sourceIp, b.sourceIp)) continue
      if (!addrSubset(cfg, a.destIp, b.destIp)) continue
      if (!svcSubset(cfg, a.service, b.service)) continue
      out.push({ rule: b, by: a, kind: a.action === b.action ? 'ridondante' : 'conflitto' })
      break
    }
  }
  return out
}

// Audit: orphan objects

export interface Orphans {
  addresses: string[]
  addressGroups: string[]
  services: string[]
  serviceGroups: string[]
}

export function orphanObjects(cfg: FirewallConfig): Orphans {
  const refAddr = new Set<string>()
  const refSvc = new Set<string>()
  const addAddr = (n?: string) => {
    if (!n || n === 'any') return
    if (refAddr.has(n)) return
    refAddr.add(n)
    cfg.addressGroups[n]?.members.forEach(addAddr)
  }
  const addSvc = (n?: string) => {
    if (!n || n === 'any') return
    if (refSvc.has(n)) return
    refSvc.add(n)
    cfg.serviceGroups[n]?.members.forEach(addSvc)
  }
  for (const r of cfg.rules) { addAddr(r.sourceIp); addAddr(r.destIp); addSvc(r.service) }
  for (const r of cfg.routes) { addAddr(r.source); addAddr(r.destination); addSvc(r.service) }
  for (const n of cfg.nats) {
    addAddr(n.sourceIp); addAddr(n.originalIp); addAddr(n.mapTo)
    addSvc(natService(n.mapType))
  }
  return {
    addresses: Object.keys(cfg.addresses).filter(n => !refAddr.has(n)).sort(),
    addressGroups: Object.keys(cfg.addressGroups).filter(n => !refAddr.has(n)).sort(),
    services: Object.keys(cfg.services).filter(n => !refSvc.has(n)).sort(),
    serviceGroups: Object.keys(cfg.serviceGroups).filter(n => !refSvc.has(n)).sort(),
  }
}

// WAN exposure
// What is reachable from the Internet: NAT virtual servers published on the
// WAN, and allow rules with from = WAN zone (or any).

const RISKY_PORTS = new Set([21, 22, 23, 135, 139, 445, 1433, 3306, 3389, 5900])

// true if the service covers a management/database port or is 'any'
function riskyService(cfg: FirewallConfig, name: string): boolean {
  const c = svcEntries(cfg, name)
  if (c.any) return true
  return c.entries.some(e =>
    e.proto !== 'icmp' && !e.proto.startsWith('ip/') &&
    [...RISKY_PORTS].some(p => p >= e.lo && p <= e.hi),
  )
}

// Name of the service published by a NAT, taken from map-type.
export function natService(mapType?: string): string {
  if (!mapType) return 'any'
  const t = mapType.split(' ')
  if (t[0] === 'service') {
    const i = t.indexOf('original-service')
    return i >= 0 && t[i + 1] ? t[i + 1] : 'any'
  }
  if (t[0] === 'service-group') return t[1] ?? 'any'
  return mapType
}

export interface NatExposure {
  nat: NatRule
  service: string // published service/group name
  ports: string
  allowRule: Rule | null // first allow rule from the WAN covering the host; null = NAT with no opening
  risky: boolean
}

export interface RuleExposure {
  rule: Rule
  ports: string
  risky: boolean
}

export function exposure(cfg: FirewallConfig): { wan: string; nats: NatExposure[]; rules: RuleExposure[] } {
  const wan = wanZone(cfg)

  const wanAllows = cfg.rules.filter(r =>
    r.enabled && r.action === 'allow' && (r.from === wan || r.from === 'any'),
  )

  const nats: NatExposure[] = cfg.nats
    .filter(n => n.enabled && n.mapTo)
    .map(n => {
      const svc = natService(n.mapType)
      const target = rangesOf(cfg, n.mapTo!)
      const allowRule = wanAllows.find(r => {
        // ZyWALL is the firewall itself: a rule to it does not open the internal server
        if (r.to === 'ZyWALL' || !svcOverlap(cfg, r.service, svc)) return false
        const d = rangesOf(cfg, r.destIp)
        return d.any || d.ranges.some(([lo, hi]) =>
          target.ranges.some(([tlo, thi]) => thi >= lo && tlo <= hi))
      }) ?? null
      return {
        nat: n, service: svc,
        ports: servicePorts(cfg, svc),
        allowRule,
        risky: riskyService(cfg, svc),
      }
    })
    .sort((a, b) => Number(b.risky) - Number(a.risky) || a.nat.name.localeCompare(b.nat.name))

  const rules: RuleExposure[] = wanAllows
    .filter(r => r.to !== wan) // WAN→WAN does not expose the inside
    .map(r => ({
      rule: r,
      ports: servicePorts(cfg, r.service),
      risky: riskyService(cfg, r.service) || r.destIp === 'any',
    }))
    .sort((a, b) => Number(b.risky) - Number(a.risky) || a.rule.order - b.rule.order)

  return { wan, nats, rules }
}

// Diff between two configs

export interface DiffSection {
  added: string[]
  removed: string[]
  changed: { name: string; fields: string[] }[]
}

function diffMaps<T>(
  a: Record<string, T>,
  b: Record<string, T>,
  fields: (x: T) => Record<string, unknown>,
): DiffSection {
  const added = Object.keys(b).filter(k => !(k in a)).sort()
  const removed = Object.keys(a).filter(k => !(k in b)).sort()
  const changed: { name: string; fields: string[] }[] = []
  for (const k of Object.keys(a)) {
    if (!(k in b)) continue
    const fa = fields(a[k])
    const fb = fields(b[k])
    const diff = Object.keys(fa).filter(f => JSON.stringify(fa[f]) !== JSON.stringify(fb[f]))
    if (diff.length > 0) changed.push({ name: k, fields: diff })
  }
  return { added, removed, changed: changed.sort((x, y) => x.name.localeCompare(y.name)) }
}

const byName = <T extends { name: string }>(list: T[]): Record<string, T> =>
  Object.fromEntries(list.map(x => [x.name, x]))

export function diffConfigs(a: FirewallConfig, b: FirewallConfig): Record<string, DiffSection> {
  return {
    [s.diff.rules]: diffMaps(byName(a.rules), byName(b.rules), r => ({
      from: r.from, to: r.to, source: r.sourceIp, destination: r.destIp,
      service: r.service, user: r.user, action: r.action, enabled: r.enabled,
    })),
    [s.diff.addresses]: diffMaps(a.addresses, b.addresses, x => ({ type: x.type, value: x.value })),
    [s.diff.addressGroups]: diffMaps(a.addressGroups, b.addressGroups, x => ({ members: [...x.members].sort() })),
    [s.diff.services]: diffMaps(a.services, b.services, x => ({ proto: x.proto, value: x.value })),
    [s.diff.serviceGroups]: diffMaps(a.serviceGroups, b.serviceGroups, x => ({ members: [...x.members].sort() })),
    [s.diff.routes]: diffMaps(byName(a.routes), byName(b.routes), r => ({
      from: r.from, source: r.source, destination: r.destination,
      service: r.service, nextHop: `${r.nextHopType} ${r.nextHop}`, enabled: r.enabled,
    })),
    'NAT': diffMaps(byName(a.nats), byName(b.nats), n => ({
      iface: n.iface, originalIp: n.originalIp, mapTo: n.mapTo, mapType: n.mapType, enabled: n.enabled,
    })),
    'VPN': diffMaps(byName(a.vpns), byName(b.vpns), v => ({
      remote: v.remoteAddress, enabled: v.enabled, localTs: v.localTs, remoteTs: v.remoteTs,
    })),
    [s.diff.zones]: diffMaps(byName(a.zones), byName(b.zones), z => ({ interfaces: [...z.interfaces].sort() })),
    [s.diff.interfaces]: diffMaps(byName(a.interfaces), byName(b.interfaces), i => ({
      ip: i.ip, enabled: i.enabled, vlan: i.vlanId, link: i.link, role: i.role,
    })),
  }
}
