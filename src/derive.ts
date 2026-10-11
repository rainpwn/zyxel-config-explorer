import type { FirewallConfig, Rule, RouteRule } from './model'
import { loc } from './i18n'

const s = loc({
  en: { group: 'group' },
  it: { group: 'gruppo' },
})

// IPv4 arithmetic

export function ipToInt(ip: string): number | null {
  const p = ip.split('.')
  if (p.length !== 4) return null
  let n = 0
  for (const s of p) {
    if (!/^\d{1,3}$/.test(s)) return null
    const b = Number(s)
    if (b > 255) return null
    n = n * 256 + b
  }
  return n
}

// Returns [start, end] for host, cidr or range; null if not an IP value.
export function toRange(type: string, value: string): [number, number] | null {
  if (type === 'host') {
    const n = ipToInt(value)
    return n === null ? null : [n, n]
  }
  if (type === 'cidr' || value.includes('/')) {
    const [ip, bits] = value.split('/')
    const n = ipToInt(ip)
    const b = Number(bits)
    if (n === null || !Number.isInteger(b) || b < 0 || b > 32) return null
    const size = 2 ** (32 - b)
    const start = Math.floor(n / size) * size
    return [start, start + size - 1]
  }
  if (type === 'range') {
    const [a, b] = value.split('-').map(ipToInt)
    return a === null || b == null ? null : [a, b]
  }
  return null
}

// Zones and object placement

// interface -> zone
export function ifaceZoneMap(cfg: FirewallConfig): Record<string, string> {
  const map: Record<string, string> = {}
  for (const z of cfg.zones) for (const i of z.interfaces) map[i] = z.name
  return map
}

// Places address objects in the zone whose interface subnet contains them.
export function placeAddresses(cfg: FirewallConfig): Record<string, string> {
  const ifZone = ifaceZoneMap(cfg)
  const subnets: { zone: string; range: [number, number] }[] = []
  for (const i of cfg.interfaces) {
    const zone = ifZone[i.name]
    if (!zone || !i.ip) continue
    const r = toRange('cidr', i.ip)
    if (r) subnets.push({ zone, range: r })
  }
  const placed: Record<string, string> = {}
  for (const a of Object.values(cfg.addresses)) {
    if (a.type === 'interface-subnet') {
      const z = ifZone[a.value]
      if (z) placed[a.name] = z
      continue
    }
    const r = toRange(a.type, a.value)
    if (!r) continue
    const hit = subnets.find(s => r[0] >= s.range[0] && r[1] <= s.range[1])
    if (hit) placed[a.name] = hit.zone
  }
  return placed
}

// Rule aggregation per zone pair

export interface ZonePair {
  from: string
  to: string
  allow: number
  deny: number
  rules: Rule[]
}

export function zonePairs(rules: Rule[]): ZonePair[] {
  const map = new Map<string, ZonePair>()
  for (const r of rules) {
    const key = `${r.from}→${r.to}`
    let p = map.get(key)
    if (!p) {
      p = { from: r.from, to: r.to, allow: 0, deny: 0, rules: [] }
      map.set(key, p)
    }
    p.rules.push(r)
    if (r.action === 'allow') p.allow++
    else p.deny++
  }
  return [...map.values()]
}

// Rules that involve an object

// Names an object can appear under in a rule source/dest: itself and
// every group containing it, nested ones included.
function aliasesOf(cfg: FirewallConfig, name: string, names = new Set<string>()): Set<string> {
  if (names.has(name)) return names
  names.add(name)
  for (const g of Object.values(cfg.addressGroups)) {
    if (g.members.includes(name)) aliasesOf(cfg, g.name, names)
  }
  return names
}

export function rulesForAddress(cfg: FirewallConfig, name: string): Rule[] {
  const names = aliasesOf(cfg, name)
  return cfg.rules.filter(r => names.has(r.sourceIp) || names.has(r.destIp))
}

export function rulesForZone(cfg: FirewallConfig, zone: string): Rule[] {
  return cfg.rules.filter(r => r.from === zone || r.to === zone)
}

// Address coverage (exact CIDR match)

export interface AddrCover { any: boolean; ranges: [number, number][] }

// IPv4 ranges covered by an address object or group ('any' is handled separately).
// fqdn/geography cannot be expressed as ranges and are left out.
export function rangesOf(cfg: FirewallConfig, name: string): AddrCover {
  if (name === 'any') return { any: true, ranges: [] }
  const out: [number, number][] = []
  const seen = new Set<string>()
  const visit = (n: string) => {
    if (seen.has(n)) return
    seen.add(n)
    const a = cfg.addresses[n]
    if (a) {
      if (a.type === 'interface-subnet') {
        const i = cfg.interfaces.find(x => x.name === a.value)
        const r = i?.ip ? toRange('cidr', i.ip) : null
        if (r) out.push(r)
      } else {
        const r = toRange(a.type, a.value)
        if (r) out.push(r)
      }
      return
    }
    cfg.addressGroups[n]?.members.forEach(visit)
  }
  visit(name)
  return { any: false, ranges: out }
}

export function coversIp(cfg: FirewallConfig, name: string, ip: number): boolean {
  const c = rangesOf(cfg, name)
  return c.any || c.ranges.some(([lo, hi]) => ip >= lo && ip <= hi)
}

function overlaps(a: [number, number][], b: [number, number][]): boolean {
  return a.some(([alo, ahi]) => b.some(([blo, bhi]) => ahi >= blo && alo <= bhi))
}

// Subnets (with IP) of a zone's interfaces.
function zoneRanges(cfg: FirewallConfig, zone: string): [number, number][] {
  const ifZone = ifaceZoneMap(cfg)
  const out: [number, number][] = []
  for (const i of cfg.interfaces) {
    if (ifZone[i.name] !== zone || !i.ip) continue
    const r = toRange('cidr', i.ip)
    if (r) out.push(r)
  }
  return out
}

// Rules that actually touch the interface subnet: objects inside it, or
// 'any' on its zone's side. Without an IP, falls back to the zone.
export function rulesForIface(cfg: FirewallConfig, ifaceName: string): Rule[] {
  const zone = ifaceZoneMap(cfg)[ifaceName]
  const i = cfg.interfaces.find(x => x.name === ifaceName)
  const r = i?.ip ? toRange('cidr', i.ip) : null
  if (!r) return zone ? rulesForZone(cfg, zone) : []
  const R = [r]
  return cfg.rules.filter(rule => {
    const s = rangesOf(cfg, rule.sourceIp)
    const d = rangesOf(cfg, rule.destIp)
    if (overlaps(s.ranges, R) || overlaps(d.ranges, R)) return true
    if (zone && rule.from === zone && s.any) return true
    if (zone && rule.to === zone && d.any) return true
    return false
  })
}

// Rules that reference a specific IP through their objects ('any' excluded).
export function rulesForIp(cfg: FirewallConfig, ip: number): Rule[] {
  return cfg.rules.filter(r => {
    const s = rangesOf(cfg, r.sourceIp)
    const d = rangesOf(cfg, r.destIp)
    const inR = ([lo, hi]: [number, number]) => ip >= lo && ip <= hi
    return s.ranges.some(inR) || d.ranges.some(inR)
  })
}

// Policy routes

export function routesForZone(cfg: FirewallConfig, zone: string): RouteRule[] {
  const zr = zoneRanges(cfg, zone)
  return cfg.routes.filter(r =>
    r.from === zone || (zr.length > 0 && overlaps(rangesOf(cfg, r.source).ranges, zr)),
  )
}

export function routesForIface(cfg: FirewallConfig, ifaceName: string): RouteRule[] {
  const zone = ifaceZoneMap(cfg)[ifaceName]
  const i = cfg.interfaces.find(x => x.name === ifaceName)
  const r = i?.ip ? toRange('cidr', i.ip) : null
  return cfg.routes.filter(route =>
    (zone && route.from === zone) ||
    (r !== null && overlaps(rangesOf(cfg, route.source).ranges, [r])),
  )
}

// Name resolution (for tooltips)

function groupSummary(members: string[]): string {
  const head = members.slice(0, 6).join(', ')
  return `${s.group}: ${head}${members.length > 6 ? ` … (+${members.length - 6})` : ''}`
}

export function resolveAddr(cfg: FirewallConfig, name: string): string {
  const a = cfg.addresses[name]
  if (a) return `${a.type} ${a.value}`
  const g = cfg.addressGroups[name]
  return g ? groupSummary(g.members) : name
}

export function resolveService(cfg: FirewallConfig, name: string): string {
  const s = cfg.services[name]
  if (s) return `${s.proto} ${s.value}`
  const g = cfg.serviceGroups[name]
  return g ? groupSummary(g.members) : name
}
