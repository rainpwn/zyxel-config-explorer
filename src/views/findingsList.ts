import type { FirewallConfig } from '../model'
import { placeAddresses } from '../derive'
import { exposure, shadowedRules, orphanObjects } from '../analysis'
import { loc } from '../i18n'

// Findings add no analysis: they line up the engines' results (exposure,
// shadowed rules, orphans) as one list ordered by severity, each attached to
// the zone it concerns (for the dot on the map) and to the view that
// explains it.

const s = loc({
  en: {
    exposed: (svc: string) => `${svc} reachable from the Internet`,
    anyFromNet: (rule: string) => `${rule} allows any destination from the Internet`,
    sensitiveFromNet: (rule: string) => `${rule} opens a sensitive port to the Internet`,
    conflict: (rule: string) => `${rule} never applies: an earlier rule does the opposite`,
    noGate: (nat: string) => `${nat} is published with no allow rule covering it`,
    redundant: (rule: string) => `${rule} is redundant: an earlier rule already does the same`,
    coveredBy: (ref: string) => `covered by ${ref}`,
    orphans: (n: number) => `${n} object${n === 1 ? '' : 's'} never used by rules, NAT or routes`,
    addr: (n: number) => `${n} address${n === 1 ? '' : 'es'}`,
    addrGroups: (n: number) => `${n} address group${n === 1 ? '' : 's'}`,
    services: (n: number) => `${n} service${n === 1 ? '' : 's'}`,
    svcGroups: (n: number) => `${n} service group${n === 1 ? '' : 's'}`,
    morePorts: (n: number) => `+${n} more`,
  },
  it: {
    exposed: (svc: string) => `${svc} raggiungibile da Internet`,
    anyFromNet: (rule: string) => `${rule} permette qualunque destinazione da Internet`,
    sensitiveFromNet: (rule: string) => `${rule} apre una porta sensibile verso Internet`,
    conflict: (rule: string) => `${rule} non si applica mai: una regola precedente fa il contrario`,
    noGate: (nat: string) => `${nat} è pubblicato senza una regola allow che lo copra`,
    redundant: (rule: string) => `${rule} è ridondante: una regola precedente fa già lo stesso`,
    coveredBy: (ref: string) => `coperta da ${ref}`,
    orphans: (n: number) => `${n} oggett${n === 1 ? 'o mai usato' : 'i mai usati'} da regole, NAT o route`,
    addr: (n: number) => `${n} address`,
    addrGroups: (n: number) => `${n} grupp${n === 1 ? 'o' : 'i'} address`,
    services: (n: number) => `${n} servizi${n === 1 ? 'o' : ''}`,
    svcGroups: (n: number) => `${n} grupp${n === 1 ? 'o' : 'i'} servizi`,
    morePorts: (n: number) => `+${n} altr${n === 1 ? 'a' : 'e'}`,
  },
})

export type Sev = 'danger' | 'warn' | 'info'
export type Evidence =
  | { view: 'expo'; risky?: boolean }
  | { view: 'rules'; q: string }
  | { view: 'objects' }
  | { view: 'findings'; zone?: string }
export interface Finding {
  id: string
  sev: Sev
  zone: string | null
  title: string
  detail: string // ports shortened to the first few
  full: string // the same with every port, for the tooltip
  ev: Evidence
}

// A published group can list dozens of ports: the first few, then a count
const PORTS_SHOWN = 4
function shortPorts(ports: string): string {
  const l = ports.split(', ')
  return l.length > PORTS_SHOWN ? `${l.slice(0, PORTS_SHOWN).join(', ')} ${s.morePorts(l.length - PORTS_SHOWN)}` : ports
}

export function findings(cfg: FirewallConfig): Finding[] {
  const exp = exposure(cfg)
  const shadows = shadowedRules(cfg)
  const orphans = orphanObjects(cfg)
  const placed = placeAddresses(cfg)
  const zones = new Set(cfg.zones.map(z => z.name))
  // A zone only counts if it is drawn: 'any' and unknown names get no dot
  const drawn = (z: string | null | undefined) => (z && zones.has(z) ? z : null)
  const hostZone = (host?: string) => drawn(host ? placed[host] : null)
  const out: Finding[] = []
  const push = (f: Omit<Finding, 'full'>, ports?: string) => out.push(
    ports ? { ...f, full: f.detail.replace(shortPorts(ports), ports) } : { ...f, full: f.detail },
  )

  // The real gap: what answers the Internet on a management port
  for (const n of exp.nats.filter(x => x.risky && x.allowRule)) {
    push({
      id: `nat:${n.nat.name}`, sev: 'danger',
      zone: hostZone(n.nat.mapTo) ?? drawn(n.allowRule?.to),
      title: s.exposed(n.service),
      detail: `${n.nat.name} → ${n.nat.mapTo} · ${shortPorts(n.ports)}`,
      ev: { view: 'expo', risky: true },
    }, n.ports)
  }
  for (const x of exp.rules.filter(r => r.risky)) {
    const r = x.rule
    push({
      id: `wan:${r.name}`, sev: 'danger',
      zone: drawn(r.to) ?? hostZone(r.destIp),
      title: r.destIp === 'any' ? s.anyFromNet(r.name) : s.sensitiveFromNet(r.name),
      detail: `#${r.order + 1} ${r.from} → ${r.to} · ${r.destIp} · ${shortPorts(x.ports)}`,
      ev: { view: 'rules', q: r.name },
    }, x.ports)
  }
  // Rules the firewall never applies, with the opposite action of the rule covering them
  for (const x of shadows.filter(y => y.kind === 'conflitto')) {
    push({
      id: `conf:${x.rule.name}`, sev: 'danger',
      zone: drawn(x.rule.from) ?? drawn(x.rule.to),
      title: s.conflict(x.rule.name),
      detail: `#${x.rule.order + 1} ${x.rule.from} → ${x.rule.to} · ${s.coveredBy(`#${x.by.order + 1} ${x.by.name} (${x.by.action})`)}`,
      ev: { view: 'rules', q: x.rule.name },
    })
  }
  // Published NAT with no allow rule: either dead, or reachable through a
  // path static analysis cannot see. Worth a look either way.
  for (const n of exp.nats.filter(x => !x.allowRule)) {
    push({
      id: `gate:${n.nat.name}`, sev: 'warn',
      zone: hostZone(n.nat.mapTo),
      title: s.noGate(n.nat.name),
      detail: `${n.nat.mapTo} · ${n.service} · ${shortPorts(n.ports)}`,
      ev: { view: 'expo' },
    }, n.ports)
  }
  // Dead weight: breaks nothing, but clutters the config
  for (const x of shadows.filter(y => y.kind === 'ridondante')) {
    push({
      id: `red:${x.rule.name}`, sev: 'info',
      zone: drawn(x.rule.from) ?? drawn(x.rule.to),
      title: s.redundant(x.rule.name),
      detail: `#${x.rule.order + 1} ${x.rule.from} → ${x.rule.to} · ${s.coveredBy(`#${x.by.order + 1} ${x.by.name}`)}`,
      ev: { view: 'rules', q: x.rule.name },
    })
  }
  const parts = [
    [orphans.addresses.length, s.addr],
    [orphans.addressGroups.length, s.addrGroups],
    [orphans.services.length, s.services],
    [orphans.serviceGroups.length, s.svcGroups],
  ] as const
  const nOrphans = parts.reduce((n, [k]) => n + k, 0)
  if (nOrphans > 0) {
    push({
      id: 'orphans', sev: 'info', zone: null,
      title: s.orphans(nOrphans),
      detail: parts.filter(([k]) => k > 0).map(([k, f]) => f(k)).join(' · '),
      ev: { view: 'objects' },
    })
  }
  return out
}

// Worst severity per zone, for the dot on the zone card
export function zoneSeverity(list: Finding[]): Map<string, Sev> {
  const m = new Map<string, Sev>()
  for (const f of list) {
    if (!f.zone || f.sev === 'info') continue
    if (m.get(f.zone) !== 'danger') m.set(f.zone, f.sev)
  }
  return m
}
