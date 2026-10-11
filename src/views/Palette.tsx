import { useEffect, useMemo, useRef, useState } from 'react'
import type { FirewallConfig } from '../model'
import type { Sel } from './DetailPanel'
import { ifaceZoneMap, ipToInt, resolveAddr, resolveService } from '../derive'
import IpSearch from './IpSearch'
import { loc } from '../i18n'

const s = loc({
  en: {
    zone: 'zone',
    group: 'group',
    rule: 'rule',
    ifaces: (n: number) => `${n} interface${n === 1 ? '' : 's'}`,
    aria: 'Global search',
    placeholder: 'Name or IP: zone, interface, VPN, object, rule…',
    inputAria: 'Search the whole configuration',
    hint: ['Search by name across zones, interfaces, VPN sites, objects, services, rules, routes and NAT, or type a full IP to see where it appears. ', ' to move, ', ' to open.'],
    enter: 'Enter',
    noHit: (q: string) => `No name contains "${q}". For an IP, type the full address (e.g. 192.168.1.20).`,
  },
  it: {
    zone: 'zona',
    group: 'gruppo',
    rule: 'regola',
    ifaces: (n: number) => `${n} interfacc${n === 1 ? 'ia' : 'e'}`,
    aria: 'Ricerca globale',
    placeholder: 'Nome o IP: zona, interfaccia, VPN, oggetto, regola…',
    inputAria: 'Cerca in tutta la configurazione',
    hint: ['Cerca per nome in zone, interfacce, sedi VPN, oggetti, servizi, regole, route e NAT, oppure digita un IP completo per vedere dove compare. ', ' per muoverti, ', ' per aprire.'],
    enter: 'Invio',
    noHit: (q: string) => `Nessun nome contiene «${q}». Per un IP serve l'indirizzo completo (es. 192.168.1.20).`,
  },
})

export type PaletteAction =
  | { kind: 'map'; sel: Sel }
  | { kind: 'rules'; query: string }
  | { kind: 'routes'; query: string }

interface Entry { badge: string; label: string; sub: string; act: PaletteAction }

// Global name search: zones, interfaces, VPN sites, objects, services,
// rules, routes and NAT. A full IPv4 switches to IP search.
export default function Palette({ cfg, onPick, onClose }: {
  cfg: FirewallConfig
  onPick: (a: PaletteAction) => void
  onClose: () => void
}) {
  const [q, setQ] = useState('')
  const [idx, setIdx] = useState(0)
  const inputRef = useRef<HTMLInputElement>(null)
  const listRef = useRef<HTMLDivElement>(null)

  const entries = useMemo<Entry[]>(() => {
    const ifZone = ifaceZoneMap(cfg)
    const out: Entry[] = []
    for (const z of cfg.zones) {
      out.push({ badge: s.zone, label: z.name, sub: z.description ?? s.ifaces(z.interfaces.length), act: { kind: 'map', sel: { kind: 'zone', name: z.name } } })
    }
    for (const i of cfg.interfaces) {
      out.push({ badge: 'iface', label: i.name, sub: [i.ip, ifZone[i.name], i.description].filter(Boolean).join(' · '), act: { kind: 'map', sel: { kind: 'iface', name: i.name } } })
    }
    for (const v of cfg.vpns) {
      out.push({ badge: 'vpn', label: v.name, sub: v.remoteTs.join(', ') || v.remoteAddress || '', act: { kind: 'map', sel: { kind: 'vpnsite', name: v.name } } })
    }
    for (const a of Object.values(cfg.addresses)) {
      out.push({ badge: 'addr', label: a.name, sub: `${a.type} ${a.value}`, act: { kind: 'map', sel: { kind: 'addr', name: a.name } } })
    }
    for (const g of Object.values(cfg.addressGroups)) {
      out.push({ badge: s.group, label: g.name, sub: resolveAddr(cfg, g.name), act: { kind: 'map', sel: { kind: 'addr', name: g.name } } })
    }
    for (const x of Object.values(cfg.services)) {
      out.push({ badge: 'svc', label: x.name, sub: `${x.proto} ${x.value}`, act: { kind: 'rules', query: x.name } })
    }
    for (const g of Object.values(cfg.serviceGroups)) {
      out.push({ badge: 'svc·grp', label: g.name, sub: resolveService(cfg, g.name), act: { kind: 'rules', query: g.name } })
    }
    for (const r of cfg.rules) {
      out.push({ badge: s.rule, label: r.name, sub: `#${r.order + 1} · ${r.from} → ${r.to} · ${r.action}`, act: { kind: 'rules', query: r.name } })
    }
    for (const r of cfg.routes) {
      out.push({ badge: 'route', label: r.name, sub: `${r.source} → ${r.destination} · ${r.nextHopType ?? ''} ${r.nextHop ?? ''}`, act: { kind: 'routes', query: r.name } })
    }
    for (const n of cfg.nats) {
      out.push({ badge: 'nat', label: n.name, sub: `${n.originalIp ?? '?'} → ${n.mapTo ?? '?'}`, act: { kind: 'map', sel: { kind: 'nat', name: n.name } } })
    }
    return out
  }, [cfg])

  const ip = ipToInt(q.trim())

  const hits = useMemo(() => {
    const needle = q.trim().toLowerCase()
    if (!needle || ip !== null) return []
    const rank = (e: Entry) => {
      const l = e.label.toLowerCase()
      if (l.startsWith(needle)) return 0
      if (l.includes(needle)) return 1
      if (e.sub.toLowerCase().includes(needle)) return 2
      return -1
    }
    return entries
      .map(e => ({ e, r: rank(e) }))
      .filter(x => x.r >= 0)
      .sort((a, b) => a.r - b.r || a.e.label.localeCompare(b.e.label))
      .slice(0, 25)
      .map(x => x.e)
  }, [entries, q, ip])

  useEffect(() => { inputRef.current?.focus() }, [])
  useEffect(() => { setIdx(0) }, [q])
  useEffect(() => {
    listRef.current?.querySelector('[aria-selected="true"]')?.scrollIntoView({ block: 'nearest' })
  }, [idx])

  function onKey(e: React.KeyboardEvent) {
    if (e.key === 'Escape') { onClose(); return }
    if (e.key === 'ArrowDown') { e.preventDefault(); setIdx(i => Math.min(i + 1, hits.length - 1)) }
    else if (e.key === 'ArrowUp') { e.preventDefault(); setIdx(i => Math.max(i - 1, 0)) }
    else if (e.key === 'Enter' && hits[idx]) { onPick(hits[idx].act) }
  }

  return (
    <div className="palback" onMouseDown={e => { if (e.target === e.currentTarget) onClose() }}>
      <div className="pal" role="dialog" aria-label={s.aria}>
        <input
          ref={inputRef} type="text" value={q}
          placeholder={s.placeholder}
          aria-label={s.inputAria}
          onChange={e => setQ(e.target.value)}
          onKeyDown={onKey}
        />
        <div className="pallist" ref={listRef} role={ip === null && hits.length > 0 ? 'listbox' : undefined}>
          {q.trim() === '' && (
            <div className="palhint">
              {s.hint[0]}<kbd>↑↓</kbd>{s.hint[1]}<kbd>{s.enter}</kbd>{s.hint[2]}
            </div>
          )}
          {ip !== null && <IpSearch cfg={cfg} ip={ip} />}
          {q.trim() !== '' && ip === null && hits.length === 0 && (
            <div className="palhint">
              {s.noHit(q.trim())}
            </div>
          )}
          {hits.map((h, k) => (
            <div
              key={`${h.badge}:${h.label}`}
              role="option" aria-selected={k === idx}
              className={`palrow${k === idx ? ' on' : ''}`}
              onMouseEnter={() => setIdx(k)}
              onMouseDown={e => e.preventDefault()}
              onClick={() => onPick(h.act)}
            >
              <span className={`palbadge b-${h.act.kind}`}>{h.badge}</span>
              <span className="pallabel">{h.label}</span>
              <span className="palsub">{h.sub}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
