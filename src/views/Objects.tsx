import { useMemo, useState } from 'react'
import type { FirewallConfig } from '../model'
import { placeAddresses } from '../derive'
import { natService } from '../analysis'
import { downloadCsv } from '../csv'
import { loc } from '../i18n'

type Cat = 'addr' | 'addrgrp' | 'svc' | 'svcgrp'

const s = loc({
  en: {
    cat: { addr: 'address', addrgrp: 'addr group', svc: 'service', svcgrp: 'svc group' } as Record<Cat, string>,
    search: 'Search: name, IP, port, member…',
    searchAria: 'Search objects',
    typeAria: 'Filter by object type',
    typeAll: 'Type: all',
    addrGroups: 'address groups',
    services: 'services',
    svcGroups: 'service groups',
    onlyOrphans: 'orphans only',
    csvTitle: 'Download the rows shown as CSV',
    csvFile: 'objects.csv',
    csvHead: ['Name', 'Type', 'Value', 'Zone', 'Rules', 'Routes', 'NAT', 'Orphan'],
    yes: 'yes',
    count: (n: number, tot: number) => `${n} / ${tot} objects`,
    none: 'No objects match the filters',
    reset: 'Clear filters',
    tableAria: 'Configuration objects',
    head: ['Name', 'Type', 'Value', 'Zone', 'Used by'],
    rules: (n: number) => `${n} rule${n === 1 ? '' : 's'}`,
    routes: (n: number) => `${n} route${n === 1 ? '' : 's'}`,
    orphan: 'orphan',
  },
  it: {
    cat: { addr: 'address', addrgrp: 'gruppo addr', svc: 'servizio', svcgrp: 'gruppo svc' },
    search: 'Cerca: nome, IP, porta, membro…',
    searchAria: 'Cerca negli oggetti',
    typeAria: 'Filtra per tipo di oggetto',
    typeAll: 'Tipo: tutti',
    addrGroups: 'gruppi address',
    services: 'servizi',
    svcGroups: 'gruppi servizi',
    onlyOrphans: 'solo orfani',
    csvTitle: 'Scarica le righe mostrate come CSV',
    csvFile: 'oggetti.csv',
    csvHead: ['Nome', 'Tipo', 'Valore', 'Zona', 'Regole', 'Route', 'NAT', 'Orfano'],
    yes: 'sì',
    count: (n: number, tot: number) => `${n} / ${tot} oggetti`,
    none: 'Nessun oggetto corrisponde ai filtri',
    reset: 'Azzera filtri',
    tableAria: 'Oggetti della configurazione',
    head: ['Nome', 'Tipo', 'Valore', 'Zona', 'Usato da'],
    rules: (n: number) => `${n} ${n === 1 ? 'regola' : 'regole'}`,
    routes: (n: number) => `${n} route`,
    orphan: 'orfano',
  },
})
const CAT_LABEL = s.cat

interface Row {
  cat: Cat
  name: string
  value: string
  zone?: string
  rules: string[]
  routes: string[]
  nats: string[]
}

interface Use { rules: Set<string>; routes: Set<string>; nats: Set<string> }

// Object explorer: each address/service object with where it is used
// (rules, routes, NAT), including indirect references through groups.
export default function Objects({ cfg, initialOrphans = false }: { cfg: FirewallConfig; initialOrphans?: boolean }) {
  const [q, setQ] = useState('')
  const [cat, setCat] = useState('')
  const [onlyOrphans, setOnlyOrphans] = useState(initialOrphans)

  const rows = useMemo(() => {
    const addrUse = new Map<string, Use>()
    const svcUse = new Map<string, Use>()
    const get = (m: Map<string, Use>, n: string): Use => {
      let u = m.get(n)
      if (!u) { u = { rules: new Set(), routes: new Set(), nats: new Set() }; m.set(n, u) }
      return u
    }
    // mark the object and, if it is a group, all nested members
    const visit = (m: Map<string, Use>, groups: Record<string, { members: string[] }>) => {
      const rec = (n: string | undefined, mark: (u: Use) => void, seen = new Set<string>()) => {
        if (!n || n === 'any' || seen.has(n)) return
        seen.add(n)
        mark(get(m, n))
        groups[n]?.members.forEach(x => rec(x, mark, seen))
      }
      return rec
    }
    const addr = visit(addrUse, cfg.addressGroups)
    const svc = visit(svcUse, cfg.serviceGroups)

    for (const r of cfg.rules) {
      addr(r.sourceIp, u => u.rules.add(r.name))
      addr(r.destIp, u => u.rules.add(r.name))
      svc(r.service, u => u.rules.add(r.name))
    }
    for (const r of cfg.routes) {
      addr(r.source, u => u.routes.add(r.name))
      addr(r.destination, u => u.routes.add(r.name))
      svc(r.service, u => u.routes.add(r.name))
    }
    for (const n of cfg.nats) {
      addr(n.sourceIp, u => u.nats.add(n.name))
      addr(n.originalIp, u => u.nats.add(n.name))
      addr(n.mapTo, u => u.nats.add(n.name))
      svc(natService(n.mapType), u => u.nats.add(n.name))
    }

    const placed = placeAddresses(cfg)
    const row = (cat: Cat, name: string, value: string, use?: Use): Row => ({
      cat, name, value, zone: cat === 'addr' ? placed[name] : undefined,
      rules: [...(use?.rules ?? [])], routes: [...(use?.routes ?? [])], nats: [...(use?.nats ?? [])],
    })
    const out: Row[] = []
    for (const a of Object.values(cfg.addresses)) out.push(row('addr', a.name, `${a.type} ${a.value}`, addrUse.get(a.name)))
    for (const g of Object.values(cfg.addressGroups)) out.push(row('addrgrp', g.name, g.members.join(', '), addrUse.get(g.name)))
    for (const s of Object.values(cfg.services)) out.push(row('svc', s.name, `${s.proto} ${s.value}`, svcUse.get(s.name)))
    for (const g of Object.values(cfg.serviceGroups)) out.push(row('svcgrp', g.name, g.members.join(', '), svcUse.get(g.name)))
    return out.sort((a, b) => a.name.localeCompare(b.name))
  }, [cfg])

  const shown = useMemo(() => {
    const needle = q.trim().toLowerCase()
    return rows.filter(r => {
      if (cat && r.cat !== cat) return false
      if (onlyOrphans && (r.rules.length || r.routes.length || r.nats.length)) return false
      if (needle && !`${r.name} ${r.value}`.toLowerCase().includes(needle)) return false
      return true
    })
  }, [rows, q, cat, onlyOrphans])

  return (
    <div className="tablewrap">
      <div className="tabletools">
        <input
          type="text" placeholder={s.search}
          aria-label={s.searchAria}
          value={q} onChange={e => setQ(e.target.value)}
        />
        <select value={cat} onChange={e => setCat(e.target.value)} aria-label={s.typeAria}>
          <option value="">{s.typeAll}</option>
          <option value="addr">address</option>
          <option value="addrgrp">{s.addrGroups}</option>
          <option value="svc">{s.services}</option>
          <option value="svcgrp">{s.svcGroups}</option>
        </select>
        <label className="check">
          <input type="checkbox" checked={onlyOrphans} onChange={e => setOnlyOrphans(e.target.checked)} />
          {' '}{s.onlyOrphans}
        </label>
        <button
          className="btn" title={s.csvTitle}
          onClick={() => downloadCsv(s.csvFile, [
            s.csvHead,
            ...shown.map(r => [
              r.name, CAT_LABEL[r.cat], r.value, r.zone ?? '',
              r.rules.join(', '), r.routes.join(', '), r.nats.join(', '),
              r.rules.length || r.routes.length || r.nats.length ? '' : s.yes,
            ]),
          ])}
        >
          CSV
        </button>
        <span className="count">{s.count(shown.length, rows.length)}</span>
      </div>
      <div className="tscroll">
        {shown.length === 0 && (
          <div className="empty">
            <b>{s.none}</b>
            <button className="btn" onClick={() => { setQ(''); setCat(''); setOnlyOrphans(false) }}>{s.reset}</button>
          </div>
        )}
        {shown.length > 0 && (
          <table className="rules" aria-label={s.tableAria}>
            <thead>
              <tr>{s.head.map(h => <th key={h}>{h}</th>)}</tr>
            </thead>
            <tbody>
              {shown.map(r => {
                const uses = [
                  r.rules.length && s.rules(r.rules.length),
                  r.routes.length && s.routes(r.routes.length),
                  r.nats.length && `${r.nats.length} NAT`,
                ].filter(Boolean).join(' · ')
                const detail = [...r.rules, ...r.routes, ...r.nats].slice(0, 15).join('\n')
                return (
                  <tr key={`${r.cat}:${r.name}`}>
                    <td className="name">{r.name}</td>
                    <td className="mono">{CAT_LABEL[r.cat]}</td>
                    <td className="mono" style={{ maxWidth: 420, overflowWrap: 'anywhere' }}>{r.value}</td>
                    <td className="mono">{r.zone ?? '–'}</td>
                    <td className="mono" title={detail}>
                      {uses || <span className="sev info">{s.orphan}</span>}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}
