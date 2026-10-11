import { useMemo, useState } from 'react'
import type { FirewallConfig } from '../model'
import { resolveAddr } from '../derive'
import { loc } from '../i18n'

const s = loc({
  en: {
    search: 'Search: name, IP, object, tunnel…',
    searchAria: 'Search policy routes',
    fromAll: 'From: all',
    hopAll: 'Next-hop: all',
    count: (n: number, tot: number) => `${n} / ${tot} routes`,
    none: 'No routes match the filters',
    reset: 'Clear filters',
    tableAria: 'Policy routes',
    name: 'Name',
  },
  it: {
    search: 'Cerca: nome, IP, oggetto, tunnel…',
    searchAria: 'Cerca nelle policy route',
    fromAll: 'From: tutte',
    hopAll: 'Next-hop: tutti',
    count: (n: number, tot: number) => `${n} / ${tot} route`,
    none: 'Nessuna route corrisponde ai filtri',
    reset: 'Azzera filtri',
    tableAria: 'Policy route',
    name: 'Nome',
  },
})

export default function RoutesTable({ cfg, initialQuery = '' }: {
  cfg: FirewallConfig
  initialQuery?: string
}) {
  const [q, setQ] = useState(initialQuery)
  const [from, setFrom] = useState('')
  const [hop, setHop] = useState('')

  const froms = useMemo(() => [...new Set(cfg.routes.map(r => r.from))].sort(), [cfg])
  const hops = useMemo(() => [...new Set(cfg.routes.map(r => r.nextHopType ?? '?'))].sort(), [cfg])

  const rows = useMemo(() => {
    const needle = q.trim().toLowerCase()
    return cfg.routes.filter(r => {
      if (from && r.from !== from) return false
      if (hop && r.nextHopType !== hop) return false
      if (needle) {
        const hay = [
          r.name, r.from, r.source, r.destination, r.service,
          r.nextHopType ?? '', r.nextHop ?? '',
          resolveAddr(cfg, r.source), resolveAddr(cfg, r.destination),
        ].join(' ').toLowerCase()
        if (!hay.includes(needle)) return false
      }
      return true
    })
  }, [cfg, q, from, hop])

  return (
    <div className="tablewrap">
      <div className="tabletools">
        <input
          type="text" placeholder={s.search}
          aria-label={s.searchAria}
          value={q} onChange={e => setQ(e.target.value)}
        />
        <select value={from} onChange={e => setFrom(e.target.value)}>
          <option value="">{s.fromAll}</option>
          {froms.map(z => <option key={z} value={z}>{z}</option>)}
        </select>
        <select value={hop} onChange={e => setHop(e.target.value)}>
          <option value="">{s.hopAll}</option>
          {hops.map(h => <option key={h} value={h}>{h}</option>)}
        </select>
        <span className="count">{s.count(rows.length, cfg.routes.length)}</span>
      </div>
      <div className="tscroll">
        {rows.length === 0 && (
          <div className="empty">
            <b>{s.none}</b>
            <button className="btn" onClick={() => { setQ(''); setFrom(''); setHop('') }}>{s.reset}</button>
          </div>
        )}
        {rows.length > 0 && (
          <table className="rules" aria-label={s.tableAria}>
            <thead>
              <tr>
                <th>#</th><th>{s.name}</th><th>From</th><th>Source</th>
                <th>Destination</th><th>Service</th><th>Next-hop</th><th>On</th>
              </tr>
            </thead>
            <tbody>
              {rows.map(r => (
                <tr key={r.name} className={r.enabled ? '' : 'off'}>
                  <td className="num">{r.order + 1}</td>
                  <td className="name">{r.name}</td>
                  <td className="zone"><b>{r.from}</b></td>
                  <td className="mono" title={resolveAddr(cfg, r.source)}>{r.source}</td>
                  <td className="mono" title={resolveAddr(cfg, r.destination)}>{r.destination}</td>
                  <td className="mono">{r.service}</td>
                  <td><span className="hop">{r.nextHopType} {r.nextHop}</span></td>
                  <td><span className={`dot ${r.enabled ? 'on' : 'off'}`} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}
