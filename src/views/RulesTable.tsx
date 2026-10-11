import { useMemo, useState } from 'react'
import type { FirewallConfig } from '../model'
import { resolveAddr, resolveService } from '../derive'
import { loc } from '../i18n'

const s = loc({
  en: {
    search: 'Search: name, IP, object, service…',
    searchAria: 'Search rules',
    fromAll: 'From: all',
    toAll: 'To: all',
    actionAll: 'Action: all',
    stateAll: 'State: all',
    on: 'enabled',
    off: 'disabled',
    count: (n: number, tot: number) => `${n} / ${tot} rules`,
    none: 'No rules match the filters',
    noneHint: 'Try a broader search or remove a filter.',
    reset: 'Clear filters',
    tableAria: 'Secure-policy rules',
    name: 'Name',
  },
  it: {
    search: 'Cerca: nome, IP, oggetto, servizio…',
    searchAria: 'Cerca nelle regole',
    fromAll: 'From: tutte',
    toAll: 'To: tutte',
    actionAll: 'Azione: tutte',
    stateAll: 'Stato: tutti',
    on: 'attive',
    off: 'disabilitate',
    count: (n: number, tot: number) => `${n} / ${tot} regole`,
    none: 'Nessuna regola corrisponde ai filtri',
    noneHint: 'Prova ad allargare la ricerca o a rimuovere qualche filtro.',
    reset: 'Azzera filtri',
    tableAria: 'Regole secure-policy',
    name: 'Nome',
  },
})

export default function RulesTable({ cfg, initialFrom = '', initialTo = '', initialQuery = '' }: {
  cfg: FirewallConfig
  initialFrom?: string
  initialTo?: string
  initialQuery?: string
}) {
  const [q, setQ] = useState(initialQuery)
  const [from, setFrom] = useState(initialFrom)
  const [to, setTo] = useState(initialTo)
  const [action, setAction] = useState('')
  const [state, setState] = useState('')

  const zones = useMemo(() => {
    const z = new Set<string>()
    for (const r of cfg.rules) { z.add(r.from); z.add(r.to) }
    return [...z].sort()
  }, [cfg])

  const rows = useMemo(() => {
    const needle = q.trim().toLowerCase()
    return cfg.rules.filter(r => {
      if (from && r.from !== from) return false
      if (to && r.to !== to) return false
      if (action && r.action !== action) return false
      if (state === 'on' && !r.enabled) return false
      if (state === 'off' && r.enabled) return false
      if (needle) {
        const hay = [
          r.name, r.description ?? '', r.from, r.to, r.sourceIp, r.destIp,
          r.service, r.user, resolveAddr(cfg, r.sourceIp),
          resolveAddr(cfg, r.destIp), resolveService(cfg, r.service),
        ].join(' ').toLowerCase()
        if (!hay.includes(needle)) return false
      }
      return true
    })
  }, [cfg, q, from, to, action, state])

  return (
    <div className="tablewrap">
      <div className="tabletools">
        <input
          type="search" placeholder={s.search}
          aria-label={s.searchAria}
          value={q} onChange={e => setQ(e.target.value)}
        />
        <select value={from} onChange={e => setFrom(e.target.value)}>
          <option value="">{s.fromAll}</option>
          {zones.map(z => <option key={z} value={z}>{z}</option>)}
        </select>
        <select value={to} onChange={e => setTo(e.target.value)}>
          <option value="">{s.toAll}</option>
          {zones.map(z => <option key={z} value={z}>{z}</option>)}
        </select>
        <select value={action} onChange={e => setAction(e.target.value)}>
          <option value="">{s.actionAll}</option>
          <option value="allow">allow</option>
          <option value="deny">deny</option>
        </select>
        <select value={state} onChange={e => setState(e.target.value)}>
          <option value="">{s.stateAll}</option>
          <option value="on">{s.on}</option>
          <option value="off">{s.off}</option>
        </select>
        <span className="count">{s.count(rows.length, cfg.rules.length)}</span>
      </div>
      <div className="tscroll">
        {rows.length === 0 && (
          <div className="empty">
            <b>{s.none}</b>
            {s.noneHint}
            <br />
            <button
              className="btn"
              onClick={() => { setQ(''); setFrom(''); setTo(''); setAction(''); setState('') }}
            >
              {s.reset}
            </button>
          </div>
        )}
        {rows.length > 0 && (
        <table className="rules" aria-label={s.tableAria}>
          <thead>
            <tr>
              <th>#</th><th>{s.name}</th><th>From → To</th><th>Source</th>
              <th>Destination</th><th>Service</th><th>User</th>
              <th>Action</th><th>Log</th>
            </tr>
          </thead>
          <tbody>
            {rows.map(r => (
              // deny is the exception among hundreds of allows: it stands out on its own
              <tr key={r.name} className={`${r.enabled ? '' : 'off'}${r.action === 'deny' && r.enabled ? ' isdeny' : ''}`}>
                <td className="num">{r.order + 1}</td>
                <td className="name">
                  {r.name}
                  {/* the normal case (enabled) is not announced: only disabled rules are marked */}
                  {!r.enabled && <> <span className="offmark">off</span></>}
                  {r.description && <small>{r.description}</small>}
                </td>
                <td className="zone"><b>{r.from}</b> <i>→</i> <b>{r.to}</b></td>
                <td className="mono" title={resolveAddr(cfg, r.sourceIp)}>{r.sourceIp}</td>
                <td className="mono" title={resolveAddr(cfg, r.destIp)}>{r.destIp}</td>
                <td className="mono" title={resolveService(cfg, r.service)}>{r.service}</td>
                <td className="mono">{r.user}</td>
                <td><span className={`badge ${r.action}`}>{r.action}</span></td>
                <td className="mono">{r.logging === 'no' ? '–' : r.logging}</td>
              </tr>
            ))}
          </tbody>
        </table>
        )}
      </div>
    </div>
  )
}
