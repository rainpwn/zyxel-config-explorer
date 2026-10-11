import { useMemo } from 'react'
import type { FirewallConfig } from '../model'
import { zonePairs } from '../derive'
import { loc } from '../i18n'

const s = loc({
  en: {
    aria: 'Traffic matrix between zones',
    cell: (f: string, t: string, allow: number, deny: number) => `${f} → ${t}: ${allow} allow, ${deny} deny (click for the rules)`,
    hint: 'Enabled rules only. Each cell counts the rules for that pair: grey is allow only, red deny only, amber mixed (allow / deny). Click a cell to list its rules.',
  },
  it: {
    aria: 'Matrice del traffico tra zone',
    cell: (f: string, t: string, allow: number, deny: number) => `${f} → ${t}: ${allow} allow, ${deny} deny (clicca per le regole)`,
    hint: 'Solo regole attive. Ogni cella conta le regole della coppia: grigio solo allow, rosso solo deny, ambra misto (allow / deny). Clicca una cella per elencarne le regole.',
  },
})

export default function Matrix({ cfg, onPick }: {
  cfg: FirewallConfig
  onPick: (from: string, to: string) => void
}) {
  const { names, cells } = useMemo(() => {
    const pairs = zonePairs(cfg.rules.filter(r => r.enabled))
    const names = cfg.zones.map(z => z.name)
    for (const p of pairs) {
      for (const n of [p.from, p.to]) if (!names.includes(n)) names.push(n)
    }
    const cells = new Map(pairs.map(p => [`${p.from}|${p.to}`, p]))
    return { names, cells }
  }, [cfg])

  return (
    <div className="matrixwrap">
      <table className="matrix" aria-label={s.aria}>
        <thead>
          <tr>
            <th className="rowhead">from \ to</th>
            {names.map(n => <th key={n} title={n}>{n}</th>)}
          </tr>
        </thead>
        <tbody>
          {names.map(f => (
            <tr key={f}>
              <th className="rowhead" title={f}>{f}</th>
              {names.map(t => {
                const p = cells.get(`${f}|${t}`)
                if (!p) return <td key={t} />
                const cls = p.deny === 0 ? 'allow' : p.allow === 0 ? 'deny' : 'mixed'
                const label = p.deny === 0 ? `${p.allow}` : p.allow === 0 ? `${p.deny}` : `${p.allow} / ${p.deny}`
                return (
                  <td
                    key={t} className={`has ${cls}`}
                    title={s.cell(f, t, p.allow, p.deny)}
                    tabIndex={0} role="button"
                    onClick={() => onPick(f, t)}
                    onKeyDown={e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onPick(f, t) } }}
                  >
                    {label}
                  </td>
                )
              })}
            </tr>
          ))}
        </tbody>
      </table>
      <p className="hintline">
        {s.hint}
      </p>
    </div>
  )
}
