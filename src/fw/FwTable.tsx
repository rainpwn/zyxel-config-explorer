import { useMemo, useState } from 'react'
import { FwSearch, FwStatus } from './fwicons'
import { loc } from '../i18n'

const s = loc({
  en: {
    readOnly: 'Read only',
    search: 'Search',
    searchTable: 'Search the table',
    empty: 'No entries.',
    on: 'enabled',
    off: 'disabled',
  },
  it: {
    readOnly: 'Sola lettura',
    search: 'Cerca',
    searchTable: 'Cerca nella tabella',
    empty: 'Nessun elemento.',
    on: 'attiva',
    off: 'disattivata',
  },
})

// `get` is the raw value (for sorting and search);
// `render` is optional, for special cells (green links, badges, status).
export interface Col<R> {
  key: string
  label: string
  get: (r: R) => string | number
  render?: (r: R) => React.ReactNode
  sortable?: boolean
  className?: string
}

// Every uOS page is this: section header, toolbar, sortable table.
// No fake Add/Edit/Remove: the view is read-only and says so.
export default function FwTable<R>({ title, cols, rows }: {
  title?: string
  cols: Col<R>[]
  rows: R[]
}) {
  const [q, setQ] = useState('')
  const [sort, setSort] = useState<{ key: string; dir: 1 | -1 } | null>(null)

  const view = useMemo(() => {
    const needle = q.trim().toLowerCase()
    let out = rows
    if (needle) {
      out = rows.filter(r => cols.map(c => String(c.get(r))).join(' ').toLowerCase().includes(needle))
    }
    if (sort) {
      const col = cols.find(c => c.key === sort.key)
      if (col) {
        out = [...out].sort((a, b) => {
          const va = col.get(a), vb = col.get(b)
          if (typeof va === 'number' && typeof vb === 'number') return (va - vb) * sort.dir
          return String(va).localeCompare(String(vb), 'it', { numeric: true }) * sort.dir
        })
      }
    }
    return out
  }, [rows, cols, q, sort])

  const toggleSort = (c: Col<R>) => {
    if (c.sortable === false) return
    setSort(s => s?.key === c.key ? { key: c.key, dir: s.dir === 1 ? -1 : 1 } : { key: c.key, dir: 1 })
  }

  return (
    <>
      {title && <div className="fw-sectitle">{title}</div>}
      <div className="fw-toolbar">
        <span className="fw-ro">{s.readOnly}</span>
        <div className="sp" />
        <label className="fw-find">
          <FwSearch size={15} />
          <input
            type="search" placeholder={s.search} aria-label={s.searchTable}
            value={q} onChange={e => setQ(e.target.value)}
          />
        </label>
      </div>
      <div className="fw-tablewrap">
        <table className="fw-table">
          <thead>
            <tr>
              {cols.map(c => (
                <th
                  key={c.key}
                  className={c.sortable === false ? 'nosort' : ''}
                  onClick={() => toggleSort(c)}
                >
                  {c.label}
                  {c.sortable !== false && (
                    <span className="sort">{sort?.key === c.key ? (sort.dir === 1 ? '▲' : '▼') : '⇅'}</span>
                  )}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {view.length === 0 && (
              <tr><td colSpan={cols.length} className="fw-empty">{s.empty}</td></tr>
            )}
            {view.map((r, i) => (
              <tr key={i}>
                {cols.map(c => (
                  <td key={c.key} className={c.className}>
                    {c.render ? c.render(r) : String(c.get(r))}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  )
}

// Reusable cells

// green link to an object, resolved value in the tooltip; "any" stays gray
export function ObjLink({ name, resolve, onNav }: {
  name: string
  resolve?: (n: string) => string
  onNav?: (n: string) => void
}) {
  if (!name || name === 'any') return <span className="fw-any">any</span>
  const title = resolve?.(name)
  return (
    <button className="fw-obj" title={title && title !== name ? title : undefined} onClick={() => onNav?.(name)}>
      {name}
    </button>
  )
}

export function StatusDot({ on }: { on: boolean }) {
  return <span className={`fw-status${on ? '' : ' off'}`} title={on ? s.on : s.off}><FwStatus /></span>
}
