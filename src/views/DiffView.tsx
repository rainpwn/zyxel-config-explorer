import { useMemo, useRef, useState } from 'react'
import type { FirewallConfig } from '../model'
import { parseUos } from '../parser/uos'
import { diffConfigs } from '../analysis'
import { loc } from '../i18n'

const s = loc({
  en: {
    notUos: (name: string) => `${name} doesn't look like a Zyxel uOS configuration.`,
    desc: ['Compares the loaded config (', ') with a second version (B). "Added" means only in B, "removed" means only in A, "changed" means the same name with different fields.'],
    change: (name: string) => `B: ${name} (change file)`,
    load: 'Load the second config (B)',
    total: (n: number) => `${n} difference${n === 1 ? '' : 's'} in total`,
    hint: ['Load another ', ' export from the same firewall, for example the one from before a change, to see what changed.'],
    same: 'The two configurations are identical (in the sections compared).',
  },
  it: {
    notUos: (name: string) => `${name} non sembra una configurazione Zyxel uOS.`,
    desc: ['Confronta la config caricata (', ') con una seconda versione (B). "Aggiunto" = presente solo in B, "rimosso" = presente solo in A, "modificato" = stesso nome con campi diversi.'],
    change: (name: string) => `B: ${name} (cambia file)`,
    load: 'Carica la seconda config (B)',
    total: (n: number) => n === 1 ? '1 differenza' : `${n} differenze totali`,
    hint: ["Carica un'altra esportazione ", ' dello stesso firewall, per esempio quella di prima di una modifica, per vedere cosa è cambiato.'],
    same: 'Le due configurazioni sono identiche (per le sezioni analizzate).',
  },
})

export default function DiffView({ cfg, filename }: { cfg: FirewallConfig; filename: string }) {
  const [other, setOther] = useState<{ cfg: FirewallConfig; name: string } | null>(null)
  const [err, setErr] = useState('')
  const fileRef = useRef<HTMLInputElement>(null)

  const diff = useMemo(
    () => (other ? diffConfigs(cfg, other.cfg) : null),
    [cfg, other],
  )
  const total = diff
    ? Object.values(diff).reduce((n, d) => n + d.added.length + d.removed.length + d.changed.length, 0)
    : 0

  async function onFile(f: File | undefined) {
    if (!f) return
    const parsed = parseUos(await f.text())
    if (parsed.rules.length === 0 && parsed.zones.length === 0) {
      setErr(s.notUos(f.name))
      return
    }
    setErr('')
    setOther({ cfg: parsed, name: f.name })
  }

  return (
    <div className="auditwrap">
      <div className="auditbox">
        <p className="desc">
          {s.desc[0]}<b>A: {filename}</b>{s.desc[1]}
        </p>
        <p>
          <button className="btn" onClick={() => fileRef.current?.click()}>
            {other ? s.change(other.name) : s.load}
          </button>
          <input
            ref={fileRef} type="file" accept=".conf,.txt" hidden
            onChange={e => { onFile(e.target.files?.[0]); e.target.value = '' }}
          />
          {diff && <span className="diffcount">{s.total(total)}</span>}
        </p>
        {err && <p className="simerr" role="alert">{err}</p>}

        {!other && !err && (
          <p className="desc">
            {s.hint[0]}<code>.conf</code>{s.hint[1]}
          </p>
        )}

        {diff && total === 0 && <p className="hint">{s.same}</p>}

        {diff && Object.entries(diff).map(([section, d]) => {
          const n = d.added.length + d.removed.length + d.changed.length
          if (n === 0) return null
          return (
            <div key={section}>
              <h2>{section}<span className="diffcount">{n}</span></h2>
              {d.added.map(x => <div key={`a${x}`} className="diffline add">+ {x}</div>)}
              {d.removed.map(x => <div key={`r${x}`} className="diffline del">− {x}</div>)}
              {d.changed.map(x => (
                <div key={`c${x.name}`} className="diffline mod">~ {x.name} ({x.fields.join(', ')})</div>
              ))}
            </div>
          )
        })}
      </div>
    </div>
  )
}
