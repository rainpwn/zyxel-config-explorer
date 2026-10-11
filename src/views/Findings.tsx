import type { Evidence, Finding } from './findingsList'
import { IconArrowRight } from '../icons'
import { loc } from '../i18n'

const s = loc({
  en: {
    go: { expo: 'Exposure', rules: 'Rules', objects: 'Objects', findings: 'Findings' } as Record<Evidence['view'], string>,
    sev: { danger: 'danger', warn: 'warning', info: 'info' } as Record<Finding['sev'], string>,
    note: 'Static analysis of the config: it shows the openings and contradictions written into the rules, not the live state of the services.',
    clean: 'Nothing to report: no sensitive ports exposed, no conflicting rules.',
    listAria: 'Findings ordered by severity',
    zoneOnly: (z: string, n: number) => `Zone ${z} only, ${n} finding${n === 1 ? '' : 's'}.`,
    showAll: 'Show all',
    sensitive: 'Sensitive ports: ftp, ssh, telnet, rpc, smb, database, rdp, vnc, plus any rule from the Internet with destination any.',
  },
  it: {
    go: { expo: 'Esposizione', rules: 'Regole', objects: 'Oggetti', findings: 'Riscontri' },
    sev: { danger: 'pericolo', warn: 'avviso', info: 'info' },
    note: 'Analisi statica della config: mostra i varchi e le contraddizioni scritte nelle regole, non lo stato reale dei servizi.',
    clean: 'Nessun riscontro: niente porte sensibili esposte, niente regole in conflitto.',
    listAria: 'Riscontri ordinati per gravità',
    zoneOnly: (z: string, n: number) => `Solo la zona ${z}, ${n} riscontr${n === 1 ? 'o' : 'i'}.`,
    showAll: 'Mostra tutti',
    sensitive: 'Porte sensibili: ftp, ssh, telnet, rpc, smb, database, rdp, vnc, più ogni regola da Internet con destinazione any.',
  },
})

export const goLabel = (ev: Evidence) => s.go[ev.view]

// One finding: severity dot, title, mono evidence, link to the view that
// explains it. Shared by the Findings view and the map's side panel.
export function FindingItem({ f, onGo, zone }: { f: Finding; onGo: (ev: Evidence) => void; zone?: boolean }) {
  return (
    <button className="fitem" onClick={() => onGo(f.ev)}>
      <span className={`dot ${f.sev}`} role="img" aria-label={s.sev[f.sev]} />
      <span className="fbody">
        <b>{f.title}</b>
        <small title={f.full}>{f.detail}</small>
        {/* in the narrow panel the link goes under the text, so titles keep the width */}
        {!zone && <span className="go">{s.go[f.ev.view]} <IconArrowRight size={12} /></span>}
      </span>
      {zone && <span className="fzone">{f.zone ?? '–'}</span>}
      {zone && <span className="go">{s.go[f.ev.view]} <IconArrowRight size={12} /></span>}
    </button>
  )
}

export default function Findings({ list: all, zone, onGo, onAll }: {
  list: Finding[]
  zone: string | null // from a zone's "+N more" link
  onGo: (ev: Evidence) => void
  onAll: () => void
}) {
  const list = zone ? all.filter(f => f.zone === zone) : all
  return (
    <div className="pagebody">
      <p className="lead">{s.note}</p>
      {zone && (
        <p className="filterline">
          {s.zoneOnly(zone, list.length)} <button className="linkbtn" onClick={onAll}>{s.showAll}</button>
        </p>
      )}
      {list.length === 0
        ? <p className="clean">{s.clean}</p>
        : (
          <ul className="flist" aria-label={s.listAria}>
            {list.map(f => <li key={f.id}><FindingItem f={f} onGo={onGo} zone /></li>)}
          </ul>
        )}
      {list.some(f => f.ev.view === 'expo' || f.id.startsWith('wan:')) && <p className="footnote">{s.sensitive}</p>}
    </div>
  )
}

export const sevLabel = s.sev
