import { useMemo, useState } from 'react'
import type { FirewallConfig } from '../model'
import { resolveAddr } from '../derive'
import { exposure } from '../analysis'
import { downloadCsv } from '../csv'
import { loc } from '../i18n'

const s = loc({
  en: {
    wan: 'Internet zone',
    nats: (n: number) => `NAT publication${n === 1 ? '' : 's'}`,
    rules: (n: number) => `allow rule${n === 1 ? '' : 's'} from the WAN`,
    risky: 'on sensitive ports',
    noGate: 'NAT with no allow rule',
    onlyRisky: 'sensitive ports only',
    csvTitle: 'Download the rows shown as CSV',
    csvFile: 'exposure.csv',
    csvHead: ['Section', 'Item', 'Detail', 'Service', 'Ports', 'Published on', 'Allow rule', 'Risk'],
    csvRule: 'Rule',
    none: 'none',
    sensitive: 'sensitive port',
    destAny: 'destination any',
    emptyTitle: 'No exposure found',
    empty: (wan: string) => `No active NAT and no allow rule from the ${wan} zone.`,
    natTitle: 'NAT virtual-server · ports open to the inside',
    natAria: 'Services published through NAT',
    host: 'Internal host',
    service: 'Service',
    ports: 'Ports',
    publishedOn: 'Published on',
    allowRule: 'Allow rule',
    noneFound: 'none found',
    rulesTitle: (wan: string) => `Allow rules with source ${wan} / any`,
    rulesAria: 'Allow rules from the WAN',
    name: 'Name',
    note: 'Static analysis: it shows the configured openings, not the live state of the services. Sensitive ports: ftp, ssh, telnet, rpc, smb, database, rdp, vnc.',
  },
  it: {
    wan: 'Zona Internet',
    nats: () => 'pubblicazioni NAT',
    rules: () => 'regole allow dalla WAN',
    risky: 'su porte sensibili',
    noGate: 'NAT senza regola allow',
    onlyRisky: 'solo porte sensibili',
    csvTitle: 'Scarica le righe mostrate come CSV',
    csvFile: 'esposizione.csv',
    csvHead: ['Sezione', 'Elemento', 'Dettaglio', 'Servizio', 'Porte', 'Pubblicato su', 'Regola allow', 'Rischio'],
    csvRule: 'Regola',
    none: 'nessuna',
    sensitive: 'porta sensibile',
    destAny: 'destinazione any',
    emptyTitle: 'Nessuna esposizione rilevata',
    empty: (wan: string) => `Nessun NAT attivo e nessuna regola allow dalla zona ${wan}.`,
    natTitle: "NAT virtual-server · porte aperte verso l'interno",
    natAria: 'Servizi pubblicati via NAT',
    host: 'Host interno',
    service: 'Servizio',
    ports: 'Porte',
    publishedOn: 'Pubblicato su',
    allowRule: 'Regola allow',
    noneFound: 'nessuna trovata',
    rulesTitle: (wan: string) => `Regole allow con sorgente ${wan} / any`,
    rulesAria: 'Regole allow dalla WAN',
    name: 'Nome',
    note: 'Analisi statica: mostra i varchi configurati, non lo stato reale dei servizi. Porte sensibili: ftp, ssh, telnet, rpc, smb, database, rdp, vnc.',
  },
})

// Exposed surface: what is reachable from the Internet given NAT and rules.
// initialOnlyRisky comes from overview findings, so the link lands on the
// exact rows the finding counted.
export default function Exposure({ cfg, initialOnlyRisky = false }: {
  cfg: FirewallConfig
  initialOnlyRisky?: boolean
}) {
  const [onlyRisky, setOnlyRisky] = useState(initialOnlyRisky)
  const exp = useMemo(() => exposure(cfg), [cfg])

  const nats = onlyRisky ? exp.nats.filter(n => n.risky) : exp.nats
  const rules = onlyRisky ? exp.rules.filter(r => r.risky) : exp.rules
  const riskyCount = exp.nats.filter(n => n.risky).length + exp.rules.filter(r => r.risky).length
  const noGate = exp.nats.filter(n => !n.allowRule).length

  return (
    <div className="tablewrap">
      <div className="tabletools">
        <span className="expostat">{s.wan} <b>{exp.wan}</b></span>
        <div className="sep" />
        <span className="expostat"><b>{exp.nats.length}</b> {s.nats(exp.nats.length)}</span>
        <div className="sep" />
        <span className="expostat"><b>{exp.rules.length}</b> {s.rules(exp.rules.length)}</span>
        {riskyCount > 0 && (
          <>
            <div className="sep" />
            <span className="expostat risky"><b>{riskyCount}</b> {s.risky}</span>
          </>
        )}
        {noGate > 0 && (
          <>
            <div className="sep" />
            <span className="expostat"><b>{noGate}</b> {s.noGate}</span>
          </>
        )}
        <label className="check push">
          <input type="checkbox" checked={onlyRisky} onChange={e => setOnlyRisky(e.target.checked)} />
          {' '}{s.onlyRisky}
        </label>
        <button
          className="btn" title={s.csvTitle}
          onClick={() => downloadCsv(s.csvFile, [
            s.csvHead,
            ...nats.map(x => [
              'NAT', x.nat.mapTo!, resolveAddr(cfg, x.nat.mapTo!), x.service, x.ports,
              `${x.nat.iface ?? ''}${x.nat.originalIp ? ` · ${x.nat.originalIp}` : ''}`,
              x.allowRule ? `#${x.allowRule.order + 1} ${x.allowRule.name}` : s.none,
              x.risky ? s.sensitive : '',
            ]),
            ...rules.map(({ rule: r, ports, risky }) => [
              s.csvRule, r.name, `${r.from} → ${r.to} · ${r.sourceIp} → ${r.destIp}`,
              r.service, ports, '', `#${r.order + 1} ${r.name}`,
              risky ? (r.destIp === 'any' ? s.destAny : s.sensitive) : '',
            ]),
          ])}
        >
          CSV
        </button>
      </div>
      <div className="tscroll">
        {exp.nats.length === 0 && exp.rules.length === 0 && (
          <div className="empty">
            <b>{s.emptyTitle}</b>
            {s.empty(exp.wan)}
          </div>
        )}

        {nats.length > 0 && (
          <>
            <h2 className="exposec">{s.natTitle}</h2>
            <table className="rules" aria-label={s.natAria}>
              <thead>
                <tr>
                  <th>{s.host}</th><th>{s.service}</th><th>{s.ports}</th>
                  <th>{s.publishedOn}</th><th>NAT</th><th>{s.allowRule}</th><th></th>
                </tr>
              </thead>
              <tbody>
                {nats.map(x => (
                  <tr key={x.nat.name}>
                    <td className="name">
                      {x.nat.mapTo}
                      <small>{resolveAddr(cfg, x.nat.mapTo!)}</small>
                    </td>
                    <td className="mono">{x.service}</td>
                    <td className="mono">{x.ports}</td>
                    <td className="mono">
                      {x.nat.iface}
                      {x.nat.originalIp ? ` · ${x.nat.originalIp}` : ''}
                    </td>
                    <td className="mono">{x.nat.name}</td>
                    <td className="mono">
                      {x.allowRule
                        ? `#${x.allowRule.order + 1} ${x.allowRule.name}`
                        : <span className="sev info">{s.noneFound}</span>}
                    </td>
                    <td>{x.risky && <span className="sev rotto">{s.sensitive}</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </>
        )}

        {rules.length > 0 && (
          <>
            <h2 className="exposec">{s.rulesTitle(exp.wan)}</h2>
            <table className="rules" aria-label={s.rulesAria}>
              <thead>
                <tr>
                  <th>#</th><th>{s.name}</th><th>From → To</th><th>Source</th>
                  <th>Destination</th><th>{s.ports}</th><th></th>
                </tr>
              </thead>
              <tbody>
                {rules.map(({ rule: r, ports, risky }) => (
                  <tr key={r.name}>
                    <td className="num">{r.order + 1}</td>
                    <td className="name">
                      {r.name}
                      {r.description && <small>{r.description}</small>}
                    </td>
                    <td className="zone"><b>{r.from}</b> → <b>{r.to}</b></td>
                    <td className="mono" title={resolveAddr(cfg, r.sourceIp)}>{r.sourceIp}</td>
                    <td className="mono" title={resolveAddr(cfg, r.destIp)}>{r.destIp}</td>
                    <td className="mono">{ports}</td>
                    <td>{risky && <span className="sev rotto">{r.destIp === 'any' ? s.destAny : s.sensitive}</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </>
        )}

        <p className="exponote">
          {s.note}
        </p>
      </div>
    </div>
  )
}
