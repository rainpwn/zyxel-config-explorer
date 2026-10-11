import { useState } from 'react'
import type { FirewallConfig } from '../model'
import { ifaceZoneMap, ipToInt, resolveAddr, resolveService } from '../derive'
import { simulate, type Proto, type SimResult, type SimError } from '../analysis'
import { IconBan, IconCheck } from '../icons'
import { loc } from '../i18n'

const s = loc({
  en: {
    badPort: 'Invalid port (1–65535).',
    lead: 'First-match verdict on the active rules, as the firewall evaluates them. User and schedule count as any, and NAT is not applied.',
    srcIface: 'Source · interface',
    freeIp: 'Any IP',
    srcIp: 'Source IP',
    dstIp: 'Destination IP',
    proto: 'Protocol',
    port: 'Port',
    eg: (x: string) => `e.g. ${x}`,
    needIps: 'Enter a valid source IP and destination IP',
    simulate: 'Simulate',
    allowed: 'Allowed',
    blocked: 'Blocked',
    traceTitle: 'Highlight the path on the map',
    trace: 'Show on map',
    howZones: 'How the zones were found',
    source: 'Source',
    destination: 'Destination',
    decisive: 'Deciding rule (first match)',
    noRule: ['No rule matches → implicit ', 'default deny', ' between zones.'],
    exit: 'Exit · policy route',
    noRoute: 'No policy route matches → leaves through the default trunk',
    assumptions: 'Assumptions',
    hint: 'Pick a source interface (or keep "Any IP" and type an IP), a destination and a service. You get the verdict, the rule that decides it and where the traffic leaves.',
  },
  it: {
    badPort: 'Porta non valida (1–65535).',
    lead: 'Verdetto first-match sulle regole attive, come il firewall: user e schedule contano come any, il NAT non viene applicato.',
    srcIface: 'Sorgente · interfaccia',
    freeIp: 'IP libero',
    srcIp: 'IP sorgente',
    dstIp: 'IP destinazione',
    proto: 'Protocollo',
    port: 'Porta',
    eg: (x: string) => `es. ${x}`,
    needIps: 'Servono un IP sorgente e un IP destinazione validi',
    simulate: 'Simula',
    allowed: 'Permesso',
    blocked: 'Bloccato',
    traceTitle: 'Accende il percorso sulla mappa',
    trace: 'Mostra sulla mappa',
    howZones: 'Come sono state determinate le zone',
    source: 'Sorgente',
    destination: 'Destinazione',
    decisive: 'Regola decisiva (first-match)',
    noRule: ['Nessuna regola corrisponde → ', 'default deny', ' implicito tra zone.'],
    exit: 'Uscita · policy route',
    noRoute: 'Nessuna policy-route corrisponde → esce dal trunk di default',
    assumptions: 'Assunzioni',
    hint: 'Scegli un\'interfaccia sorgente (o lascia "IP libero" e digita un IP), una destinazione e un servizio: vedrai il verdetto, la regola che decide e da dove esce il traffico.',
  },
})

export default function Simulator({ cfg, onTrace }: {
  cfg: FirewallConfig
  onTrace?: (r: SimResult) => void
}) {
  const ifZone = ifaceZoneMap(cfg)
  const ifaces = cfg.interfaces.filter(i => i.ip && ifZone[i.name])

  const [srcIface, setSrcIface] = useState('')
  const [srcIp, setSrcIp] = useState('')
  const [dstIp, setDstIp] = useState('')
  const [proto, setProto] = useState<Proto>('icmp')
  const [port, setPort] = useState('')
  const [res, setRes] = useState<SimResult | SimError | null>(null)

  function firstHostIp(cidr: string): string {
    // .1 is almost always the firewall: suggest .10 as the test host
    const base = cidr.split('/')[0].split('.')
    return `${base[0]}.${base[1]}.${base[2]}.10`
  }

  // button stays disabled until source and destination are valid IPs;
  // with an interface chosen, an empty source means the suggested host (.10)
  const srcOk = srcIp.trim() === '' ? srcIface !== '' : ipToInt(srcIp.trim()) !== null
  const dstOk = ipToInt(dstIp.trim()) !== null

  function run() {
    const iface = ifaces.find(i => i.name === srcIface)
    const ip = iface ? (srcIp.trim() || firstHostIp(iface.ip!)) : srcIp.trim()
    const zone = iface ? ifZone[iface.name] : undefined
    const p = proto === 'icmp' ? 0 : Number(port)
    if (proto !== 'icmp' && (!Number.isInteger(p) || p < 1 || p > 65535)) {
      setRes({ ok: false, error: s.badPort })
      return
    }
    setRes(simulate(cfg, ip, dstIp.trim(), proto, p, zone))
  }

  return (
    <div className="simwrap">
      <div className="simbox">
        <p className="simlead">{s.lead}</p>
        <form className="simform" onSubmit={e => { e.preventDefault(); if (srcOk && dstOk) run() }}>
          <div className="field">
            <label htmlFor="sim-iface">{s.srcIface}</label>
            <select
              id="sim-iface" value={srcIface} className={srcIface ? 'data' : 'data free'}
              onChange={e => { setSrcIface(e.target.value); setRes(null) }}
            >
              <option value="" className="free">{s.freeIp}</option>
              {ifaces.map(i => (
                <option key={i.name} value={i.name}>{i.name} · {i.ip} ({ifZone[i.name]})</option>
              ))}
            </select>
          </div>
          <div className="field">
            <label htmlFor="sim-src">{s.srcIp}</label>
            <input
              id="sim-src" type="text" value={srcIp}
              placeholder={srcIface ? firstHostIp(ifaces.find(i => i.name === srcIface)!.ip!) : s.eg('192.168.11.50')}
              onChange={e => setSrcIp(e.target.value)}
            />
          </div>
          <div className="field">
            <label htmlFor="sim-dst">{s.dstIp}</label>
            <input
              id="sim-dst" type="text" value={dstIp} placeholder={s.eg('8.8.8.8')}
              onChange={e => setDstIp(e.target.value)}
            />
          </div>
          <div className="field">
            <label htmlFor="sim-proto">{s.proto}</label>
            <select id="sim-proto" value={proto} onChange={e => setProto(e.target.value as Proto)}>
              <option value="icmp">ICMP (ping)</option>
              <option value="tcp">TCP</option>
              <option value="udp">UDP</option>
            </select>
          </div>
          {proto !== 'icmp' && (
            <div className="field">
              <label htmlFor="sim-port">{s.port}</label>
              <input
                id="sim-port" type="text" value={port} placeholder={s.eg('3389')}
                style={{ width: 90 }} onChange={e => setPort(e.target.value)}
              />
            </div>
          )}
          <button
            type="submit" className="btn primary" disabled={!srcOk || !dstOk}
            title={srcOk && dstOk ? undefined : s.needIps}
          >
            {s.simulate}
          </button>
        </form>

        {res && !res.ok && <p className="simerr">{res.error}</p>}

        {res && res.ok && (
          <div className={`verdict ${res.verdict}`}>
            <div className="vhead">
              <b>
                {res.verdict === 'allow' ? <IconCheck size={16} /> : <IconBan size={16} />}
                {res.verdict === 'allow' ? s.allowed : s.blocked}
              </b>
              <span className="path">
                {res.srcIp} ({res.srcZone}) → {res.dstIp} ({res.dstZone})
                {' · '}{proto === 'icmp' ? 'ping' : `${proto}/${port}`}
              </span>
              {onTrace && (
                <button
                  className="btn" style={{ marginLeft: 'auto' }}
                  title={s.traceTitle}
                  onClick={() => onTrace(res)}
                >
                  {s.trace}
                </button>
              )}
            </div>
            <div className="vbody">
              <h3>{s.howZones}</h3>
              <dl className="kv">
                <dt>{s.source}</dt><dd>{res.srcZone} · {res.srcHow}</dd>
                <dt>{s.destination}</dt><dd>{res.dstZone} · {res.dstHow}</dd>
              </dl>

              <h3>{s.decisive}</h3>
              {res.rule ? (
                <div className={`rulecard ${res.rule.action}`}>
                  <div className="rname">
                    <span>#{res.rule.order + 1} · {res.rule.name}</span>
                    <span className={`act ${res.rule.action}`}>{res.rule.action}</span>
                  </div>
                  <div className="rmeta">{res.rule.from} → {res.rule.to}</div>
                  <div className="rmeta" title={`${resolveAddr(cfg, res.rule.sourceIp)} → ${resolveAddr(cfg, res.rule.destIp)}`}>
                    {res.rule.sourceIp} → {res.rule.destIp}
                  </div>
                  <div className="rmeta" title={resolveService(cfg, res.rule.service)}>service: {res.rule.service}</div>
                </div>
              ) : (
                <p className="simnote">{s.noRule[0]}<b>{s.noRule[1]}</b>{s.noRule[2]}</p>
              )}

              <h3>{s.exit}</h3>
              {res.route ? (
                <div className="routerow">
                  <div className="rname">
                    <span>#{res.route.order + 1} · {res.route.name}</span>
                    <span className="hop">{res.route.nextHopType} {res.route.nextHop}</span>
                  </div>
                  <div className="rmeta">{res.route.source} → {res.route.destination}</div>
                </div>
              ) : (
                <p className="simnote">
                  {s.noRoute}
                  {cfg.defaultTrunk ? <> (<b>{cfg.defaultTrunk}</b>)</> : null}.
                </p>
              )}

              <h3>{s.assumptions}</h3>
              {res.notes.map((n, k) => <p key={k} className="simnote">{n}</p>)}
            </div>
          </div>
        )}

        {!res && (
          <p className="hint">{s.hint}</p>
        )}
      </div>
    </div>
  )
}
