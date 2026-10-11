import type { FirewallConfig, Rule, RouteRule } from '../model'
import {
  resolveAddr, resolveService, rulesForAddress, rulesForZone,
  rulesForIface, routesForZone, routesForIface,
} from '../derive'
import { impactOfDown, type ImpactItem } from '../analysis'
import { IconX, IconBan, IconArrowRight } from '../icons'
import { FindingItem } from './Findings'
import type { Evidence, Finding } from './findingsList'
import { loc } from '../i18n'

const s = loc({
  en: {
    noRules: 'No rules.',
    noRoutes: 'No policy routes.',
    config: 'Configuration',
    findings: 'Findings',
    sevSummary: (d: number, w: number, i: number) => `${d} danger · ${w} warning${w === 1 ? '' : 's'} · ${i} info`,
    clean: 'Nothing to report: no sensitive ports exposed, no conflicting rules.',
    allFindings: (n: number) => `All ${n} findings`,
    moreInFindings: (n: number) => `+${n} more in Findings`,
    pickZone: 'Click a zone on the map to see its flows, its findings and its rules.',
    zone: 'Zone',
    zoneLabel: 'Zone',
    interfaces: 'Interfaces',
    zoneRoutes: 'Exits · policy routes',
    rules: 'Rules',
    egLabel: { 'ipsec-vpn': 'VPN', trunk: 'trunk', interface: 'interface' } as Record<string, string>,
    zoneOf: (z: string) => `zone ${z}`,
    disabledIface: 'disabled',
    ifaceKind: (k: string) => `Interface ${k}`,
    exitsVia: 'Leaves through',
    dflt: 'default',
    nRoutes: (n: number) => `${n} routes`,
    systemRouting: 'System routing · no dedicated policy route.',
    outPolicy: 'Outbound policy routes',
    subnetRules: 'Subnet rules',
    cidrMatch: (ip: string, z: string) => `CIDR match on ${ip}: objects inside it, plus 'any' in zone ${z}`,
    noIp: (z: string) => `interface without an IP: rules of zone ${z}`,
    ifaceDown: 'Simulate this interface going down',
    details: 'Details',
    note: 'Note',
    groups: 'Groups',
    rulesCiting: 'Rules that reference it',
    pairKind: 'Traffic between zones',
    pairRules: 'Rules in evaluation order',
    natKind: 'NAT · virtual server',
    iface: 'Interface',
    originalIp: 'Original IP',
    mappedTo: 'Mapped to',
    source: 'Source',
    service: 'Service',
    status: 'Status',
    active: 'active',
    disabled: 'disabled',
    vpnTitle: 'Remote sites',
    vpnSub: (on: number, all: number) => `${on} active / ${all} total`,
    siteKind: 'VPN site · IPsec',
    tunnelOff: 'tunnel disabled',
    remoteGw: 'Remote gateway',
    localSubnets: 'Local subnets',
    remoteSubnets: 'Remote subnets',
    tunnelRoutes: 'Policy routes on the tunnel',
    tunnelDown: 'Simulate this tunnel going down',
    downKind: 'Failure simulation',
    down: (name: string) => `${name} down`,
    downSub: (broken: number, warn: number) => `${broken} broken · ${warn} warning${warn === 1 ? '' : 's'}`,
    impact: 'Impact',
    sev: { rotto: 'broken', degradato: 'degraded', info: 'info' } as Record<ImpactItem['severity'], string>,
    close: 'Close',
    closeAria: 'Close detail panel',
  },
  it: {
    noRules: 'Nessuna regola.',
    noRoutes: 'Nessuna policy-route.',
    config: 'Configurazione',
    findings: 'Riscontri',
    sevSummary: (d: number, w: number, i: number) => `${d} pericol${d === 1 ? 'o' : 'i'} · ${w} avvis${w === 1 ? 'o' : 'i'} · ${i} info`,
    clean: 'Nessun riscontro: niente porte sensibili esposte, niente regole in conflitto.',
    allFindings: (n: number) => `Tutti i ${n} riscontri`,
    moreInFindings: (n: number) => `+${n} in Riscontri`,
    pickZone: 'Clicca una zona sulla mappa per vederne i flussi, i riscontri e le regole.',
    zone: 'Zona',
    zoneLabel: 'Zona',
    interfaces: 'Interfacce',
    zoneRoutes: 'Uscite · policy route',
    rules: 'Regole',
    egLabel: { 'ipsec-vpn': 'VPN', trunk: 'trunk', interface: 'interfaccia' },
    zoneOf: (z: string) => `zona ${z}`,
    disabledIface: 'disabilitata',
    ifaceKind: (k: string) => `Interfaccia ${k}`,
    exitsVia: 'Esce da',
    dflt: 'predefinito',
    nRoutes: (n: number) => `${n} route`,
    systemRouting: 'Instradamento di sistema · nessuna policy route dedicata.',
    outPolicy: 'Policy in uscita',
    subnetRules: 'Regole della subnet',
    cidrMatch: (ip: string, z: string) => `match CIDR su ${ip}: oggetti che vi ricadono, più 'any' della zona ${z}`,
    noIp: (z: string) => `interfaccia senza IP: regole della zona ${z}`,
    ifaceDown: 'Simula questa interfaccia giù',
    details: 'Dettagli',
    note: 'Note',
    groups: 'Gruppi',
    rulesCiting: 'Regole che lo citano',
    pairKind: 'Traffico tra zone',
    pairRules: 'Regole in ordine di valutazione',
    natKind: 'NAT · virtual server',
    iface: 'Interfaccia',
    originalIp: 'IP originale',
    mappedTo: 'Mappato su',
    source: 'Sorgente',
    service: 'Servizio',
    status: 'Stato',
    active: 'attivo',
    disabled: 'disabilitato',
    vpnTitle: 'Sedi remote',
    vpnSub: (on: number, all: number) => `${on} attive / ${all} totali`,
    siteKind: 'Sede VPN · IPsec',
    tunnelOff: 'tunnel disabilitato',
    remoteGw: 'Gateway remoto',
    localSubnets: 'Subnet locali',
    remoteSubnets: 'Subnet remote',
    tunnelRoutes: 'Policy route sul tunnel',
    tunnelDown: 'Simula questo tunnel giù',
    downKind: 'Simulazione guasto',
    down: (name: string) => `${name} giù`,
    downSub: (broken: number, warn: number) => `${broken} element${broken === 1 ? 'o rotto' : 'i rotti'} · ${warn} avvis${warn === 1 ? 'o' : 'i'}`,
    impact: 'Impatto',
    sev: { rotto: 'rotto', degradato: 'degradato', info: 'info' },
    close: 'Chiudi',
    closeAria: 'Chiudi pannello dettaglio',
  },
})

export type Sel =
  | { kind: 'zone'; name: string }
  | { kind: 'iface'; name: string }
  | { kind: 'addr'; name: string }
  | { kind: 'pair'; from: string; to: string }
  | { kind: 'nat'; name: string }
  | { kind: 'vpn' }
  | { kind: 'vpnsite'; name: string }
  | { kind: 'down'; target: { kind: 'iface' | 'vpn'; name: string } }

// Compact rule row: name, action tag (only deny takes colour), mono meta line
function RuleRow({ cfg, r }: { cfg: FirewallConfig; r: Rule }) {
  return (
    <div className={`rule${r.enabled ? '' : ' off'}`}>
      <span className="nm">{r.name}</span>
      <span className={`tag${r.action === 'deny' ? ' deny' : ''}`}>{r.action}{r.enabled ? '' : ' · off'}</span>
      <span
        className="meta"
        title={`${resolveAddr(cfg, r.sourceIp)} → ${resolveAddr(cfg, r.destIp)} · ${resolveService(cfg, r.service)}`}
      >
        {r.from} → {r.to} · {r.sourceIp} → {r.destIp} · {r.service}{r.user !== 'any' ? ` · user ${r.user}` : ''}
      </span>
    </div>
  )
}

function RuleList({ cfg, rules }: { cfg: FirewallConfig; rules: Rule[] }) {
  if (rules.length === 0) return <p className="none">{s.noRules}</p>
  return <>{rules.map(r => <RuleRow key={r.name} cfg={cfg} r={r} />)}</>
}

function RouteList({ cfg, routes }: { cfg: FirewallConfig; routes: RouteRule[] }) {
  if (routes.length === 0) return <p className="none">{s.noRoutes}</p>
  return (
    <>
      {routes.map(r => (
        <div key={r.name} className={`rule${r.enabled ? '' : ' off'}`}>
          <span className="nm">{r.name}</span>
          <span className="tag">{r.nextHopType} {r.nextHop}</span>
          <span className="meta" title={`${resolveAddr(cfg, r.source)} → ${resolveAddr(cfg, r.destination)}`}>
            {r.from !== 'any' ? `from ${r.from} · ` : ''}{r.source} → {r.destination}
            {r.service !== 'any' ? ` · ${r.service}` : ''}
          </span>
        </div>
      ))}
    </>
  )
}

function Section({ title, n, children }: { title: string; n?: number; children: React.ReactNode }) {
  return (
    <section className="sec">
      <h3>{title}{n !== undefined && <span className="n">{n}</span>}</h3>
      {children}
    </section>
  )
}

function FindingList({ list, onGo }: { list: Finding[]; onGo: (ev: Evidence) => void }) {
  return <div className="fcards">{list.map(f => <FindingItem key={f.id} f={f} onGo={onGo} />)}</div>
}

// Findings shown in the panel when nothing is selected, and per zone
const SUMMARY = 6
const ZONE_FINDINGS = 3

export default function DetailPanel({ cfg, sel, placed, findings, onClose, onSelect, onGo }: {
  cfg: FirewallConfig
  sel: Sel | null
  placed: Record<string, string>
  findings: Finding[]
  onClose: () => void
  onSelect: (s: Sel) => void
  onGo: (ev: Evidence) => void
}) {
  if (!sel) {
    const n = (k: Finding['sev']) => findings.filter(f => f.sev === k).length
    return (
      <aside className="panel">
        <div className="ph">
          <h2>{s.findings}</h2>
          <p>{s.config} · {s.sevSummary(n('danger'), n('warn'), n('info'))}</p>
        </div>
        <div className="sec">
          {findings.length === 0
            ? <p className="none">{s.clean}</p>
            : <FindingList list={findings.slice(0, SUMMARY)} onGo={onGo} />}
          {findings.length > SUMMARY && (
            <button className="morelink" onClick={() => onGo({ view: 'findings' })}>
              {s.allFindings(findings.length)} <IconArrowRight size={12} />
            </button>
          )}
        </div>
        <p className="panelhint">{s.pickZone}</p>
      </aside>
    )
  }

  let head: { kind: string; title: string; sub?: React.ReactNode }
  let body: React.ReactNode

  switch (sel.kind) {
    case 'zone': {
      const z = cfg.zones.find(x => x.name === sel.name)
      const rules = rulesForZone(cfg, sel.name)
      const routes = routesForZone(cfg, sel.name)
      const zf = findings.filter(f => f.zone === sel.name)
      const ifs = (z?.interfaces ?? []).map(n => cfg.interfaces.find(x => x.name === n)).filter(x => !!x)
      // subtitle: description, then the first interfaces as data
      const ifLine = ifs.slice(0, 2).map(i => `${i.name}${i.ip ? ` ${i.ip}` : ''}`).join(', ')
        + (ifs.length > 2 ? ` +${ifs.length - 2}` : '')
      head = {
        kind: s.zone, title: sel.name,
        sub: z?.description || ifLine
          ? <>{z?.description}{z?.description && ifLine ? ' · ' : ''}{ifLine && <span className="mono">{ifLine}</span>}</>
          : undefined,
      }
      body = (
        <>
          {zf.length > 0 && (
            <Section title={s.findings} n={zf.length}>
              <FindingList list={zf.slice(0, ZONE_FINDINGS)} onGo={onGo} />
              {zf.length > ZONE_FINDINGS && (
                <button className="morelink" onClick={() => onGo({ view: 'findings', zone: sel.name })}>
                  {s.moreInFindings(zf.length - ZONE_FINDINGS)} <IconArrowRight size={12} />
                </button>
              )}
            </Section>
          )}
          <Section title={s.rules} n={rules.length}>
            <RuleList cfg={cfg} rules={rules} />
          </Section>
          {ifs.length > 0 && (
            <Section title={s.interfaces} n={ifs.length}>
              <dl className="kv">
                {ifs.map(i => [
                  <dt key={`${i.name}t`}>
                    <button className="linkbtn" onClick={() => onSelect({ kind: 'iface', name: i.name })}>{i.name}</button>
                  </dt>,
                  <dd key={`${i.name}d`}>{i.ip ?? i.description ?? '–'}</dd>,
                ])}
              </dl>
            </Section>
          )}
          <Section title={s.zoneRoutes} n={routes.length}>
            <RouteList cfg={cfg} routes={routes} />
          </Section>
        </>
      )
      break
    }
    case 'iface': {
      const i = cfg.interfaces.find(x => x.name === sel.name)
      const zone = cfg.zones.find(z => z.interfaces.includes(sel.name))?.name
      const rules = rulesForIface(cfg, sel.name)
      const routes = routesForIface(cfg, sel.name)

      // Egress: which next-hops traffic from here leaves through, per active
      // policy route.
      const egress = new Map<string, { type: string; name: string; n: number }>()
      for (const r of routes) {
        if (!r.enabled || !r.nextHopType) continue
        const nm = r.nextHop ?? '–'
        const key = `${r.nextHopType} ${nm}`
        const e = egress.get(key) ?? { type: r.nextHopType, name: nm, n: 0 }
        e.n++
        egress.set(key, e)
      }
      const egressList: { type: string; name: string; n: number; dflt?: boolean }[] = [...egress.values()]
      // Without dedicated policy routes, egress follows the default trunk.
      if (egressList.length === 0 && cfg.defaultTrunk) {
        egressList.push({ type: 'trunk', name: cfg.defaultTrunk, n: 0, dflt: true })
      }
      // WAN (trunk/interface) first, VPN after. Stable sort keeps route order
      // within each group.
      egressList.sort((a, b) => (a.type === 'ipsec-vpn' ? 1 : 0) - (b.type === 'ipsec-vpn' ? 1 : 0))
      const egLabel = s.egLabel
      // WAN interfaces in a trunk (interface-group). If no member is marked
      // external, show all members anyway.
      const trunkMembers = (name: string) => {
        const g = cfg.ifaceGroups.find(x => x.name === name)
        if (!g) return []
        const ifs = g.members
          .map(m => cfg.interfaces.find(x => x.name === m.name))
          .filter((x): x is (typeof cfg.interfaces)[number] => !!x)
        const wan = ifs.filter(x => x.role === 'external' || /wan/i.test(x.name))
        return wan.length ? wan : ifs
      }

      const idSub = [
        i?.ip,
        i?.vlanId ? `VLAN ${i.vlanId}` : null,
        zone ? s.zoneOf(zone) : null,
        i && !i.enabled ? s.disabledIface : null,
      ].filter(Boolean).join(' · ')

      head = { kind: s.ifaceKind(i?.kind ?? ''), title: sel.name, sub: idSub || i?.description }
      body = (
        <>
          <div className="sec">
            <button
              className="btn simdown"
              onClick={() => onSelect({ kind: 'down', target: { kind: 'iface', name: sel.name } })}
            >
              <IconBan size={14} /> {s.ifaceDown}
            </button>
          </div>
          <Section title={s.exitsVia} n={egressList.length}>
          {egressList.length > 0 ? (
            <div className="egress">
              {egressList.map(e => {
                const vpn = e.type === 'ipsec-vpn' ? cfg.vpns.find(v => v.policies.includes(e.name)) : null
                const iface = e.type === 'interface' ? cfg.interfaces.find(x => x.name === e.name) : null
                const members = e.type === 'trunk' ? trunkMembers(e.name) : []
                return (
                  <div className="ehop" key={`${e.type}${e.name}`}>
                    <div className="ehop-top">
                      <span className="etype">{egLabel[e.type] ?? e.type}</span>
                      {vpn
                        ? <button className={`ename linkbtn${vpn.enabled ? '' : ' off'}`} onClick={() => onSelect({ kind: 'vpnsite', name: vpn.name })}>{e.name}</button>
                        : iface
                          ? <button className="ename linkbtn" onClick={() => onSelect({ kind: 'iface', name: iface.name })}>{e.name}</button>
                          : <span className="ename">{e.name}</span>}
                      {e.dflt ? <span className="en">{s.dflt}</span> : e.n > 1 ? <span className="en">{s.nRoutes(e.n)}</span> : null}
                    </div>
                    {members.length > 0 && (
                      <div className="emembers">
                        {members.map(m => (
                          <button key={m.name} className={`emem linkbtn${m.enabled ? '' : ' off'}`} onClick={() => onSelect({ kind: 'iface', name: m.name })}>
                            {m.name}{m.ip ? <span className="emip">{m.ip}</span> : ''}
                          </button>
                        ))}
                      </div>
                    )}
                  </div>
                )
              })}
            </div>
          ) : (
            <p className="none">{s.systemRouting}</p>
          )}
          </Section>

          <Section title={s.outPolicy} n={routes.length}>
            <RouteList cfg={cfg} routes={routes} />
          </Section>

          <Section title={s.subnetRules} n={rules.length}>
            <p className="none">
              {i?.ip
                ? s.cidrMatch(i.ip, zone ?? '')
                : s.noIp(zone ?? '')}
            </p>
            <RuleList cfg={cfg} rules={rules} />
          </Section>
        </>
      )
      break
    }
    case 'addr': {
      const a = cfg.addresses[sel.name]
      const rules = rulesForAddress(cfg, sel.name)
      const groups = Object.values(cfg.addressGroups).filter(g => g.members.includes(sel.name))
      head = { kind: `address · ${a?.type ?? '?'}`, title: sel.name, sub: a?.value }
      body = (
        <>
          <Section title={s.details}>
            <dl className="kv">
              {a?.description && [<dt key="dt">{s.note}</dt>, <dd key="dd">{a.description}</dd>]}
              {placed[sel.name] && [<dt key="zt">{s.zoneLabel}</dt>, <dd key="zd">{placed[sel.name]}</dd>]}
              {groups.length > 0 && [<dt key="gt">{s.groups}</dt>, <dd key="gd">{groups.map(g => g.name).join(', ')}</dd>]}
            </dl>
          </Section>
          <Section title={s.rulesCiting} n={rules.length}>
            <RuleList cfg={cfg} rules={rules} />
          </Section>
        </>
      )
      break
    }
    case 'pair': {
      const rules = cfg.rules.filter(r => r.from === sel.from && r.to === sel.to)
      const allow = rules.filter(r => r.action === 'allow').length
      head = {
        kind: s.pairKind,
        title: `${sel.from} → ${sel.to}`,
        sub: `${allow} allow · ${rules.length - allow} deny`,
      }
      body = (
        <Section title={s.pairRules} n={rules.length}>
          <RuleList cfg={cfg} rules={rules} />
        </Section>
      )
      break
    }
    case 'nat': {
      const n = cfg.nats.find(x => x.name === sel.name)
      head = { kind: s.natKind, title: sel.name }
      body = (
        <>
          <Section title={s.details}>
            <dl className="kv">
              {n?.iface && [<dt key="it">{s.iface}</dt>, <dd key="id">{n.iface}</dd>]}
              {n?.originalIp && [<dt key="ot">{s.originalIp}</dt>, <dd key="od">{n.originalIp} · {resolveAddr(cfg, n.originalIp)}</dd>]}
              {n?.mapTo && [<dt key="mt">{s.mappedTo}</dt>, <dd key="md">{n.mapTo} · {resolveAddr(cfg, n.mapTo)}</dd>]}
              {n?.sourceIp && [<dt key="st">{s.source}</dt>, <dd key="sd">{n.sourceIp} · {resolveAddr(cfg, n.sourceIp)}</dd>]}
              {n?.mapType && [<dt key="tt">{s.service}</dt>, <dd key="td">{n.mapType}</dd>]}
              {n && [<dt key="et">{s.status}</dt>, <dd key="ed">{n.enabled ? s.active : s.disabled}</dd>]}
            </dl>
          </Section>
        </>
      )
      break
    }
    case 'vpn': {
      const on = cfg.vpns.filter(v => v.enabled)
      head = { kind: 'VPN IPsec', title: s.vpnTitle, sub: s.vpnSub(on.length, cfg.vpns.length) }
      body = (
        <>
          <Section title="Tunnel" n={cfg.vpns.length}>
            {[...cfg.vpns].sort((a, b) => a.name.localeCompare(b.name)).map(v => (
              <div className="vpnrow" key={v.name}>
                <button
                  className={`linkbtn${v.enabled ? '' : ' off'}`}
                  onClick={() => onSelect({ kind: 'vpnsite', name: v.name })}
                >
                  {v.name}
                </button>
                <span title={v.remoteAddress}>{v.remoteTs.join(', ') || v.remoteAddress || '–'}</span>
              </div>
            ))}
          </Section>
        </>
      )
      break
    }
    case 'vpnsite': {
      const v = cfg.vpns.find(x => x.name === sel.name)
      const routes = cfg.routes.filter(r =>
        r.nextHopType === 'ipsec-vpn' && !!r.nextHop && !!v?.policies.includes(r.nextHop),
      )
      head = {
        kind: s.siteKind,
        title: sel.name,
        sub: v?.enabled === false ? s.tunnelOff : v?.remoteAddress,
      }
      body = (
        <>
          <Section title={s.details}>
            <dl className="kv">
              {v?.remoteAddress && [<dt key="rt">{s.remoteGw}</dt>, <dd key="rd">{v.remoteAddress}</dd>]}
              {v && [<dt key="et">{s.status}</dt>, <dd key="ed">{v.enabled ? s.active : s.disabled}</dd>]}
              {v && v.localTs.length > 0 && [<dt key="lt">{s.localSubnets}</dt>, <dd key="ld">{v.localTs.join(', ')}</dd>]}
              {v && v.remoteTs.length > 0 && [<dt key="st">{s.remoteSubnets}</dt>, <dd key="sd">{v.remoteTs.join(', ')}</dd>]}
            </dl>
          </Section>
          <Section title={s.tunnelRoutes} n={routes.length}>
            <RouteList cfg={cfg} routes={routes} />
          </Section>
          <div className="sec">
            <button
              className="btn simdown"
              onClick={() => onSelect({ kind: 'down', target: { kind: 'vpn', name: sel.name } })}
            >
              <IconBan size={14} /> {s.tunnelDown}
            </button>
          </div>
        </>
      )
      break
    }
    case 'down': {
      const imp = impactOfDown(cfg, sel.target.kind, sel.target.name)
      const rotti = imp.items.filter(i => i.severity === 'rotto').length
      head = {
        kind: s.downKind,
        title: s.down(`${sel.target.kind === 'vpn' ? 'VPN ' : ''}${sel.target.name}`),
        sub: s.downSub(rotti, imp.items.length - rotti),
      }
      body = (
        <>
          <Section title={s.impact} n={imp.items.length}>
            {imp.items.map((it, k) => (
              <div key={k} className="rule">
                <span className="nm">{it.label}</span>
                <span className={`sev ${it.severity}`}>{s.sev[it.severity]}</span>
                <span className="meta">{it.detail}</span>
              </div>
            ))}
          </Section>
        </>
      )
      break
    }
  }

  return (
    <aside className="panel">
      <div className="ph">
        <h2>{head.title}</h2>
        {/* the kind leads the subtitle: no label above the title */}
        <p>{head.kind}{head.sub ? <> · {head.sub}</> : null}</p>
        <button className="btn icon ghost close" onClick={onClose} title={s.close} aria-label={s.closeAria}>
          <IconX size={14} />
        </button>
      </div>
      {body}
    </aside>
  )
}
