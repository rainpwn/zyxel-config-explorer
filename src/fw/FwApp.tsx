import { useMemo, useState } from 'react'
import './fw.css'
import type { FirewallConfig } from '../model'
import { resolveAddr, resolveService, ifaceZoneMap } from '../derive'
import { natService } from '../analysis'
import { FwShield, FwNetwork, FwLock, FwBox, FwBack, FwChevron, FwSearch } from './fwicons'
import FwTable, { ObjLink, StatusDot, type Col } from './FwTable'
import { loc } from '../i18n'

// Labels copied from the device stay in English like on the Zyxel;
// only the app shell is translated here.
const s = loc({
  en: {
    mode: 'Mode',
    analysis: 'Analysis',
    search: 'Search',
    searchMenu: 'Search the menu',
    back: 'Back to Analysis mode',
  },
  it: {
    mode: 'Modalità',
    analysis: 'Analisi',
    search: 'Cerca',
    searchMenu: 'Cerca nel menu',
    back: 'Torna alla modalità Analisi',
  },
})

// Only sections the .conf file actually fills: no fake pages.
const MENU = [
  { id: 'sp', label: 'Security Policy', Icon: FwShield, leaves: [{ id: 'rules', label: 'Policy Control' }] },
  { id: 'net', label: 'Network', Icon: FwNetwork, leaves: [{ id: 'interface', label: 'Interface' }, { id: 'route', label: 'Routing' }, { id: 'nat', label: 'NAT' }] },
  { id: 'vpn', label: 'VPN', Icon: FwLock, leaves: [{ id: 'ipsec', label: 'IPSec VPN' }] },
  { id: 'obj', label: 'Object', Icon: FwBox, leaves: [{ id: 'address', label: 'Address' }, { id: 'service', label: 'Service' }, { id: 'zone', label: 'Zone' }] },
] as const

type PageId = 'rules' | 'interface' | 'nat' | 'route' | 'ipsec' | 'address' | 'service' | 'zone'

const CRUMB: Record<PageId, [string, string]> = {
  rules: ['Security Policy', 'Policy Control'],
  interface: ['Network', 'Interface'],
  nat: ['Network', 'NAT'],
  route: ['Network', 'Routing'],
  ipsec: ['VPN Status', 'IPSec VPN'],
  address: ['Object', 'Address'],
  service: ['Object', 'Service'],
  zone: ['Object', 'Zone'],
}

// "Reference": how many times each object is cited. A real Zyxel column;
// reference 0 means an orphan object.
function useRefCounts(cfg: FirewallConfig) {
  return useMemo(() => {
    const addr = new Map<string, number>()
    const svc = new Map<string, number>()
    const bumpA = (n?: string) => { if (n && n !== 'any') addr.set(n, (addr.get(n) ?? 0) + 1) }
    const bumpS = (n?: string) => { if (n && n !== 'any') svc.set(n, (svc.get(n) ?? 0) + 1) }
    for (const r of cfg.rules) { bumpA(r.sourceIp); bumpA(r.destIp); bumpS(r.service) }
    for (const r of cfg.routes) { bumpA(r.source); bumpA(r.destination); bumpS(r.service) }
    for (const n of cfg.nats) {
      bumpA(n.sourceIp); bumpA(n.originalIp); bumpA(n.mapTo)
      bumpS(natService(n.mapType))
    }
    for (const g of Object.values(cfg.addressGroups)) g.members.forEach(bumpA)
    for (const g of Object.values(cfg.serviceGroups)) g.members.forEach(bumpS)
    return { addr, svc }
  }, [cfg])
}

function Ref({ n }: { n: number }) {
  return <span className={`fw-ref${n === 0 ? ' zero' : ''}`}>{n}</span>
}

export default function FwApp({ cfg, filename, onExit }: {
  cfg: FirewallConfig
  filename: string
  onExit: () => void
}) {
  const [open, setOpen] = useState<Record<string, boolean>>({ sp: true, net: true, vpn: true, obj: true })
  const [page, setPage] = useState<PageId>('rules')
  const [tab, setTab] = useState(0)
  const [menuQ, setMenuQ] = useState('')
  const refs = useRefCounts(cfg)

  // filter menu items: a section with no matching items disappears
  const menu = useMemo(() => {
    const n = menuQ.trim().toLowerCase()
    if (!n) return MENU.map(s => ({ ...s, leaves: [...s.leaves] }))
    return MENU
      .map(s => ({ ...s, leaves: s.leaves.filter(l => l.label.toLowerCase().includes(n) || s.label.toLowerCase().includes(n)) }))
      .filter(s => s.leaves.length > 0)
  }, [menuQ])

  const go = (p: PageId) => { setPage(p); setTab(0) }
  const rAddr = (n: string) => resolveAddr(cfg, n)
  const rSvc = (n: string) => resolveService(cfg, n)

  const [crumbA, crumbB] = CRUMB[page]

  return (
    <div className="fwroot">
      <header className="fw-top">
        <div className="fw-brand">
          <span className="name">Config Explorer</span>
        </div>
        <span className="fw-model">{filename}</span>
        <div className="sp" />
        <div className="fw-mode" role="group" aria-label={s.mode}>
          <button onClick={onExit}>{s.analysis}</button>
          <button className="on" aria-pressed>Firewall</button>
        </div>
      </header>

      <div className="fw-body">
        <nav className="fw-side">
          <div className="fw-search">
            <FwSearch size={16} />
            <input
              type="search" placeholder={s.search} aria-label={s.searchMenu}
              value={menuQ} onChange={e => setMenuQ(e.target.value)}
            />
          </div>
          {menu.map(sec => (
            <div key={sec.id} className={`fw-sec${open[sec.id] || menuQ ? ' open' : ''}`}>
              <button className="fw-sechead" onClick={() => setOpen(o => ({ ...o, [sec.id]: !o[sec.id] }))}>
                <sec.Icon size={19} />
                {sec.label}
                <FwChevron size={16} />
              </button>
              {(open[sec.id] || menuQ) && sec.leaves.map(l => (
                <button
                  key={l.id}
                  className={`fw-leaf${page === l.id ? ' on' : ''}`}
                  onClick={() => go(l.id as PageId)}
                >
                  {l.label}
                </button>
              ))}
            </div>
          ))}
        </nav>

        <main className="fw-main">
          <div className="fw-crumb">
            <button className="back" onClick={onExit} title={s.back}><FwBack size={16} /></button>
            {crumbA}
            <span className="sep">›</span>
            <b>{crumbB}</b>
          </div>

          {page === 'rules' && <RulesPage cfg={cfg} rAddr={rAddr} rSvc={rSvc} go={go} />}
          {page === 'interface' && <InterfacePage cfg={cfg} tab={tab} setTab={setTab} />}
          {page === 'nat' && <NatPage cfg={cfg} rAddr={rAddr} go={go} />}
          {page === 'route' && <RoutePage cfg={cfg} rAddr={rAddr} rSvc={rSvc} go={go} />}
          {page === 'ipsec' && <IpsecPage cfg={cfg} />}
          {page === 'address' && <AddressPage cfg={cfg} refs={refs} tab={tab} setTab={setTab} />}
          {page === 'service' && <ServicePage cfg={cfg} refs={refs} tab={tab} setTab={setTab} />}
          {page === 'zone' && <ZonePage cfg={cfg} />}
        </main>
      </div>
    </div>
  )
}

// Pages

type Nav = (p: PageId) => void

function RulesPage({ cfg, rAddr, rSvc, go }: { cfg: FirewallConfig; rAddr: (n: string) => string; rSvc: (n: string) => string; go: Nav }) {
  const cols: Col<FirewallConfig['rules'][number]>[] = [
    { key: 'st', label: 'St.', get: r => r.enabled ? 1 : 0, render: r => <StatusDot on={r.enabled} />, className: 'muted' },
    { key: 'pri', label: 'Priority', get: r => r.order + 1 },
    { key: 'name', label: 'Name', get: r => r.name },
    { key: 'from', label: 'From', get: r => r.from, render: r => <ObjLink name={r.from} onNav={() => go('zone')} /> },
    { key: 'to', label: 'To', get: r => r.to, render: r => <ObjLink name={r.to} onNav={() => go('zone')} /> },
    { key: 'src', label: 'Source', get: r => r.sourceIp, render: r => <ObjLink name={r.sourceIp} resolve={rAddr} onNav={() => go('address')} /> },
    { key: 'dst', label: 'Destination', get: r => r.destIp, render: r => <ObjLink name={r.destIp} resolve={rAddr} onNav={() => go('address')} /> },
    { key: 'svc', label: 'Service', get: r => r.service, render: r => <ObjLink name={r.service} resolve={rSvc} onNav={() => go('service')} /> },
    { key: 'user', label: 'User', get: r => r.user, render: r => <ObjLink name={r.user} /> },
    { key: 'sched', label: 'Schedule', get: r => r.schedule, render: r => r.schedule === 'any' ? <span className="fw-any">none</span> : r.schedule, className: 'muted' },
    { key: 'act', label: 'Action', get: r => r.action, render: r => <span className={`fw-badge ${r.action}`}>{r.action}</span> },
    { key: 'log', label: 'Log', get: r => r.logging ?? 'no', render: r => <span className="muted">{r.logging === 'no' || !r.logging ? 'no' : r.logging}</span> },
  ]
  return <FwTable cols={cols} rows={cfg.rules} />
}

function InterfacePage({ cfg, tab, setTab }: { cfg: FirewallConfig; tab: number; setTab: (n: number) => void }) {
  const ifZone = useMemo(() => ifaceZoneMap(cfg), [cfg])
  // Reference: how often the interface is cited (its zone, VLANs/LAGs linked
  // on top of it, routes with it as next-hop).
  const ref = useMemo(() => {
    const m = new Map<string, number>()
    const bump = (n?: string) => { if (n) m.set(n, (m.get(n) ?? 0) + 1) }
    for (const z of cfg.zones) z.interfaces.forEach(bump)
    for (const i of cfg.interfaces) bump(i.link)
    for (const r of cfg.routes) if (r.nextHopType === 'interface') bump(r.nextHop)
    return m
  }, [cfg])

  const TYPE: Record<string, string> = { ethernet: 'Ethernet', vlan: 'VLAN', lag: 'LAG', bridge: 'Bridge' }
  const cols: Col<FirewallConfig['interfaces'][number]>[] = [
    { key: 'st', label: 'Status', get: i => i.enabled ? 1 : 0, render: i => <StatusDot on={i.enabled} /> },
    { key: 'name', label: 'Name', get: i => i.name },
    { key: 'zone', label: 'Zone', get: i => ifZone[i.name] ?? '', render: i => ifZone[i.name] ? <span className="fw-obj" style={{ cursor: 'default' }}>{ifZone[i.name]}</span> : <span className="fw-any">none</span> },
    { key: 'desc', label: 'Description', get: i => i.description ?? '', className: 'muted wrap' },
    { key: 'ip', label: 'IP/Netmask', get: i => i.ip ?? '', render: i => i.ip ? i.ip : <span className="fw-any">–</span> },
    { key: 'vlan', label: 'VLAN ID', get: i => i.vlanId ?? '', render: i => i.vlanId ?? <span className="fw-any">–</span>, className: 'muted' },
    { key: 'type', label: 'Type', get: i => TYPE[i.kind] ?? i.kind, className: 'muted' },
    { key: 'members', label: 'Members', get: i => i.link ?? '', render: i => i.link ? <span className="fw-obj" style={{ cursor: 'default' }}>{i.link}</span> : <span className="fw-any">–</span> },
    { key: 'ref', label: 'Reference', get: i => ref.get(i.name) ?? 0, render: i => <Ref n={ref.get(i.name) ?? 0} /> },
  ]
  const ext = cfg.interfaces.filter(i => i.role === 'external')
  const intn = cfg.interfaces.filter(i => i.role !== 'external')

  // Trunk = interface-group; mark the default one
  const trunkCols: Col<FirewallConfig['ifaceGroups'][number]>[] = [
    { key: 'name', label: 'Name', get: g => g.name, render: g => <>{g.name}{g.name === cfg.defaultTrunk && <span className="fw-badge" style={{ marginLeft: 6, color: 'var(--fw-green-dark)' }}>default</span>}</> },
    { key: 'members', label: 'Members', get: g => g.members.map(m => m.name).join(', '), render: g => <span className="fw-grp">{g.members.map(m => <span key={m.name} className="fw-obj" style={{ cursor: 'default' }} title={m.passive ? 'passive' : undefined}>{m.name}</span>)}</span>, className: 'wrap' },
    { key: 'n', label: 'Members #', get: g => g.members.length, className: 'muted' },
  ]

  return (
    <>
      <div className="fw-tabs">
        <button className={tab === 0 ? 'on' : ''} onClick={() => setTab(0)}>Interface</button>
        <button className={tab === 1 ? 'on' : ''} onClick={() => setTab(1)}>Trunk</button>
      </div>
      {tab === 0 ? (
        <>
          <FwTable title="External" cols={cols} rows={ext} />
          <FwTable title="Internal" cols={cols} rows={intn} />
        </>
      ) : (
        <FwTable title="Configuration" cols={trunkCols} rows={cfg.ifaceGroups} />
      )}
    </>
  )
}

function NatPage({ cfg, rAddr, go }: { cfg: FirewallConfig; rAddr: (n: string) => string; go: Nav }) {
  const cols: Col<FirewallConfig['nats'][number]>[] = [
    { key: 'st', label: 'St.', get: n => n.enabled ? 1 : 0, render: n => <StatusDot on={n.enabled} /> },
    { key: 'name', label: 'Name', get: n => n.name },
    { key: 'iface', label: 'Interface', get: n => n.iface ?? '', className: 'muted' },
    { key: 'orig', label: 'Original IP', get: n => n.originalIp ?? '', render: n => n.originalIp ? <ObjLink name={n.originalIp} resolve={rAddr} onNav={() => go('address')} /> : <span className="fw-any">any</span> },
    { key: 'map', label: 'Mapped IP', get: n => n.mapTo ?? '', render: n => n.mapTo ? <ObjLink name={n.mapTo} resolve={rAddr} onNav={() => go('address')} /> : <span className="fw-any">–</span> },
    { key: 'type', label: 'Mapping', get: n => n.mapType ?? '', className: 'muted' },
  ]
  return <FwTable cols={cols} rows={cfg.nats} />
}

function RoutePage({ cfg, rAddr, rSvc, go }: { cfg: FirewallConfig; rAddr: (n: string) => string; rSvc: (n: string) => string; go: Nav }) {
  const cols: Col<FirewallConfig['routes'][number]>[] = [
    { key: 'st', label: 'St.', get: r => r.enabled ? 1 : 0, render: r => <StatusDot on={r.enabled} /> },
    { key: 'pri', label: '#', get: r => r.order + 1 },
    { key: 'name', label: 'Name', get: r => r.name },
    { key: 'from', label: 'Incoming', get: r => r.from, render: r => <ObjLink name={r.from} onNav={() => go('zone')} /> },
    { key: 'src', label: 'Source', get: r => r.source, render: r => <ObjLink name={r.source} resolve={rAddr} onNav={() => go('address')} /> },
    { key: 'dst', label: 'Destination', get: r => r.destination, render: r => <ObjLink name={r.destination} resolve={rAddr} onNav={() => go('address')} /> },
    { key: 'svc', label: 'Service', get: r => r.service, render: r => <ObjLink name={r.service} resolve={rSvc} onNav={() => go('service')} /> },
    { key: 'hop', label: 'Next-Hop', get: r => `${r.nextHopType ?? ''} ${r.nextHop ?? ''}`, render: r => <span className="muted">{r.nextHopType} {r.nextHop}</span> },
  ]
  return <FwTable cols={cols} rows={cfg.routes} />
}

function IpsecPage({ cfg }: { cfg: FirewallConfig }) {
  const rows = useMemo(() => [...cfg.vpns].sort((a, b) => a.name.localeCompare(b.name)), [cfg])
  const cols: Col<FirewallConfig['vpns'][number]>[] = [
    { key: 'st', label: 'St.', get: v => v.enabled ? 1 : 0, render: v => <StatusDot on={v.enabled} /> },
    { key: 'name', label: 'Name', get: v => v.name },
    { key: 'gw', label: 'Remote Gateway', get: v => v.remoteAddress ?? '', className: 'muted' },
    { key: 'local', label: 'Local Networks', get: v => v.localTs.join(', '), render: v => <span className="muted">{v.localTs.join(', ') || '–'}</span>, className: 'wrap' },
    { key: 'remote', label: 'Remote Networks', get: v => v.remoteTs.join(', '), render: v => <span className="muted">{v.remoteTs.join(', ') || '–'}</span>, className: 'wrap' },
  ]
  return (
    <>
      <div className="fw-tabs"><button className="on">Site to Site VPN</button></div>
      <FwTable title="Custom" cols={cols} rows={rows} />
    </>
  )
}

function AddressPage({ cfg, refs, tab, setTab }: { cfg: FirewallConfig; refs: { addr: Map<string, number> }; tab: number; setTab: (n: number) => void }) {
  const addrRows = useMemo(() => Object.values(cfg.addresses).sort((a, b) => a.name.localeCompare(b.name)), [cfg])
  const grpRows = useMemo(() => Object.values(cfg.addressGroups).sort((a, b) => a.name.localeCompare(b.name)), [cfg])
  const TYPE: Record<string, string> = { host: 'HOST', range: 'RANGE', cidr: 'SUBNET', 'interface-subnet': 'INTERFACE SUBNET', fqdn: 'FQDN', geography: 'GEOGRAPHY' }

  const addrCols: Col<(typeof addrRows)[number]>[] = [
    { key: 'name', label: 'Name', get: a => a.name },
    { key: 'type', label: 'Type', get: a => TYPE[a.type] ?? a.type.toUpperCase(), className: 'muted' },
    { key: 'addr', label: 'Address', get: a => a.value },
    { key: 'desc', label: 'Description', get: a => a.description ?? '', className: 'muted wrap' },
    { key: 'ref', label: 'Reference', get: a => refs.addr.get(a.name) ?? 0, render: a => <Ref n={refs.addr.get(a.name) ?? 0} /> },
  ]
  const grpCols: Col<(typeof grpRows)[number]>[] = [
    { key: 'name', label: 'Name', get: g => g.name },
    { key: 'members', label: 'Members', get: g => g.members.join(', '), render: g => <span className="fw-grp">{g.members.map(m => <span key={m} className="fw-obj" style={{ cursor: 'default' }}>{m}</span>)}</span>, className: 'wrap' },
    { key: 'desc', label: 'Description', get: g => g.description ?? '', className: 'muted wrap' },
    { key: 'ref', label: 'Reference', get: g => refs.addr.get(g.name) ?? 0, render: g => <Ref n={refs.addr.get(g.name) ?? 0} /> },
  ]
  return (
    <>
      <div className="fw-tabs">
        <button className={tab === 0 ? 'on' : ''} onClick={() => setTab(0)}>Address</button>
        <button className={tab === 1 ? 'on' : ''} onClick={() => setTab(1)}>Address Group</button>
      </div>
      {tab === 0
        ? <FwTable title="IPv4 Address Configuration" cols={addrCols} rows={addrRows} />
        : <FwTable title="IPv4 Address Group Configuration" cols={grpCols} rows={grpRows} />}
    </>
  )
}

function ServicePage({ cfg, refs, tab, setTab }: { cfg: FirewallConfig; refs: { svc: Map<string, number> }; tab: number; setTab: (n: number) => void }) {
  const svcRows = useMemo(() => Object.values(cfg.services).sort((a, b) => a.name.localeCompare(b.name)), [cfg])
  const grpRows = useMemo(() => Object.values(cfg.serviceGroups).sort((a, b) => a.name.localeCompare(b.name)), [cfg])
  const content = (s: (typeof svcRows)[number]) =>
    s.proto === 'protocol' ? `Protocol=${s.value}` : `${s.proto.toUpperCase()}=${s.value}`

  const svcCols: Col<(typeof svcRows)[number]>[] = [
    { key: 'name', label: 'Name', get: s => s.name },
    { key: 'content', label: 'Content', get: content, className: 'muted' },
    { key: 'ref', label: 'Reference', get: s => refs.svc.get(s.name) ?? 0, render: s => <Ref n={refs.svc.get(s.name) ?? 0} /> },
  ]
  const grpCols: Col<(typeof grpRows)[number]>[] = [
    { key: 'name', label: 'Name', get: g => g.name },
    { key: 'members', label: 'Members', get: g => g.members.join(', '), render: g => <span className="fw-grp">{g.members.map(m => <span key={m} className="fw-obj" style={{ cursor: 'default' }}>{m}</span>)}</span>, className: 'wrap' },
    { key: 'ref', label: 'Reference', get: g => refs.svc.get(g.name) ?? 0, render: g => <Ref n={refs.svc.get(g.name) ?? 0} /> },
  ]
  return (
    <>
      <div className="fw-tabs">
        <button className={tab === 0 ? 'on' : ''} onClick={() => setTab(0)}>Service</button>
        <button className={tab === 1 ? 'on' : ''} onClick={() => setTab(1)}>Service Group</button>
      </div>
      {tab === 0
        ? <FwTable title="Configuration" cols={svcCols} rows={svcRows} />
        : <FwTable title="Service Group Configuration" cols={grpCols} rows={grpRows} />}
    </>
  )
}

function ZonePage({ cfg }: { cfg: FirewallConfig }) {
  const rows = useMemo(() => [...cfg.zones].sort((a, b) => a.name.localeCompare(b.name)), [cfg])
  const cols: Col<(typeof rows)[number]>[] = [
    { key: 'name', label: 'Name', get: z => z.name },
    { key: 'member', label: 'Member', get: z => z.interfaces.join(', '), render: z => <span className="fw-grp">{z.interfaces.map(m => <span key={m} className="fw-obj" style={{ cursor: 'default' }}>{m}</span>)}</span>, className: 'wrap' },
    { key: 'desc', label: 'Description', get: z => z.description ?? '', className: 'muted wrap' },
  ]
  return <FwTable title="Configuration" cols={cols} rows={rows} />
}
