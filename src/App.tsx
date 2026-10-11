import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import type { FirewallConfig } from './model'
import { parseConfig } from './parser'
import { loadConfig, saveConfig, clearConfig, loadTheme, applyTheme, loadAppMode, saveAppMode } from './storage'
import FwApp from './fw/FwApp'
import { buildReport } from './report'
import type { SimResult } from './analysis'
import MapDiagram from './views/MapDiagram'
import RulesTable from './views/RulesTable'
import RoutesTable from './views/RoutesTable'
import Matrix from './views/Matrix'
import Objects from './views/Objects'
import Simulator from './views/Simulator'
import Exposure from './views/Exposure'
import DiffView from './views/DiffView'
import Findings from './views/Findings'
import { findings as computeFindings, type Evidence } from './views/findingsList'
import Palette, { type PaletteAction } from './views/Palette'
import type { Sel } from './views/DetailPanel'
import { zonePairs } from './derive'
import {
  IconAlert, IconDiff, IconGlobe, IconGrid, IconLayers, IconList, IconLock, IconMap, IconMoon,
  IconPlay, IconRoute, IconSearch, IconSun, IconTopology, IconUpload, IconWarn,
} from './icons'
import { lang, loc, setLang } from './i18n'

type Theme = 'light' | 'dark'
type Tab = 'map' | 'matrix' | 'routes' | 'rules' | 'expo' | 'objects' | 'findings' | 'sim' | 'diff'

// README section with checks anyone can run (offline test, Network tab, CSP)
const RELEASES_URL = 'https://github.com/rainpwn/zyxel-config-explorer/releases'
const TRUST_URL = 'https://github.com/rainpwn/zyxel-config-explorer#can-i-trust-it-with-my-config'

const s = loc({
  en: {
    tabs: {
      map: 'Map', matrix: 'Matrix', routes: 'Routes', rules: 'Rules', expo: 'NAT & exposure',
      objects: 'Objects', findings: 'Findings', sim: 'Simulate', diff: 'Diff',
    } as Record<Tab, string>,
    groups: ['Network', 'Policy', 'Checks'],
    views: 'Views',
    appMode: 'App mode',
    analysis: 'Analysis',
    firewall: 'Firewall',
    firewallView: ' view',
    firewallTitle: 'See the config laid out like the firewall web interface',
    searchAria: 'Search by name or IP (Ctrl+K)',
    search: 'Search name or IP',
    device: 'Zyxel uOS · ZLD',
    fileAria: (f: string) => `File ${f}: replace, report, close`,
    replace: 'Replace config…',
    report: 'Printable report',
    close: 'Close and remove from browser',
    themeTitle: 'Light/dark theme',
    toLight: 'Switch to light theme',
    toDark: 'Switch to dark theme',
    otherLang: 'IT',
    otherLangAria: "Passa all'italiano",
    navFoot: 'Runs in your browser. The file is never uploaded.',
    inv: {
      zones: (n: number) => `zone${n === 1 ? '' : 's'}`,
      ifaces: (n: number) => `interface${n === 1 ? '' : 's'}`,
      rules: (n: number) => `rule${n === 1 ? '' : 's'}`,
    },
    invAria: 'Inventory',
    sevCount: (d: number, w: number, i: number) => [`${d}`, ' danger', `${w}`, w === 1 ? ' warning' : ' warnings', `${i}`, ' info'],
    lede: 'Reads the configuration of a Zyxel firewall (uOS or ZLD) and draws the network: zones, traffic between them, exposed services and rules that never match.',
    dropAria: 'Load the firewall configuration file',
    dropTitle: 'Drop a .conf file here',
    dropText: 'or click to choose the file exported from the firewall',
    compat: 'Zyxel uOS: USG FLEX H (e.g. 700H) · ZLD: USG FLEX, ATP (beta)',
    sample: 'Try a sample config',
    privacy: 'The file never leaves your browser and secrets are not read.',
    verify: 'How to verify',
    notUos: (name: string) => `${name} doesn't look like a Zyxel configuration: no zones or rules found.`,
    sampleFail: 'Could not load the sample config.',
  },
  it: {
    tabs: {
      map: 'Mappa', matrix: 'Matrice', routes: 'Route', rules: 'Regole', expo: 'NAT ed esposizione',
      objects: 'Oggetti', findings: 'Riscontri', sim: 'Simula', diff: 'Diff',
    },
    groups: ['Rete', 'Policy', 'Verifiche'],
    views: 'Viste',
    appMode: "Modalità dell'app",
    analysis: 'Analisi',
    firewall: 'Firewall',
    firewallView: '',
    firewallTitle: "Vedi la config come nell'interfaccia del firewall",
    searchAria: 'Cerca per nome o IP (Ctrl+K)',
    search: 'Cerca nome o IP',
    device: 'Zyxel uOS · ZLD',
    fileAria: (f: string) => `File ${f}: sostituisci, report, chiudi`,
    replace: 'Sostituisci config…',
    report: 'Report stampabile',
    close: 'Chiudi e rimuovi dal browser',
    themeTitle: 'Tema chiaro/scuro',
    toLight: 'Passa al tema chiaro',
    toDark: 'Passa al tema scuro',
    otherLang: 'EN',
    otherLangAria: 'Switch to English',
    navFoot: 'Gira nel browser. Il file non viene mai caricato.',
    inv: {
      zones: (n: number) => (n === 1 ? 'zona' : 'zone'),
      ifaces: (n: number) => (n === 1 ? 'interfaccia' : 'interfacce'),
      rules: (n: number) => (n === 1 ? 'regola' : 'regole'),
    },
    invAria: 'Inventario',
    sevCount: (d: number, w: number, i: number) => [`${d}`, d === 1 ? ' pericolo' : ' pericoli', `${w}`, w === 1 ? ' avviso' : ' avvisi', `${i}`, ' info'],
    lede: 'Legge la configurazione di un firewall Zyxel (uOS o ZLD) e disegna la rete: zone, traffico tra loro, servizi esposti e regole che non scattano mai.',
    dropAria: 'Carica il file di configurazione del firewall',
    dropTitle: 'Trascina qui un file .conf',
    dropText: 'o clicca per scegliere il file esportato dal firewall',
    compat: 'Zyxel uOS: USG FLEX H (es. 700H) · ZLD: USG FLEX, ATP (beta)',
    sample: 'Prova con una config di esempio',
    privacy: 'Il file non lascia il browser e i segreti non vengono letti.',
    verify: 'Come verificarlo',
    notUos: (name: string) => `${name} non sembra una configurazione Zyxel: nessuna zona o regola trovata.`,
    sampleFail: 'Impossibile caricare la config di esempio.',
  },
})

const NAV: { tabs: Tab[] }[] = [
  { tabs: ['map', 'matrix', 'routes'] },
  { tabs: ['rules', 'expo', 'objects'] },
  { tabs: ['findings', 'sim', 'diff'] },
]
const ICON: Record<Tab, (p: { size?: number }) => React.ReactElement> = {
  map: IconMap, matrix: IconGrid, routes: IconRoute, rules: IconList, expo: IconGlobe,
  objects: IconLayers, findings: IconWarn, sim: IconPlay, diff: IconDiff,
}

export default function App() {
  const [theme, setTheme] = useState<Theme>(() => {
    const t = loadTheme()
    applyTheme(t)
    return t
  })
  const [doc, setDoc] = useState<{ cfg: FirewallConfig; filename: string } | null>(loadConfig)
  const [tab, setTab] = useState<Tab>('map')
  const [appMode, setAppMode] = useState<'analisi' | 'firewall'>(loadAppMode)
  const [dragOver, setDragOver] = useState(false)
  const [ruleInit, setRuleInit] = useState({ from: '', to: '', q: '', n: 0 })
  const [routeInit, setRouteInit] = useState({ q: '', n: 0 })
  const [expoInit, setExpoInit] = useState({ risky: false, n: 0 })
  const [objInit, setObjInit] = useState({ orphans: false, n: 0 })
  const [findZone, setFindZone] = useState<string | null>(null)
  const [trace, setTrace] = useState<SimResult | null>(null)
  const [mapFocus, setMapFocus] = useState<{ sel: Sel; n: number } | null>(null)
  const [palOpen, setPalOpen] = useState(false)
  const [toast, setToast] = useState('')
  const fileRef = useRef<HTMLInputElement>(null)
  const fileMenu = useRef<HTMLDetailsElement>(null)

  useEffect(() => {
    if (!toast) return
    const t = setTimeout(() => setToast(''), 5000)
    return () => clearTimeout(t)
  }, [toast])

  function toggleTheme() {
    const t = theme === 'dark' ? 'light' : 'dark'
    applyTheme(t)
    setTheme(t)
  }

  function setMode(m: 'analisi' | 'firewall') {
    saveAppMode(m)
    setAppMode(m)
  }

  // Ctrl/Cmd+K opens the global search
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault()
        setPalOpen(o => !o)
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

  // File menu is a native <details>: closes on outside click or Esc
  useEffect(() => {
    const close = (e: Event) => {
      const d = fileMenu.current
      if (!d?.open) return
      if (e instanceof KeyboardEvent ? e.key === 'Escape' : !d.contains(e.target as Node)) {
        d.open = false
        if (e instanceof KeyboardEvent) d.querySelector('summary')?.focus()
      }
    }
    document.addEventListener('mousedown', close)
    document.addEventListener('keydown', close)
    return () => {
      document.removeEventListener('mousedown', close)
      document.removeEventListener('keydown', close)
    }
  }, [])

  const cfg = doc?.cfg ?? null
  const found = useMemo(() => (cfg ? computeFindings(cfg) : []), [cfg])

  // Sidebar counts: what each view lists
  const counts = useMemo<Partial<Record<Tab, number>>>(() => cfg ? {
    map: cfg.zones.length,
    matrix: zonePairs(cfg.rules.filter(r => r.enabled)).length,
    routes: cfg.routes.length,
    rules: cfg.rules.length,
    expo: cfg.nats.length,
    objects: Object.keys(cfg.addresses).length + Object.keys(cfg.addressGroups).length
      + Object.keys(cfg.services).length + Object.keys(cfg.serviceGroups).length,
    findings: found.length,
  } : {}, [cfg, found])

  function loadText(raw: string, name: string) {
    const parsed = parseConfig(raw)
    if (parsed.rules.length === 0 && parsed.zones.length === 0) {
      setToast(s.notUos(name))
      return
    }
    saveConfig(parsed, name)
    setDoc({ cfg: parsed, filename: name })
    setTab('map')
  }

  async function onFile(f: File | undefined) {
    if (!f) return
    loadText(await f.text(), f.name)
  }

  // Synthetic config served from public/: fake data, no real secrets
  async function loadSample() {
    try {
      const r = await fetch('sample.conf') // relative, so it also works under a subpath
      if (!r.ok) throw new Error(String(r.status))
      loadText(await r.text(), 'sample.conf')
    } catch {
      setToast(s.sampleFail)
    }
  }

  // File menu items close it before acting
  function fileAction(fn: () => void) {
    return () => { if (fileMenu.current) fileMenu.current.open = false; fn() }
  }

  function goRules(from: string, to: string) {
    setRuleInit(x => ({ from, to, q: '', n: x.n + 1 }))
    setTab('rules')
  }

  // Jump from a finding to the view that explains it
  const goFinding = useCallback((ev: Evidence) => {
    if (ev.view === 'expo') { setExpoInit(x => ({ risky: ev.risky ?? false, n: x.n + 1 })); setTab('expo') }
    else if (ev.view === 'rules') { setRuleInit(x => ({ from: '', to: '', q: ev.q, n: x.n + 1 })); setTab('rules') }
    else if (ev.view === 'objects') { setObjInit(x => ({ orphans: true, n: x.n + 1 })); setTab('objects') }
    else { setFindZone(ev.zone ?? null); setTab('findings') }
  }, [])

  function onPalettePick(a: PaletteAction) {
    setPalOpen(false)
    if (a.kind === 'map') {
      setMapFocus(f => ({ sel: a.sel, n: (f?.n ?? 0) + 1 }))
      setTab('map')
    } else if (a.kind === 'rules') {
      setRuleInit(x => ({ from: '', to: '', q: a.query, n: x.n + 1 }))
      setTab('rules')
    } else {
      setRouteInit(x => ({ q: a.query, n: x.n + 1 }))
      setTab('routes')
    }
  }

  function openReport() {
    if (!cfg || !doc) return
    const w = window.open('', '_blank')
    if (!w) return
    w.document.write(buildReport(cfg, doc.filename))
    w.document.close()
  }

  // Firewall mode: full-screen clone of the Zyxel UI on the same data.
  if (cfg && doc && appMode === 'firewall') {
    return <FwApp cfg={cfg} filename={doc.filename} onExit={() => setMode('analisi')} />
  }

  const danger = found.some(f => f.sev === 'danger')
  const sevN = (k: string) => found.filter(f => f.sev === k).length

  // Page title, with the inventory inline on the map and the severity
  // breakdown on the findings
  function pageHead(id: Tab) {
    let meta: [string, string][] = []
    if (cfg && id === 'map') {
      meta = [
        [String(cfg.zones.length), ` ${s.inv.zones(cfg.zones.length)}`],
        [String(cfg.interfaces.length), ` ${s.inv.ifaces(cfg.interfaces.length)}`],
        [String(cfg.rules.length), ` ${s.inv.rules(cfg.rules.length)}`],
        [String(cfg.nats.length), ' NAT'],
        [String(cfg.vpns.length), ' VPN'],
      ]
    } else if (id === 'findings') {
      const c = s.sevCount(sevN('danger'), sevN('warn'), sevN('info'))
      meta = [[c[0], c[1]], [c[2], c[3]], [c[4], c[5]]]
    }
    return (
      <div className="mainhead">
        <h1>{s.tabs[id]}</h1>
        {meta.length > 0 && (
          <p className="inv" aria-label={id === 'map' ? s.invAria : undefined}>
            {meta.map(([n, l]) => <span key={l}><b>{n}</b>{l}</span>)}
          </p>
        )}
      </div>
    )
  }

  return (
    <div className={`app${cfg ? '' : ' bare'}`}>
      <header className="topbar">
        <div className="logo" aria-hidden><IconTopology size={14} /></div>
        <div className="crumb">
          <span className="product">Config Explorer</span>
          {doc && cfg && (
            <>
              <span className="sep" aria-hidden>/</span>
              <details className="filemenu" ref={fileMenu}>
                <summary title={doc.filename} aria-label={s.fileAria(doc.filename)}>{doc.filename}</summary>
                <div className="fmpop">
                  <button onClick={fileAction(() => fileRef.current?.click())}>{s.replace}</button>
                  <button onClick={fileAction(openReport)}>{s.report}</button>
                  <button className="fmclose" onClick={fileAction(() => { clearConfig(); setDoc(null) })}>
                    {s.close}
                  </button>
                </div>
              </details>
              <span className="pill">{s.device}</span>
            </>
          )}
        </div>
        <div className="spacer" />
        {cfg && (
          <button
            className="searchbtn" onClick={() => setPalOpen(true)}
            aria-label={s.searchAria} aria-keyshortcuts="Control+K"
          >
            <IconSearch size={14} />
            <span>{s.search}</span>
            <kbd>Ctrl K</kbd>
          </button>
        )}
        {cfg && (
          <div className="seg" role="group" aria-label={s.appMode}>
            <button className="on" aria-pressed>{s.analysis}</button>
            <button aria-pressed={false} onClick={() => setMode('firewall')} title={s.firewallTitle}>
              {s.firewall}<span className="segx">{s.firewallView}</span>
            </button>
          </div>
        )}
        <button
          className="btn icon"
          onClick={() => setLang(lang === 'en' ? 'it' : 'en')}
          aria-label={s.otherLangAria}
          lang={lang === 'en' ? 'it' : 'en'}
        >
          {s.otherLang}
        </button>
        <button
          className="btn icon"
          onClick={toggleTheme}
          title={s.themeTitle}
          aria-label={theme === 'dark' ? s.toLight : s.toDark}
        >
          {theme === 'dark' ? <IconSun size={15} /> : <IconMoon size={15} />}
        </button>
        <input
          ref={fileRef} type="file" accept=".conf,.txt" hidden
          onChange={e => { onFile(e.target.files?.[0]); e.target.value = '' }}
        />
      </header>

      {cfg && (
        <nav className="sidenav" aria-label={s.views}>
          {NAV.map((g, k) => (
            <div className="navgroup" key={k}>
              <p className="navhead">{s.groups[k]}</p>
              {g.tabs.map(id => {
                const Icon = ICON[id]
                const n = counts[id]
                return (
                  <button
                    key={id}
                    className={`navitem${tab === id ? ' on' : ''}`}
                    aria-current={tab === id ? 'page' : undefined}
                    onClick={() => { setTab(id); if (id === 'findings') setFindZone(null) }}
                  >
                    <Icon size={16} />
                    <span className="lbl">{s.tabs[id]}</span>
                    {n !== undefined && <span className={`n${id === 'findings' && danger ? ' red' : ''}`}>{n}</span>}
                  </button>
                )
              })}
            </div>
          ))}
          <p className="navfoot">
            {s.navFoot}
            <a className="navver" href={RELEASES_URL} target="_blank" rel="noopener noreferrer">v{__APP_VERSION__}</a>
          </p>
        </nav>
      )}

      {!cfg && (
        <main className="landing">
          <div className="landbox">
            <h1>Config Explorer</h1>
            <p className="lede">{s.lede}</p>
            <div
              className={`drop ${dragOver ? 'over' : ''}`}
              role="button"
              tabIndex={0}
              aria-label={s.dropAria}
              onClick={() => fileRef.current?.click()}
              onKeyDown={e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); fileRef.current?.click() } }}
              onDragOver={e => { e.preventDefault(); setDragOver(true) }}
              onDragLeave={() => setDragOver(false)}
              onDrop={e => { e.preventDefault(); setDragOver(false); onFile(e.dataTransfer.files?.[0]) }}
            >
              <IconUpload size={20} />
              <h2>{s.dropTitle}</h2>
              <p>{s.dropText}</p>
              <p className="compat">{s.compat}</p>
            </div>
            <button className="btn" onClick={loadSample}>{s.sample}</button>
            <p className="privacy">
              <IconLock size={13} /> {s.privacy}{' '}
              <a href={TRUST_URL} target="_blank" rel="noopener noreferrer">{s.verify}</a>
            </p>
          </div>
        </main>
      )}

      {cfg && tab === 'map' && (
        <main className="view">
          <MapDiagram
            cfg={cfg}
            trace={trace} onClearTrace={() => setTrace(null)}
            focus={mapFocus} findings={found} onGo={goFinding}
            head={pageHead('map')}
          />
        </main>
      )}
      {cfg && doc && tab !== 'map' && (
        <main className="view page">
          {pageHead(tab)}
          {tab === 'rules' && (
            <RulesTable
              key={ruleInit.n} cfg={cfg}
              initialFrom={ruleInit.from} initialTo={ruleInit.to} initialQuery={ruleInit.q}
            />
          )}
          {tab === 'routes' && <RoutesTable key={routeInit.n} cfg={cfg} initialQuery={routeInit.q} />}
          {tab === 'objects' && <Objects key={objInit.n} cfg={cfg} initialOrphans={objInit.orphans} />}
          {tab === 'matrix' && <Matrix cfg={cfg} onPick={goRules} />}
          {tab === 'sim' && <Simulator cfg={cfg} onTrace={r => { setTrace(r); setTab('map') }} />}
          {tab === 'expo' && <Exposure key={expoInit.n} cfg={cfg} initialOnlyRisky={expoInit.risky} />}
          {tab === 'findings' && <Findings list={found} zone={findZone} onGo={goFinding} onAll={() => setFindZone(null)} />}
          {tab === 'diff' && <DiffView cfg={cfg} filename={doc.filename} />}
        </main>
      )}

      {cfg && palOpen && <Palette cfg={cfg} onPick={onPalettePick} onClose={() => setPalOpen(false)} />}
      {toast && (
        <div className="toast" role="alert">
          <IconAlert size={15} />
          {toast}
        </div>
      )}
    </div>
  )
}
