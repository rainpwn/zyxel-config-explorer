import type { FirewallConfig } from './model'
import { parseUos } from './parser/uos'

// Store the parsed config, never the .conf text: the parser drops secrets,
// the raw file has them (psk, password hashes).
const CFG = 'ct.cfg'
// Bump when FirewallConfig or the parser changes: a config saved with a
// different version is discarded and must be reloaded
const CFG_VERSION = 1
const NAME = 'ct.filename'
const THEME = 'ct.theme'
const LEGACY_RAW = 'ct.raw'

function read(key: string): string | null {
  try { return localStorage.getItem(key) } catch { return null }
}

export function saveConfig(cfg: FirewallConfig, filename: string) {
  try {
    localStorage.setItem(CFG, JSON.stringify({ v: CFG_VERSION, cfg }))
    localStorage.setItem(NAME, filename)
  } catch {
    // Quota exceeded: the app still works, just without persistence
  }
}

export function loadConfig(): { cfg: FirewallConfig; filename: string } | null {
  // Older versions stored the raw .conf: convert it and delete it
  const legacy = read(LEGACY_RAW)
  if (legacy) {
    saveConfig(parseUos(legacy), read(NAME) ?? 'config.conf')
    try { localStorage.removeItem(LEGACY_RAW) } catch { /* storage denied */ }
  }
  const json = read(CFG)
  if (!json) return null
  try {
    const saved = JSON.parse(json)
    if (saved.v !== CFG_VERSION) return null
    return { cfg: saved.cfg, filename: read(NAME) ?? 'config.conf' }
  } catch {
    return null
  }
}

export function clearConfig() {
  try {
    localStorage.removeItem(CFG)
    localStorage.removeItem(NAME)
  } catch { /* storage denied */ }
}

// Dark by default: the map is the one view you cannot skim,
// and on a graphite background the allow/deny arrows stand out much better.
export function loadTheme(): 'light' | 'dark' {
  const t = read(THEME)
  return t === 'light' || t === 'dark' ? t : 'dark'
}

const APPMODE = 'ct.appmode'
export function loadAppMode(): 'analisi' | 'firewall' {
  return read(APPMODE) === 'firewall' ? 'firewall' : 'analisi'
}
export function saveAppMode(m: 'analisi' | 'firewall') {
  try { localStorage.setItem(APPMODE, m) } catch { /* storage denied: applies for this session */ }
}

// Written to the DOM outside useEffect on purpose: the map reads the tokens
// with getComputedStyle inside an effect, and child effects run before the
// parent's, so going through here the attribute is already right when it reads.
export function applyTheme(t: 'light' | 'dark') {
  document.documentElement.dataset.theme = t
  try {
    localStorage.setItem(THEME, t)
  } catch {
    // Storage full or denied: the theme stays valid for this session
  }
}
