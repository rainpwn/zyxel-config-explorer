// Two languages, no library. Each file declares its strings next to the
// code with loc({ en, it }): TypeScript forces `it` to have the same keys
// and signatures as `en`. The language is fixed at load; switching reloads
// the page (the config stays in localStorage), so module-level strings
// stay valid.

export type Lang = 'en' | 'it'

const KEY = 'ct.lang'

function detect(): Lang {
  try {
    const saved = localStorage.getItem(KEY)
    if (saved === 'en' || saved === 'it') return saved
  } catch { /* storage denied */ }
  if (typeof navigator !== 'undefined' && navigator.language?.toLowerCase().startsWith('it')) return 'it'
  return 'en'
}

export const lang: Lang = detect()

if (typeof document !== 'undefined') document.documentElement.lang = lang

export function loc<T>(d: { en: T; it: NoInfer<T> }): T {
  return d[lang]
}

export function setLang(l: Lang) {
  try { localStorage.setItem(KEY, l) } catch { /* storage denied: keep the current language */ }
  location.reload()
}
