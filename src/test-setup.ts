// Tests always run in English, whatever the machine locale:
// i18n reads navigator.language on import.
Object.defineProperty(globalThis, 'navigator', { value: { language: 'en-US' }, configurable: true })
