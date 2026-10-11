import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'

// Privacy enforced by the browser: the built page may load its own files and
// nothing else, and may not connect anywhere but its own origin (the bundled
// sample). A config dropped on the page has no way out. Build only: the dev
// server needs inline scripts for hot reload.
// style-src keeps 'unsafe-inline' for React style props and the printable
// report, which is written into a blank window that inherits this policy.
const CSP = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self' 'unsafe-inline'",
  "font-src 'self'",
  "img-src 'self' data: blob:",
  "connect-src 'self'",
  "base-uri 'none'",
  "form-action 'none'",
].join('; ')

export default defineConfig({
  // relative paths: works under GitHub Pages' /<repo>/ and any static host
  base: './',
  plugins: [
    react(),
    {
      name: 'csp',
      apply: 'build',
      transformIndexHtml: html =>
        html.replace('<meta charset="UTF-8" />', `<meta charset="UTF-8" />\n    <meta http-equiv="Content-Security-Policy" content="${CSP}" />`),
    },
  ],
  test: { setupFiles: ['src/test-setup.ts'] },
})
