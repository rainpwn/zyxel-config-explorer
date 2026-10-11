import { lang } from './i18n'

// Downloads rows as CSV for Excel: ';' separator in Italian (the comma is
// the decimal mark), ',' in English; UTF-8 BOM.
const SEP = lang === 'it' ? ';' : ','

export function downloadCsv(filename: string, rows: (string | number)[][]) {
  const cell = (v: string | number) => {
    const s = String(v)
    return /[";,\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s
  }
  const csv = '﻿' + rows.map(r => r.map(cell).join(SEP)).join('\r\n')
  const a = document.createElement('a')
  a.href = URL.createObjectURL(new Blob([csv], { type: 'text/csv;charset=utf-8' }))
  a.download = filename
  a.click()
  URL.revokeObjectURL(a.href)
}
