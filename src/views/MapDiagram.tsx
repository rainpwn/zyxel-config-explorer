import { useLayoutEffect, useMemo, useRef, useState } from 'react'
import type { FirewallConfig } from '../model'
import { ifaceZoneMap, zonePairs, rulesForIface } from '../derive'
import { impactOfDown, type SimResult } from '../analysis'
import DetailPanel, { type Sel } from './DetailPanel'
import { zoneSeverity, type Evidence, type Finding } from './findingsList'
import { sevLabel } from './Findings'
import { IconBan, IconCheck, IconX } from '../icons'
import { loc } from '../i18n'

const s = loc({
  en: {
    tiers: ['Internet', 'Perimeter and VPN', 'DMZ', 'Internal'],
    down: (iface: string, n: number) => `Failure simulation: ${iface} down, ${n} broken. Affected zones are outlined in red.`,
    zoneSel: (z: string, i: number, o: number) => `${z} selected: ${i} inbound, ${o} outbound. Hover an arrow to isolate it.`,
    ifaceSel: (n: string, i: number, o: number) => `Interface ${n} selected: ${i} inbound, ${o} outbound, only the rules that touch its subnet.`,
    idle: 'Click a zone to see where its traffic comes from and where it goes.',
    mixed: 'mixed',
    legendAria: 'Arrow colours',
    allowed: 'Allowed',
    blocked: 'Blocked',
    traceRule: (n: number, name: string) => ` · rule #${n} ${name}`,
    closeTrace: 'Close the trace',
    arrowTitle: 'click for the rules',
    zoneRules: (n: number) => `${n} rule${n === 1 ? '' : 's'}`,
    kidTitle: 'click for this interface’s flows',
    moreIfaces: (n: number) => `+${n} interface${n === 1 ? '' : 's'}`,
    tunnels: (n: number) => `${n} tunnel${n === 1 ? '' : 's'}`,
    noIfaces: 'no interfaces',
  },
  it: {
    tiers: ['Internet', 'Perimetro e VPN', 'DMZ', 'Reti interne'],
    down: (iface: string, n: number) => `Simulazione guasto: ${iface} giù, ${n} rott${n === 1 ? 'o' : 'i'}. Le zone colpite sono bordate di rosso.`,
    zoneSel: (z: string, i: number, o: number) => `${z} selezionata: ${i} in ingresso, ${o} in uscita. Passa su una freccia per isolarla.`,
    ifaceSel: (n: string, i: number, o: number) => `Interfaccia ${n} selezionata: ${i} in ingresso, ${o} in uscita, solo le regole che toccano la sua subnet.`,
    idle: 'Clicca una zona per vedere da dove riceve e verso dove esce il traffico.',
    mixed: 'misto',
    legendAria: 'Colori delle frecce',
    allowed: 'Permesso',
    blocked: 'Bloccato',
    traceRule: (n: number, name: string) => ` · regola #${n} ${name}`,
    closeTrace: 'Chiudi il tracciato',
    arrowTitle: 'clic per le regole',
    zoneRules: (n: number) => `${n} ${n === 1 ? 'regola' : 'regole'}`,
    kidTitle: 'clic per i flussi di questa interfaccia',
    moreIfaces: (n: number) => `+${n} interfacc${n === 1 ? 'ia' : 'e'}`,
    tunnels: (n: number) => `${n} tunnel`,
    noIfaces: 'nessuna interfaccia',
  },
})

// Structural diagram, not a node-and-edge graph: by default it shows only
// the firewall, trust bands and zones with their interfaces. Clicking a zone
// shows only its arrows, with flows animated in the traffic direction.

function tierOf(name: string, external: boolean): number {
  if (external || /wan/i.test(name)) return 0
  if (/vpn|tunnel/i.test(name) || name === 'ZyWALL' || name === 'any') return 1
  if (/dmz/i.test(name)) return 2
  return 3
}
const TIER_LABEL = s.tiers

const CARD_W = 230 // minimum width: the card grows until the data fits
const CARD_MAX_W = 320
const GAP_Y = 68
const PAD_TOP = 24
const PAD_L = 130 // left gutter for the band labels
const PAD_R = 48 // room for lanes beside the outermost cards
const CLEAR = 14 // a flow keeps this far from any card it does not connect
const FW_W = 320
const FW_H = 34
const MAX_PER_ROW = 5
const GAP_X = 32
// Card metrics, mirrored in theme.css (.dgm-zhead, .dgm-kid)
const HEAD_H = 40
const ROW_H = 27

// Card width needed to avoid truncating name and IP. Data is Geist Mono 12px
// (7.2px per char); the zone name is Geist 14px medium, about 8.2px per char.
function cardWidth(name: string, rules: number, kids: Kid[]): number {
  const head = 24 + 15 + name.length * 8.2 + 12 + String(rules).length * 7.2
  const rows = kids.slice(0, 4).map(k => {
    const label = k.name.length + (k.vlan ? ` · ${k.vlan}`.length : 0)
    const right = k.ip ?? k.note
    return 24 + label * 7.2 + (right ? 16 + right.length * 7.2 : 0)
  })
  return Math.min(CARD_MAX_W, Math.ceil(Math.max(CARD_W, head, ...rows)))
}

// Orthogonal path through the points, with small rounded corners
function orth(pts: [number, number][], r = 6): string {
  let d = `M ${pts[0][0]} ${pts[0][1]}`
  for (let i = 1; i < pts.length - 1; i++) {
    const [px, py] = pts[i - 1], [x, y] = pts[i], [nx, ny] = pts[i + 1]
    const k = Math.min(r, Math.hypot(x - px, y - py) / 2, Math.hypot(nx - x, ny - y) / 2)
    d += ` L ${x - Math.sign(x - px) * k} ${y - Math.sign(y - py) * k}`
      + ` Q ${x} ${y} ${x + Math.sign(nx - x) * k} ${y + Math.sign(ny - y) * k}`
  }
  const [lx, ly] = pts[pts.length - 1]
  return `${d} L ${lx} ${ly}`
}

interface Kid { name: string; ip?: string; vlan?: number; off?: boolean; note?: string }
interface ZoneBox {
  name: string
  tier: number
  kids: Kid[]
  rules: number
  tunnels: string | null // muted row when the tunnel count has no free slot in a vti row
  x: number; y: number; w: number; h: number
}
interface Arrow {
  key: string; from: string; to: string
  d: string; status: string; label: string; mx: number; my: number
}

export default function MapDiagram({ cfg, trace, onClearTrace, focus, findings, onGo, head }: {
  cfg: FirewallConfig
  trace?: SimResult | null
  onClearTrace?: () => void
  focus?: { sel: Sel; n: number } | null
  findings: Finding[]
  onGo: (ev: Evidence) => void
  head: React.ReactNode
}) {
  const [sel, setSel] = useState<Sel | null>(null)
  const [selZone, setSelZone] = useState<string | null>(null)
  const [selIface, setSelIface] = useState<string | null>(null)
  const [selPair, setSelPair] = useState<string | null>(null)
  const [hoverPair, setHoverPair] = useState<string | null>(null)
  const frameRef = useRef<HTMLDivElement>(null)
  const [frameW, setFrameW] = useState(1000)

  useLayoutEffect(() => {
    const el = frameRef.current
    if (!el) return
    const measure = () => setFrameW(el.clientWidth)
    measure()
    const ro = new ResizeObserver(measure)
    ro.observe(el)
    return () => ro.disconnect()
  }, [])

  const ifZone = useMemo(() => ifaceZoneMap(cfg), [cfg])
  const pairs = useMemo(() => zonePairs(cfg.rules.filter(r => r.enabled)), [cfg])
  const zoneSev = useMemo(() => zoneSeverity(findings), [findings])

  // With an interface selected, flows are its own (CIDR match on its subnet).
  // Arrows still start from the zone card, but count only rules touching the subnet.
  const activePairs = useMemo(
    () => selIface ? zonePairs(rulesForIface(cfg, selIface).filter(r => r.enabled)) : pairs,
    [cfg, selIface, pairs],
  )

  const { boxes, byName, innerW, height, fwY, fwX, spine } = useMemo(() => {
    const externalZones = new Set(
      cfg.interfaces.filter(i => i.role === 'external' && ifZone[i.name]).map(i => ifZone[i.name]),
    )
    const kidsOf = new Map<string, Kid[]>()
    for (const i of cfg.interfaces) {
      const z = ifZone[i.name]
      if (!z) continue
      const l = kidsOf.get(z) ?? []
      // a vti interface stands for the IPsec tunnels: show how many there are
      const note = i.kind === 'vti' && !i.ip && cfg.vpns.length ? s.tunnels(cfg.vpns.length) : undefined
      l.push({ name: i.name, ip: i.ip, vlan: i.vlanId, off: !i.enabled, note })
      kidsOf.set(z, l)
    }
    const weight = (n: string) => cfg.rules.filter(r => r.enabled && (r.from === n || r.to === n)).length

    const cardH = (n: number) => 2 + HEAD_H + Math.max(1, Math.min(n, 4)) * ROW_H + (n > 4 ? ROW_H : 0)
    const vtiIfaces = new Set(cfg.interfaces.filter(i => i.kind === 'vti' && i.ip).map(i => i.name))
    const boxes: ZoneBox[] = cfg.zones.map(z => {
      const kids = kidsOf.get(z.name) ?? []
      const rules = weight(z.name)
      const tunnels = cfg.vpns.length && kids.some(k => vtiIfaces.has(k.name)) ? s.tunnels(cfg.vpns.length) : null
      return {
        name: z.name, tier: tierOf(z.name, externalZones.has(z.name)), kids,
        rules, tunnels,
        w: cardWidth(z.name, rules, kids), h: cardH(kids.length) + (tunnels ? ROW_H : 0),
        x: 0, y: 0,
      }
    })
    // Rows wrap at the measured canvas width, so the diagram never needs a
    // horizontal scroll (only a canvas narrower than one card does).
    const avail = Math.max(CARD_W, frameW - PAD_L - PAD_R)

    const perTier: ZoneBox[][] = [[], [], [], []]
    for (const b of boxes) perTier[b.tier].push(b)
    let y = PAD_TOP
    let maxW = FW_W
    let fwY = PAD_TOP
    const rows: ZoneBox[][] = []
    perTier.forEach((zones, tier) => {
      if (zones.length > 0) {
        zones.sort((a, b) => b.rules - a.rules)
        for (let k = 0; k < zones.length;) {
          let n = 1, w = zones[k].w
          while (n < MAX_PER_ROW && k + n < zones.length && w + GAP_X + zones[k + n].w <= avail) {
            w += GAP_X + zones[k + n].w
            n++
          }
          const chunk = zones.slice(k, k + n)
          k += n
          const ordered: ZoneBox[] = []
          chunk.forEach((b, i) => (i % 2 === 0 ? ordered.push(b) : ordered.unshift(b)))
          // a pair of zones gets air between them when it fits, a full row stays compact
          const gap = ordered.length === 2 && w + 80 - GAP_X <= avail ? 80 : GAP_X
          // a row below the firewall with several zones needs room for its bus
          if (ordered.length > 1 && rows.length > 0) y += 30
          const rowW = ordered.reduce((n, b) => n + b.w, 0) + (ordered.length - 1) * gap
          maxW = Math.max(maxW, rowW)
          let x = -rowW / 2
          for (const b of ordered) { b.x = x; b.y = y; x += b.w + gap }
          rows.push(ordered)
          y += Math.max(...ordered.map(b => b.h)) + GAP_Y
        }
      }
      // the firewall bar sits between the Internet band and everything else
      if (tier === 0) {
        fwY = perTier[0].length ? y - GAP_Y + 56 : y
        y = fwY + FW_H + 46
      }
    })
    const innerW = maxW
    const fwX = innerW / 2
    for (const b of boxes) b.x += fwX

    // Spine: orthogonal wiring from every zone to the firewall bar. One trunk
    // through the middle, a bus per row, a drop per zone. Drawn under the
    // cards, which hide the trunk where it passes behind them.
    const spine: { key: string; d: string; zone?: string }[] = []
    let lowest = fwY + FW_H
    for (const row of rows) {
      const above = row[0].y < fwY
      const top = Math.min(...row.map(b => b.y))
      const bottom = Math.max(...row.map(b => b.y + b.h))
      const busY = above ? (bottom + fwY) / 2 : top - 40
      const xs = row.map(b => b.x + b.w / 2)
      spine.push({ key: `bus${top}`, d: `M ${Math.min(fwX, ...xs)} ${busY} H ${Math.max(fwX, ...xs)}` })
      if (above) spine.push({ key: `trunk${top}`, d: `M ${fwX} ${busY} V ${fwY}` })
      else lowest = Math.max(lowest, busY)
      for (const b of row) {
        const cx = b.x + b.w / 2
        spine.push({ key: b.name, zone: b.name, d: above ? `M ${cx} ${b.y + b.h} V ${busY}` : `M ${cx} ${busY} V ${b.y}` })
      }
    }
    spine.push({ key: 'trunk', d: `M ${fwX} ${fwY + FW_H} V ${lowest}` })

    const byName = new Map(boxes.map(b => [b.name, b]))
    return { boxes, byName, innerW, height: y - GAP_Y + 24, fwY, fwX, spine }
  }, [cfg, ifZone, frameW])

  const arrows = useMemo<Arrow[]>(() => {
    if (!selZone) return []
    // Slots are allocated on the selected zone's edges: zones to its right
    // take offsets right of the spine, zones to its left take the left, and
    // a zone in the same column puts inbound right, outbound left. The other
    // end reuses the same offset, so arrows run parallel and never cross.
    const sel = byName.get(selZone)
    const used = new Map<string, number>()
    const offsetFor = (other: ZoneBox, side: 'top' | 'bot', inbound: boolean) => {
      if (!sel) return 0
      const dx = other.x + other.w / 2 - (sel.x + sel.w / 2)
      const sign = Math.abs(dx) < 1 ? (inbound ? 1 : -1) : Math.sign(dx)
      const k = `${side}${sign}`
      const i = used.get(k) ?? 0
      used.set(k, i + 1)
      return sign * (30 + i * 26)
    }
    const clampX = (b: ZoneBox, off: number) => {
      const max = b.w / 2 - 14
      return b.x + b.w / 2 + Math.max(-max, Math.min(max, off))
    }

    // Free horizontal bands: the gaps between rows, split by the firewall
    // bar. Nothing is drawn there, so a flow can always turn inside one.
    const spans = [...boxes.map(c => [c.y, c.y + c.h]), [fwY, fwY + FW_H]].sort((p, q) => p[0] - q[0])
    const bands: [number, number][] = []
    let reach = spans[0][1]
    for (const [t, b] of spans.slice(1)) {
      if (t > reach) bands.push([reach, t])
      reach = Math.max(reach, b)
    }
    const mid = (band: [number, number]) => (band[0] + band[1]) / 2

    const lanes = new Map<string, number>()
    const out: Arrow[] = []
    for (const p of activePairs) {
      if ((p.from !== selZone && p.to !== selZone) || p.from === p.to) continue
      const a = byName.get(p.from), b = byName.get(p.to)
      if (!a || !b) continue
      const inbound = p.to === selZone
      const other = inbound ? a : b
      // Obstacles: every card but the two ends, grown by the clearance
      const rects = boxes.filter(c => c !== a && c !== b)
        .map(c => ({ l: c.x - CLEAR, r: c.x + c.w + CLEAR, t: c.y - CLEAR, b: c.y + c.h + CLEAR }))
      const inside = (x: number, y: number) => rects.some(o => x > o.l && x < o.r && y > o.t && y < o.b)
      const vClear = (x: number, ya: number, yb: number) => !rects.some(o =>
        x > o.l && x < o.r && Math.max(ya, yb) > o.t && Math.min(ya, yb) < o.b)

      let x1: number, y1: number, x2: number, y2: number, yA: number, yB: number
      if (a.y + a.h <= b.y || b.y + b.h <= a.y) {
        const down = a.y < b.y
        const off = offsetFor(other, (down === inbound) ? 'top' : 'bot', inbound)
        x1 = clampX(a, off); y1 = down ? a.y + a.h : a.y
        x2 = clampX(b, off); y2 = down ? b.y : b.y + b.h
        const between = bands.filter(([t, bt]) => t >= Math.min(y1, y2) - 1 && bt <= Math.max(y1, y2) + 1)
        // first band leaving a, last band reaching b
        yA = mid(down ? between[0] : between[between.length - 1])
        yB = mid(down ? between[between.length - 1] : between[0])
      } else {
        // same band: out of the bottoms, across the band below the row
        const off = offsetFor(other, 'bot', inbound)
        x1 = clampX(a, off); y1 = a.y + a.h
        x2 = clampX(b, -off); y2 = b.y + b.h
        const below = bands.find(([t]) => t >= Math.max(y1, y2) - 1)
        yA = yB = below ? mid(below) : Math.max(y1, y2) + 34
      }

      // A plain curve when it clears every other card, as in the mockup
      let d: string, mx: number, my: number
      const cy = (y1 + y2) / 2
      const curveOk = yA !== yB || a.y + a.h <= b.y || b.y + b.h <= a.y
        ? Array.from({ length: 41 }, (_, i) => i / 40).every(t => {
            const u = 1 - t
            const x = u * u * u * x1 + 3 * u * u * t * x1 + 3 * u * t * t * x2 + t * t * t * x2
            const y = u * u * u * y1 + 3 * u * u * t * cy + 3 * u * t * t * cy + t * t * t * y2
            return !inside(x, y)
          })
        : false
      if (curveOk) {
        d = `M ${x1} ${y1} C ${x1} ${cy}, ${x2} ${cy}, ${x2} ${y2}`
        mx = (x1 + x2) / 2; my = cy
      } else if (yA === yB) {
        d = orth([[x1, y1], [x1, yA], [x2, yA], [x2, y2]])
        mx = (x1 + x2) / 2; my = yA
      } else {
        // Vertical lane between the two turn bands: straight under an end if
        // that is clear, else beside the cards in the way, on the nearer side.
        let lane = [x2, x1].find(x => vClear(x, yA, yB))
        if (lane === undefined) {
          const sideLane = (dir: -1 | 1) => {
            let x = (x1 + x2) / 2
            for (let i = 0; i < 20; i++) {
              const hit = rects.find(o => x > o.l && x < o.r && Math.max(yA, yB) > o.t && Math.min(yA, yB) < o.b)
              if (!hit) return x
              x = dir < 0 ? hit.l : hit.r
            }
            return x
          }
          const l = sideLane(-1), r = sideLane(1)
          const xc = (x1 + x2) / 2
          const goLeft = Math.abs(xc - l) <= Math.abs(xc - r)
          const base = goLeft ? l : r
          const k = `${Math.round(base)}`
          const n = lanes.get(k) ?? 0
          lanes.set(k, n + 1)
          // parallel flows step outward, away from the cards they skirt
          lane = base + (goLeft ? -6 : 6) * n
        }
        d = orth([[x1, y1], [x1, yA], [lane, yA], [lane, yB], [x2, yB], [x2, y2]])
        mx = lane; my = (yA + yB) / 2
      }
      const status = p.deny === 0 ? 'allow' : p.allow === 0 ? 'deny' : 'mixed'
      const label = p.deny > 0 && p.allow > 0 ? `${p.allow} allow · ${p.deny} deny` : `${p.rules.length}`
      out.push({ key: `${p.from}→${p.to}`, from: p.from, to: p.to, d, status, label, mx, my })
    }
    return out
  }, [selZone, activePairs, byName, boxes, fwY])

  const related = useMemo(() => {
    if (!selZone) return null
    const r = new Set<string>([selZone])
    for (const p of activePairs) {
      if (p.from === selZone) r.add(p.to)
      if (p.to === selZone) r.add(p.from)
    }
    return r
  }, [selZone, activePairs])

  // Interface failure: affected zones are outlined in red, the rest dims.
  // The list of impacts lives in the panel ('down' view).
  const down = useMemo(
    () => (sel?.kind === 'down' && sel.target.kind === 'iface')
      ? impactOfDown(cfg, 'iface', sel.target.name) : null,
    [cfg, sel],
  )
  const downZones = down && down.zones.length ? new Set(down.zones) : null
  const downIface = down?.target.name ?? null
  const downBroken = down ? down.items.filter(i => i.severity === 'rotto').length : 0

  // A mouse click would focus the button and the browser would scroll the
  // canvas to it: skip the focus on mousedown (the click still fires,
  // keyboard focus is untouched).
  function noScrollFocus(e: React.MouseEvent<HTMLButtonElement>) {
    e.preventDefault()
  }

  function zoneOfIface(name: string) {
    return cfg.zones.find(z => z.interfaces.includes(name))?.name ?? null
  }
  function pickZone(name: string | null) {
    setSelZone(name); setSelIface(null); setSelPair(null)
    setSel(name ? { kind: 'zone', name } : null)
    onClearTrace?.()
  }
  function pickIface(name: string, zone: string) {
    // clicking the selected interface again goes back to whole-zone flows
    if (selIface === name) { pickZone(zone); return }
    setSelZone(zone); setSelIface(name); setSelPair(null)
    setSel({ kind: 'iface', name })
    onClearTrace?.()
  }
  function pickPair(a: Arrow) {
    setSelPair(a.key)
    setSel({ kind: 'pair', from: a.from, to: a.to })
  }
  function onPanelSelect(p: Sel) {
    setSel(p)
    if (p.kind === 'zone') { setSelZone(p.name); setSelIface(null); setSelPair(null) }
    else if (p.kind === 'iface') { const z = zoneOfIface(p.name); if (z) setSelZone(z); setSelIface(p.name); setSelPair(null) }
    else if (p.kind === 'pair') { setSelZone(p.from); setSelIface(null); setSelPair(`${p.from}→${p.to}`) }
    else if (p.kind === 'down') { setSelZone(null); setSelIface(null); setSelPair(null) }
  }

  useLayoutEffect(() => {
    if (!focus) return
    const f = focus.sel
    setSel(f)
    if (f.kind === 'zone') setSelZone(f.name)
    else if (f.kind === 'iface') { const z = zoneOfIface(f.name); if (z) setSelZone(z) }
  }, [focus?.n])

  useLayoutEffect(() => {
    if (trace && trace.ok) { setSelZone(trace.srcZone); setSel({ kind: 'zone', name: trace.srcZone }); setSelPair(null) }
  }, [trace?.srcIp, trace?.dstIp])

  const inCount = selZone ? activePairs.filter(p => p.to === selZone && p.from !== selZone).length : 0
  const outCount = selZone ? activePairs.filter(p => p.from === selZone && p.to !== selZone).length : 0
  const focusKey = hoverPair ?? selPair

  return (
    <div className="mapwrap">
      <div className="mapmain">
        {head}
        <div className="hintrow">
          <p className="hintline" aria-live="polite">
            {down
              ? s.down(downIface ?? '', downBroken)
              : selIface
                ? s.ifaceSel(selIface, inCount, outCount)
                : selZone ? s.zoneSel(selZone, inCount, outCount) : s.idle}
          </p>
          <div className="legend" aria-label={s.legendAria}>
            <span><i className="allow" />allow</span>
            <span><i className="deny" />deny</span>
            <span><i className="mixed" />{s.mixed}</span>
          </div>
        </div>

        <div className="mapframe" ref={frameRef}>

          {trace && trace.ok && (
            <div className={`tracebar ${trace.verdict}`} role="status">
              <b>{trace.verdict === 'allow' ? <IconCheck size={14} /> : <IconBan size={14} />}{trace.verdict === 'allow' ? s.allowed : s.blocked}</b>
              <span className="path">
                {trace.srcIp} ({trace.srcZone}) → {trace.dstIp} ({trace.dstZone})
                {trace.rule ? s.traceRule(trace.rule.order + 1, trace.rule.name) : ' · default deny'}
              </span>
              <button className="btn icon ghost" onClick={() => onClearTrace?.()} aria-label={s.closeTrace}><IconX size={13} /></button>
            </div>
          )}

          <div
            className="dgm-scroll"
            onClick={e => { if (!(e.target as Element).closest('.dgm-zone, .dgm-hit')) pickZone(null) }}
          >
            <div className={`dgm-canvas${selZone ? ' focused' : ''}`} style={{ width: Math.max(frameW, PAD_L + innerW + PAD_R), height }}>
              {/* sticky gutter: the band labels stay put when the map is panned */}
              <div className="dgm-gutter" style={{ height }}>
                {TIER_LABEL.map((lbl, t) => {
                  const row = boxes.filter(b => b.tier === t)
                  if (row.length === 0) return null
                  return <div key={lbl} className="dgm-tier" style={{ top: Math.min(...row.map(b => b.y)) + 10 }}>{lbl}</div>
                })}
              </div>

              <div className="dgm-inner" style={{ width: innerW, height, left: Math.max(PAD_L, (frameW - innerW) / 2) }}>
                <svg className="dgm-svg" width={innerW} height={height} aria-hidden>
                  {spine.map(p => {
                    const hit = p.zone && downZones?.has(p.zone)
                    const dim = p.zone && (downZones ? !hit : (related && !related.has(p.zone)))
                    return <path key={p.key} className={`dgm-spine${dim ? ' dim' : ''}${hit ? ' hit' : ''}`} d={p.d} />
                  })}
                </svg>

                {/* traffic arrows under the opaque cards: a flow never crosses a
                    card that is not its endpoint, it takes a lane beside it */}
                <svg className="dgm-svg dgm-flows" width={innerW} height={height} aria-hidden>
                  <defs>
                    {['allow', 'deny', 'mixed'].map(k => (
                      <marker key={k} id={`ah-${k}`} markerWidth="10" markerHeight="9" refX="10" refY="4.5" orient="auto" markerUnits="userSpaceOnUse">
                        <path d="M0,0 L10,4.5 L0,9 Z" className={`ah ${k}`} />
                      </marker>
                    ))}
                  </defs>
                  {arrows.map(a => {
                    const faded = focusKey && focusKey !== a.key
                    const on = selPair === a.key
                    return (
                      <g key={a.key} data-from={a.from} data-to={a.to} className={`dgm-arw ${a.status}${faded ? ' faded' : ''}${on ? ' sel' : ''}`}>
                        <path className="dgm-flow" d={a.d} markerEnd={`url(#ah-${a.status})`} />
                        <path
                          className="dgm-hit" d={a.d}
                          onClick={() => pickPair(a)}
                          onMouseEnter={() => setHoverPair(a.key)}
                          onMouseLeave={() => setHoverPair(null)}
                        >
                          <title>{a.from} → {a.to} · {s.arrowTitle}</title>
                        </path>
                      </g>
                    )
                  })}
                  {/* rule count only on the focused arrow: with all labels on, they
                      overlapped at the midpoint */}
                  {arrows.filter(a => a.key === focusKey).map(a => (
                    <text key={`t${a.key}`} className="dgm-albl" x={a.mx} y={a.my - 6}>{a.label}</text>
                  ))}
                </svg>

                <div className="dgm-fw" style={{ top: fwY, left: fwX - FW_W / 2, width: FW_W, height: FW_H }}>Firewall</div>

                {boxes.map(b => {
                  const on = selZone === b.name
                  const hit = downZones?.has(b.name)
                  const dim = downZones ? !hit : (related && !related.has(b.name))
                  const sev = zoneSev.get(b.name)
                  return (
                    <div key={b.name} className={`dgm-zone${on ? ' on' : ''}${hit ? ' hit' : ''}${dim ? ' dim' : ''}`} style={{ left: b.x, top: b.y, width: b.w }}>
                      <button
                        className="dgm-zhead" aria-pressed={on} onMouseDown={noScrollFocus}
                        onClick={() => pickZone(on && !selIface ? null : b.name)} title={s.zoneRules(b.rules)}
                      >
                        {sev && <span className={`dot ${sev}`} role="img" aria-label={sevLabel[sev]} />}
                        <span className="dgm-zname">{b.name}</span>
                        <span className="dgm-zn">{b.rules}</span>
                      </button>
                      {b.kids.slice(0, 4).map(k => (
                        <button
                          key={k.name}
                          className={`dgm-kid${k.off ? ' off' : ''}${selIface === k.name ? ' on' : ''}${downIface === k.name ? ' down' : ''}`}
                          aria-pressed={selIface === k.name} onMouseDown={noScrollFocus}
                          onClick={() => pickIface(k.name, b.name)}
                          title={s.kidTitle}
                        >
                          <span className="dgm-kn">{k.name}{k.vlan ? ` · ${k.vlan}` : ''}</span>
                          {k.ip && <span className="dgm-kip">{k.ip}</span>}
                          {!k.ip && k.note && <span className="dgm-kip note">{k.note}</span>}
                        </button>
                      ))}
                      {b.tunnels && <div className="dgm-kmore mono">{b.tunnels}</div>}
                      {b.kids.length > 4 && <div className="dgm-kmore">{s.moreIfaces(b.kids.length - 4)}</div>}
                      {b.kids.length === 0 && <div className="dgm-kmore">{s.noIfaces}</div>}
                    </div>
                  )
                })}

              </div>
            </div>
          </div>
        </div>
      </div>

      <DetailPanel
        cfg={cfg} sel={sel} placed={{}} findings={findings}
        onClose={() => pickZone(null)} onSelect={onPanelSelect} onGo={onGo}
      />
    </div>
  )
}
