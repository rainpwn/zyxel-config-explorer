import { useMemo } from 'react'
import type { FirewallConfig } from '../model'
import { toRange, coversIp, ifaceZoneMap, rulesForIp } from '../derive'
import { loc } from '../i18n'

const s = loc({
  en: {
    ifaces: 'Subnets / interfaces',
    noIface: 'not in any local subnet',
    objects: 'Address objects',
    noObject: 'not in any object',
    more: (n: number) => `… and ${n} more`,
    moreF: (n: number) => `… and ${n} more`,
    rules: 'Rules that reference it',
    noRule: 'none (apart from rules with any)',
    routes: 'Policy routes',
    noRoute: 'none explicitly',
    vpns: 'VPN tunnels',
    noVpn: 'not in any remote subnet',
  },
  it: {
    ifaces: 'Subnet / interfacce',
    noIface: 'nessuna subnet locale lo contiene',
    objects: 'Address object',
    noObject: 'nessun oggetto lo contiene',
    more: (n: number) => `… e altri ${n}`,
    moreF: (n: number) => n === 1 ? '… e un\'altra' : `… e altre ${n}`,
    rules: 'Regole che lo citano',
    noRule: 'nessuna (oltre alle regole con any)',
    routes: 'Policy route',
    noRoute: 'nessuna esplicita',
    vpns: 'Tunnel VPN',
    noVpn: 'nessuna subnet remota lo contiene',
  },
})

// Where an IP appears across the config. The palette (Ctrl+K) shows this
// when the input is a full IPv4, so there is a single search field.
export default function IpSearch({ cfg, ip }: { cfg: FirewallConfig; ip: number }) {
  const results = useMemo(() => {
    const ifZone = ifaceZoneMap(cfg)
    const ifaces = cfg.interfaces.filter(i => {
      if (!i.ip) return false
      const r = toRange('cidr', i.ip)
      return r !== null && ip >= r[0] && ip <= r[1]
    }).map(i => `${i.name} · ${i.ip}${ifZone[i.name] ? ` (${ifZone[i.name]})` : ''}`)
    const objects = Object.values(cfg.addresses)
      .filter(a => coversIp(cfg, a.name, ip))
      .map(a => `${a.name} · ${a.type} ${a.value}`)
    const rules = rulesForIp(cfg, ip)
    const routes = cfg.routes.filter(r => {
      const inSide = (n: string) => n !== 'any' && coversIp(cfg, n, ip)
      return inSide(r.source) || inSide(r.destination)
    })
    const vpns = cfg.vpns.filter(v => v.remoteTs.some(ts => {
      if (ts.endsWith('/0')) return false
      const r = toRange('cidr', ts)
      return r !== null && ip >= r[0] && ip <= r[1]
    })).map(v => `${v.name} · ${v.remoteTs.join(', ')}`)
    return { ifaces, objects, rules, routes, vpns }
  }, [cfg, ip])

  return (
    <div className="ipresults">
      <h4>{s.ifaces} ({results.ifaces.length})</h4>
      {results.ifaces.length === 0 && <div className="none">{s.noIface}</div>}
      {results.ifaces.map(x => <div key={x}>{x}</div>)}

      <h4>{s.objects} ({results.objects.length})</h4>
      {results.objects.length === 0 && <div className="none">{s.noObject}</div>}
      {results.objects.slice(0, 15).map(x => <div key={x}>{x}</div>)}
      {results.objects.length > 15 && <div className="none">{s.more(results.objects.length - 15)}</div>}

      <h4>{s.rules} ({results.rules.length})</h4>
      {results.rules.slice(0, 12).map(r => (
        <div key={r.name}>#{r.order + 1} {r.name} · {r.from}→{r.to}</div>
      ))}
      {results.rules.length > 12 && <div className="none">{s.moreF(results.rules.length - 12)}</div>}
      {results.rules.length === 0 && <div className="none">{s.noRule}</div>}

      <h4>{s.routes} ({results.routes.length})</h4>
      {results.routes.slice(0, 8).map(r => (
        <div key={r.name}>{r.name} → {r.nextHopType} {r.nextHop}</div>
      ))}
      {results.routes.length > 8 && <div className="none">{s.moreF(results.routes.length - 8)}</div>}
      {results.routes.length === 0 && <div className="none">{s.noRoute}</div>}

      <h4>{s.vpns} ({results.vpns.length})</h4>
      {results.vpns.map(x => <div key={x}>{x}</div>)}
      {results.vpns.length === 0 && <div className="none">{s.noVpn}</div>}
    </div>
  )
}
