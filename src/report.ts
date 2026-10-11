import type { FirewallConfig } from './model'
import { ifaceZoneMap, resolveAddr } from './derive'
import { exposure, orphanObjects } from './analysis'
import { lang, loc } from './i18n'

const s = loc({
  en: {
    yes: 'yes',
    riskyPort: 'sensitive port',
    anyDest: 'any destination',
    title: 'Firewall report',
    print: 'Print / save as PDF',
    generated: (date: string) => `generated on ${date}`,
    zones: 'zones', rules: 'rules', vpnTunnels: 'VPN tunnels', routes: 'policy routes',
    addresses: 'address objects', exposed: 'exposed services',
    expoNat: (wan: string) => `Exposure to the Internet · NAT virtual servers (zone ${wan})`,
    expoRules: (wan: string) => `Exposure to the Internet · allow rules with source ${wan} / any`,
    internalHost: 'Internal host', service: 'Service', ports: 'Ports', publishedOn: 'Published on',
    allowRule: 'Allow rule', risk: 'Risk', name: 'Name',
    zonesTitle: 'Zones', zone: 'Zone', description: 'Description', interfaces: 'Interfaces',
    type: 'Type',
    rulesTitle: 'Secure policy rules (in evaluation order)', action: 'Action',
    natTitle: 'NAT / virtual servers', iface: 'Interface', originalIp: 'Original IP', mappedTo: 'Mapped to',
    vpnTitle: 'IPsec VPN tunnels', remotePeer: 'Remote peer', localSubnets: 'Local subnets', remoteSubnets: 'Remote subnets',
    routesTitle: 'Policy routes (in evaluation order)',
    orphansTitle: 'Orphan objects (never referenced by rules, NAT or policy routes)',
    addressObjects: 'Address objects', addressGroups: 'Address groups', services: 'Services', serviceGroups: 'Service groups',
  },
  it: {
    yes: 'sì',
    riskyPort: 'porta sensibile',
    anyDest: 'destinazione any',
    title: 'Report firewall',
    print: 'Stampa / salva PDF',
    generated: (date: string) => `generato il ${date}`,
    zones: 'zone', rules: 'regole', vpnTunnels: 'tunnel VPN', routes: 'policy route',
    addresses: 'address object', exposed: 'servizi esposti',
    expoNat: (wan: string) => `Esposizione verso Internet · NAT virtual-server (zona ${wan})`,
    expoRules: (wan: string) => `Esposizione verso Internet · regole allow con sorgente ${wan} / any`,
    internalHost: 'Host interno', service: 'Servizio', ports: 'Porte', publishedOn: 'Pubblicato su',
    allowRule: 'Regola allow', risk: 'Rischio', name: 'Nome',
    zonesTitle: 'Zone', zone: 'Zona', description: 'Descrizione', interfaces: 'Interfacce',
    type: 'Tipo',
    rulesTitle: 'Regole secure-policy (in ordine di valutazione)', action: 'Azione',
    natTitle: 'NAT / virtual server', iface: 'Interfaccia', originalIp: 'IP originale', mappedTo: 'Mappato su',
    vpnTitle: 'Tunnel VPN IPsec', remotePeer: 'Peer remoto', localSubnets: 'Subnet locali', remoteSubnets: 'Subnet remote',
    routesTitle: 'Policy route (in ordine di valutazione)',
    orphansTitle: 'Oggetti orfani (mai citati da regole, NAT o policy-route)',
    addressObjects: 'Address object', addressGroups: 'Gruppi address', services: 'Servizi', serviceGroups: 'Gruppi servizi',
  },
})

const yesNo = (on: boolean) => (on ? s.yes : 'no')

const esc = (x: string) =>
  x.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')

// Standalone HTML report, meant for printing (Ctrl+P → PDF).
export function buildReport(cfg: FirewallConfig, filename: string): string {
  const ifZone = ifaceZoneMap(cfg)
  const date = new Date().toLocaleDateString(lang, { day: '2-digit', month: 'long', year: 'numeric' })

  const zoneRows = cfg.zones.map(z => {
    const ifs = z.interfaces.map(n => {
      const i = cfg.interfaces.find(x => x.name === n)
      return `${esc(n)}${i?.ip ? ` (${esc(i.ip)})` : ''}`
    }).join(', ')
    return `<tr><td><b>${esc(z.name)}</b></td><td>${esc(z.description ?? '')}</td><td>${ifs}</td></tr>`
  }).join('')

  const ruleRows = cfg.rules.map(r => `
    <tr class="${r.enabled ? '' : 'off'}">
      <td>${r.order + 1}</td><td>${esc(r.name)}</td>
      <td>${esc(r.from)} → ${esc(r.to)}</td>
      <td>${esc(r.sourceIp)} → ${esc(r.destIp)}</td>
      <td>${esc(r.service)}</td><td>${esc(r.user)}</td>
      <td class="${r.action}">${r.action}</td><td>${yesNo(r.enabled)}</td>
    </tr>`).join('')

  const natRows = cfg.nats.map(n => `
    <tr class="${n.enabled ? '' : 'off'}">
      <td>${esc(n.name)}</td><td>${esc(n.iface ?? '')}</td>
      <td>${esc(n.originalIp ?? '')}</td><td>${esc(n.mapTo ?? '')}</td>
      <td>${esc(n.mapType ?? '')}</td><td>${yesNo(n.enabled)}</td>
    </tr>`).join('')

  const vpnRows = [...cfg.vpns].sort((a, b) => a.name.localeCompare(b.name)).map(v => `
    <tr class="${v.enabled ? '' : 'off'}">
      <td>${esc(v.name)}</td><td>${esc(v.remoteAddress ?? '')}</td>
      <td>${esc(v.localTs.join(', '))}</td><td>${esc(v.remoteTs.join(', '))}</td>
      <td>${yesNo(v.enabled)}</td>
    </tr>`).join('')

  const routeRows = cfg.routes.map(r => `
    <tr class="${r.enabled ? '' : 'off'}">
      <td>${r.order + 1}</td><td>${esc(r.name)}</td><td>${esc(r.from)}</td>
      <td>${esc(r.source)} → ${esc(r.destination)}</td><td>${esc(r.service)}</td>
      <td>${esc(r.nextHopType ?? '')} ${esc(r.nextHop ?? '')}</td><td>${yesNo(r.enabled)}</td>
    </tr>`).join('')

  const exp = exposure(cfg)
  const expoRows = exp.nats.map(x => `
    <tr>
      <td><b>${esc(x.nat.mapTo ?? '')}</b> ${esc(resolveAddr(cfg, x.nat.mapTo!))}</td>
      <td>${esc(x.service)}</td><td>${esc(x.ports)}</td>
      <td>${esc(x.nat.iface ?? '')}${x.nat.originalIp ? ` · ${esc(x.nat.originalIp)}` : ''}</td>
      <td>${esc(x.nat.name)}</td>
      <td>${x.allowRule ? `#${x.allowRule.order + 1} ${esc(x.allowRule.name)}` : '–'}</td>
      <td class="${x.risky ? 'deny' : ''}">${x.risky ? s.riskyPort : ''}</td>
    </tr>`).join('')
  const expoRuleRows = exp.rules.map(({ rule: r, ports, risky }) => `
    <tr>
      <td>${r.order + 1}</td><td>${esc(r.name)}</td>
      <td>${esc(r.from)} → ${esc(r.to)}</td>
      <td>${esc(r.sourceIp)} → ${esc(r.destIp)}</td>
      <td>${esc(ports)}</td>
      <td class="${risky ? 'deny' : ''}">${risky ? (r.destIp === 'any' ? s.anyDest : s.riskyPort) : ''}</td>
    </tr>`).join('')

  const orphans = orphanObjects(cfg)
  const orphanList = (title: string, names: string[]) =>
    names.length === 0 ? '' : `<p><b>${title} (${names.length}):</b> ${names.map(esc).join(', ')}</p>`

  const ifaceRows = cfg.interfaces.filter(i => ifZone[i.name]).map(i => `
    <tr class="${i.enabled ? '' : 'off'}">
      <td>${esc(i.name)}</td><td>${esc(i.kind)}</td><td>${i.vlanId ?? ''}</td>
      <td>${esc(i.ip ?? '')}</td><td>${esc(ifZone[i.name])}</td>
      <td>${esc(i.description ?? '')}</td>
    </tr>`).join('')

  return `<!doctype html>
<html lang="${lang}"><head><meta charset="utf-8">
<title>${s.title}: ${esc(filename)}</title>
<style>
  body { font-family: 'Segoe UI', system-ui, sans-serif; font-size: 12px; color: #1c2733; margin: 32px; }
  h1 { font-size: 22px; margin: 0 0 2px; }
  .sub { color: #5a6572; margin-bottom: 20px; }
  h2 { font-size: 15px; margin: 26px 0 8px; border-bottom: 2px solid #1c2733; padding-bottom: 3px; }
  table { border-collapse: collapse; width: 100%; font-size: 10.5px; }
  th { text-align: left; background: #eceade; padding: 4px 7px; border: 1px solid #c9c4b4; }
  td { padding: 3px 7px; border: 1px solid #d9d4c4; vertical-align: top; }
  tr.off td { color: #999; }
  td.allow { color: #1e8f5e; font-weight: 600; }
  td.deny { color: #c23b3b; font-weight: 600; }
  .stats { display: flex; gap: 26px; margin: 14px 0; }
  .stats div { font-size: 11px; color: #5a6572; }
  .stats b { display: block; font-size: 19px; color: #1c2733; }
  .noprint { margin: 0 0 18px; }
  @media print { .noprint { display: none; } h2 { break-after: avoid; } tr { break-inside: avoid; } }
</style></head><body>
<div class="noprint"><button onclick="print()" style="padding:8px 16px;font-size:13px;cursor:pointer">${s.print}</button></div>
<h1>${s.title}</h1>
<div class="sub">${esc(filename)} · ${s.generated(date)} · Config Explorer</div>
<div class="stats">
  <div><b>${cfg.zones.length}</b> ${s.zones}</div>
  <div><b>${cfg.rules.length}</b> ${s.rules}</div>
  <div><b>${cfg.nats.length}</b> NAT</div>
  <div><b>${cfg.vpns.length}</b> ${s.vpnTunnels}</div>
  <div><b>${cfg.routes.length}</b> ${s.routes}</div>
  <div><b>${Object.keys(cfg.addresses).length}</b> ${s.addresses}</div>
  <div><b>${exp.nats.length}</b> ${s.exposed}</div>
</div>
<h2>${s.expoNat(esc(exp.wan))}</h2>
<table><tr><th>${s.internalHost}</th><th>${s.service}</th><th>${s.ports}</th><th>${s.publishedOn}</th><th>NAT</th><th>${s.allowRule}</th><th>${s.risk}</th></tr>${expoRows}</table>
<h2>${s.expoRules(esc(exp.wan))}</h2>
<table><tr><th>#</th><th>${s.name}</th><th>From → To</th><th>Source → Destination</th><th>${s.ports}</th><th>${s.risk}</th></tr>${expoRuleRows}</table>
<h2>${s.zonesTitle}</h2>
<table><tr><th>${s.zone}</th><th>${s.description}</th><th>${s.interfaces}</th></tr>${zoneRows}</table>
<h2>${s.interfaces}</h2>
<table><tr><th>${s.name}</th><th>${s.type}</th><th>VLAN</th><th>IP</th><th>${s.zone}</th><th>${s.description}</th></tr>${ifaceRows}</table>
<h2>${s.rulesTitle}</h2>
<table><tr><th>#</th><th>${s.name}</th><th>From → To</th><th>Source → Destination</th><th>Service</th><th>User</th><th>${s.action}</th><th>On</th></tr>${ruleRows}</table>
<h2>${s.natTitle}</h2>
<table><tr><th>${s.name}</th><th>${s.iface}</th><th>${s.originalIp}</th><th>${s.mappedTo}</th><th>${s.service}</th><th>On</th></tr>${natRows}</table>
<h2>${s.vpnTitle}</h2>
<table><tr><th>${s.name}</th><th>${s.remotePeer}</th><th>${s.localSubnets}</th><th>${s.remoteSubnets}</th><th>On</th></tr>${vpnRows}</table>
<h2>${s.routesTitle}</h2>
<table><tr><th>#</th><th>${s.name}</th><th>From</th><th>Source → Destination</th><th>Service</th><th>Next-hop</th><th>On</th></tr>${routeRows}</table>
<h2>${s.orphansTitle}</h2>
${orphanList(s.addressObjects, orphans.addresses)}
${orphanList(s.addressGroups, orphans.addressGroups)}
${orphanList(s.services, orphans.services)}
${orphanList(s.serviceGroups, orphans.serviceGroups)}
</body></html>`
}
