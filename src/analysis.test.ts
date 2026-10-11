import { describe, it, expect } from 'vitest'
import type { FirewallConfig, Rule } from './model'
import { ipToInt, toRange, rangesOf, rulesForAddress } from './derive'
import {
  simulate, zoneOfIp, exposure, servicePorts, natService, shadowedRules, wanZone,
  orphanObjects, impactOfDown,
} from './analysis'

// Minimal hand-built config: LAN 192.168.1.0/24, DMZ 10.0.0.0/24, external WAN.
const rule = (order: number, r: Partial<Rule>): Rule => ({
  order, name: `r${order}`, from: 'any', to: 'any', sourceIp: 'any', destIp: 'any',
  service: 'any', user: 'any', schedule: 'any', action: 'allow', enabled: true, ...r,
})

const cfg: FirewallConfig = {
  zones: [
    { name: 'LAN', interfaces: ['P11'] },
    { name: 'DMZ', interfaces: ['vlan16'] },
    { name: 'WAN', interfaces: ['wan1'] },
  ],
  interfaces: [
    { name: 'P11', kind: 'ethernet', enabled: true, role: 'internal', ip: '192.168.1.1/24' },
    { name: 'vlan16', kind: 'vlan', enabled: true, ip: '10.0.0.1/24' },
    { name: 'wan1', kind: 'ethernet', enabled: true, role: 'external', ip: '1.2.3.4/28' },
  ],
  addresses: {
    SERVER_11: { name: 'SERVER_11', type: 'host', value: '10.0.0.11' },
    RETE_LAN: { name: 'RETE_LAN', type: 'cidr', value: '192.168.1.0/24' },
  },
  addressGroups: { SERVERS: { name: 'SERVERS', members: ['SERVER_11'] } },
  services: {
    RDP: { name: 'RDP', proto: 'tcp', value: '3389' },
    WEB: { name: 'WEB', proto: 'tcp', value: '80,443' },
  },
  serviceGroups: { GRP_WEB: { name: 'GRP_WEB', members: ['WEB'] } },
  rules: [
    rule(0, { name: 'lan_web', from: 'LAN', to: 'WAN', service: 'WEB', action: 'allow' }),
    rule(1, { name: 'wan_rdp', from: 'WAN', to: 'DMZ', destIp: 'SERVER_11', service: 'RDP', action: 'allow' }),
    rule(2, { name: 'lan_web_dup', from: 'LAN', to: 'WAN', sourceIp: 'RETE_LAN', service: 'GRP_WEB', action: 'deny' }),
  ],
  vpns: [{ name: 'Sede1', enabled: true, localTs: ['10.0.0.0/24'], remoteTs: ['192.168.93.0/24'], policies: ['Sede1_sp1'] }],
  nats: [
    { name: 'NAT_RDP', enabled: true, iface: 'wan1', mapTo: 'SERVER_11', mapType: 'service original-service RDP mapped-service RDP' },
    { name: 'NAT_MORTO', enabled: true, iface: 'wan1', mapTo: 'RETE_LAN', mapType: 'service-group GRP_WEB' },
  ],
  routes: [],
  ifaceGroups: [{ name: 'WAN_Trunk', members: [{ name: 'wan1', passive: false }] }],
  defaultTrunk: 'WAN_Trunk',
}

describe('derive: IP arithmetic', () => {
  it('ipToInt and toRange', () => {
    expect(ipToInt('192.168.1.10')).toBe(192 * 256 ** 3 + 168 * 256 ** 2 + 256 + 10)
    expect(ipToInt('999.1.1.1')).toBeNull()
    expect(ipToInt('10.0.0.')).toBeNull()
    expect(ipToInt('1..2.3')).toBeNull()
    expect(toRange('host', '10.0.0.11')).toEqual([ipToInt('10.0.0.11'), ipToInt('10.0.0.11')])
    expect(toRange('cidr', '192.168.1.0/24')).toEqual([ipToInt('192.168.1.0'), ipToInt('192.168.1.255')])
    expect(toRange('range', '10.0.0.8-10.0.0.9')).toEqual([ipToInt('10.0.0.8'), ipToInt('10.0.0.9')])
  })

  it('rangesOf resolves groups', () => {
    const c = rangesOf(cfg, 'SERVERS')
    expect(c.ranges).toEqual([[ipToInt('10.0.0.11'), ipToInt('10.0.0.11')]])
  })

  it('rulesForAddress finds rules that reference a nested group', () => {
    const c: FirewallConfig = {
      ...cfg,
      addressGroups: { ...cfg.addressGroups, TUTTI: { name: 'TUTTI', members: ['SERVERS'] } },
      rules: [rule(0, { name: 'via_tutti', destIp: 'TUTTI' })],
    }
    expect(rulesForAddress(c, 'SERVER_11').map(r => r.name)).toEqual(['via_tutti'])
  })
})

describe('zoneOfIp', () => {
  it('classifies by interface subnet, tunnel and WAN fallback', () => {
    expect(zoneOfIp(cfg, ipToInt('192.168.1.50')!).zone).toBe('LAN')
    expect(zoneOfIp(cfg, ipToInt('10.0.0.11')!).zone).toBe('DMZ')
    expect(zoneOfIp(cfg, ipToInt('192.168.1.1')!).zone).toBe('ZyWALL') // firewall IP
    expect(zoneOfIp(cfg, ipToInt('8.8.8.8')!).zone).toBe('WAN')
  })
})

describe('simulate (first-match)', () => {
  it('allow from LAN to web', () => {
    const r = simulate(cfg, '192.168.1.50', '8.8.8.8', 'tcp', 443)
    expect(r.ok && r.verdict).toBe('allow')
    expect(r.ok && r.rule?.name).toBe('lan_web')
  })

  it('implicit default deny when no rule matches', () => {
    const r = simulate(cfg, '192.168.1.50', '8.8.8.8', 'tcp', 22)
    expect(r.ok && r.verdict).toBe('deny')
    expect(r.ok && r.rule).toBeNull()
  })

  it('matches on destination object and service', () => {
    const r = simulate(cfg, '8.8.8.8', '10.0.0.11', 'tcp', 3389)
    expect(r.ok && r.verdict).toBe('allow')
    expect(r.ok && r.rule?.name).toBe('wan_rdp')
    const miss = simulate(cfg, '8.8.8.8', '10.0.0.12', 'tcp', 3389)
    expect(miss.ok && miss.verdict).toBe('deny')
  })

  it('invalid IP → error', () => {
    const r = simulate(cfg, 'pippo', '8.8.8.8', 'icmp', 0)
    expect(r.ok).toBe(false)
  })
})

describe('WAN exposure', () => {
  it('wanZone from the default trunk', () => {
    expect(wanZone(cfg)).toBe('WAN')
  })

  it('natService extracts the service from map-type', () => {
    expect(natService('service original-service RDP mapped-service RDP')).toBe('RDP')
    expect(natService('service-group GRP_WEB')).toBe('GRP_WEB')
    expect(natService(undefined)).toBe('any')
  })

  it('servicePorts in readable form', () => {
    expect(servicePorts(cfg, 'WEB')).toBe('tcp/80, tcp/443')
    expect(servicePorts(cfg, 'any')).toBe('all ports')
  })

  it('links the NAT to its allow rule and flags sensitive ports', () => {
    const exp = exposure(cfg)
    const rdp = exp.nats.find(n => n.nat.name === 'NAT_RDP')!
    expect(rdp.allowRule?.name).toBe('wan_rdp')
    expect(rdp.risky).toBe(true) // 3389
    const morto = exp.nats.find(n => n.nat.name === 'NAT_MORTO')!
    expect(morto.allowRule).toBeNull() // no allow from the WAN covers RETE_LAN
    expect(exp.rules.map(x => x.rule.name)).toEqual(['wan_rdp'])
  })
})

describe('shadowedRules', () => {
  it('detects a rule shadowed by an earlier one with a different action (conflict)', () => {
    const s = shadowedRules(cfg)
    expect(s).toHaveLength(1)
    expect(s[0].rule.name).toBe('lan_web_dup')
    expect(s[0].by.name).toBe('lan_web')
    expect(s[0].kind).toBe('conflitto')
  })
})

describe('orphanObjects', () => {
  it('a service used only by a NAT is not orphaned', () => {
    const c: FirewallConfig = {
      ...cfg,
      services: { ...cfg.services, SSH: { name: 'SSH', proto: 'tcp', value: '22' }, FTP: { name: 'FTP', proto: 'tcp', value: '21' } },
      nats: [...cfg.nats, { name: 'NAT_SSH', enabled: true, mapTo: 'SERVER_11', mapType: 'service original-service SSH mapped-service SSH' }],
    }
    const o = orphanObjects(c)
    expect(o.services).not.toContain('SSH')
    expect(o.services).toContain('FTP')
  })
})

describe('WAN exposure: NAT coverage', () => {
  it('does not count a rule to the firewall or on another service as coverage', () => {
    const c: FirewallConfig = {
      ...cfg,
      rules: [
        rule(0, { name: 'wan_mgmt', from: 'WAN', to: 'ZyWALL', service: 'any' }),
        rule(1, { name: 'wan_web', from: 'WAN', to: 'DMZ', destIp: 'SERVER_11', service: 'WEB' }),
      ],
    }
    const rdp = exposure(c).nats.find(n => n.nat.name === 'NAT_RDP')!
    expect(rdp.allowRule).toBeNull()
  })
})

describe('impactOfDown: tunnel', () => {
  it('matches the next-hop by security-policy name, not by substring', () => {
    const c: FirewallConfig = {
      ...cfg,
      vpns: [
        ...cfg.vpns,
        { name: 'Sede10', enabled: true, localTs: [], remoteTs: [], policies: ['Sede10_sp1'] },
      ],
      routes: [{
        order: 0, name: 'to_sede10', enabled: true, from: 'LAN', source: 'any',
        destination: 'any', service: 'any', nextHopType: 'ipsec-vpn', nextHop: 'Sede10_sp1',
      }],
    }
    const routeItems = (vpn: string) => impactOfDown(c, 'vpn', vpn).items.filter(i => i.label.includes('to_sede10'))
    expect(routeItems('Sede1')).toHaveLength(0)
    expect(routeItems('Sede10')).toHaveLength(1)
  })
})
