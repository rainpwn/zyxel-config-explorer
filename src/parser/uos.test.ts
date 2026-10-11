import { describe, it, expect } from 'vitest'
import { parseUos } from './uos'

// Synthetic fixture in the real Zyxel uOS format (one property per line).
const CONF = `
/ object zone-object zone "LAN"
/ object zone-object zone "LAN" "description" "Rete interna"
/ object zone-object zone "LAN" interface-list "ethernet" "P11"
/ object zone-object zone "WAN"
/ object zone-object zone "WAN" interface-list "ethernet" "wan1"
/ object zone-object zone "DMZ"
/ object zone-object zone "DMZ" interface-list "vlan" "vlan16"
/ object address-object address "SERVER_11" "type" "host" "10.0.0.11"
/ object address-object address "RETE_LAN" "type" "cidr" "192.168.1.0/24"
/ object address-object address "CONSOLE" "type" "range" "10.0.0.8-10.0.0.9"
/ object address-object address "ORFANO" "type" "host" "10.9.9.9"
/ object address-object group "SERVERS"
/ object address-object group "SERVERS" "address-list" "SERVER_11"
/ object address-object address "DC01" "description" "Domain Controller" "type" "host" "10.0.0.20"
/ object address-object address "RELAY" "type" "host" "192.88.99.1" "description" "Relay"
/ object address-object address "LAN1_SUBNET" "description" "type" "type" "interface-subnet" "P11" "vrf" "main"
/ object address-object group "ALL_SRV"
/ object address-object group "ALL_SRV" "group-list" "SERVERS"
/ object service-object service "API" "description" "API negozi" "type" "tcp" "8100"
/ object service-object group "GRP_ALL"
/ object service-object group "GRP_ALL" "group-list" "GRP_WEB"
/ object service-object service "RDP" "type" "tcp" "3389"
/ object service-object service "WEB" "type" "tcp" "80,443"
/ object service-object service "PING" "type" "icmp" "8"
/ object service-object group "GRP_WEB"
/ object service-object group "GRP_WEB" "service-list" "WEB"
/ vrf "main" interface ethernet "P11"
/ vrf "main" interface ethernet "P11" "enabled" "true"
/ vrf "main" interface ethernet "P11" "type" "internal"
/ vrf "main" interface ethernet "P11" ipv4 address "192.168.1.1/24"
/ vrf "main" interface ethernet "wan1"
/ vrf "main" interface ethernet "wan1" "type" "external"
/ vrf "main" interface ethernet "wan1" ipv4 address "1.2.3.4/28"
/ vrf "main" interface vlan "vlan16"
/ vrf "main" interface vlan "vlan16" "vlan-id" "16"
/ vrf "main" interface vlan "vlan16" ipv4 address "10.0.0.1/24"
/ vrf "main" secure-policy rule "LAN_out"
/ vrf "main" secure-policy rule "LAN_out" "from" "LAN"
/ vrf "main" secure-policy rule "LAN_out" "to" "WAN"
/ vrf "main" secure-policy rule "LAN_out" "source-ip" "any"
/ vrf "main" secure-policy rule "LAN_out" "destination-ip" "any"
/ vrf "main" secure-policy rule "LAN_out" "service" "any"
/ vrf "main" secure-policy rule "LAN_out" "user" "any"
/ vrf "main" secure-policy rule "LAN_out" "schedule" "any"
/ vrf "main" secure-policy rule "LAN_out" "action" "allow"
/ vrf "main" secure-policy rule "LAN_out" "enabled" "true"
/ vrf "main" secure-policy rule "WAN_rdp"
/ vrf "main" secure-policy rule "WAN_rdp" "from" "WAN"
/ vrf "main" secure-policy rule "WAN_rdp" "to" "DMZ"
/ vrf "main" secure-policy rule "WAN_rdp" "source-ip" "any"
/ vrf "main" secure-policy rule "WAN_rdp" "destination-ip" "SERVER_11"
/ vrf "main" secure-policy rule "WAN_rdp" "service" "RDP"
/ vrf "main" secure-policy rule "WAN_rdp" "user" "any"
/ vrf "main" secure-policy rule "WAN_rdp" "schedule" "any"
/ vrf "main" secure-policy rule "WAN_rdp" "action" "allow"
/ vrf "main" secure-policy rule "WAN_rdp" "enabled" "true"
/ vrf "main" secure-policy rule "LAN_out_dup"
/ vrf "main" secure-policy rule "LAN_out_dup" "from" "LAN"
/ vrf "main" secure-policy rule "LAN_out_dup" "to" "WAN"
/ vrf "main" secure-policy rule "LAN_out_dup" "source-ip" "RETE_LAN"
/ vrf "main" secure-policy rule "LAN_out_dup" "destination-ip" "any"
/ vrf "main" secure-policy rule "LAN_out_dup" "service" "WEB"
/ vrf "main" secure-policy rule "LAN_out_dup" "user" "any"
/ vrf "main" secure-policy rule "LAN_out_dup" "schedule" "any"
/ vrf "main" secure-policy rule "LAN_out_dup" "action" "deny"
/ vrf "main" secure-policy rule "LAN_out_dup" "enabled" "true"
/ vrf "main" ike vpn "Sede1"
/ vrf "main" ike vpn "Sede1" "enabled" "true"
/ vrf "main" ike vpn "Sede1" "remote-address" "sede1.example.org"
/ vrf "main" ike vpn "Sede1" "authentication" "psk" "SEGRETISSIMO"
/ vrf "main" ike vpn "Sede1" security-policy "sp1" local-ts "subnet" "10.0.0.0/24"
/ vrf "main" ike vpn "Sede1" security-policy "sp1" remote-ts "subnet" "192.168.93.0/24"
/ vrf "main" virtual-server rule "NAT_RDP"
/ vrf "main" virtual-server rule "NAT_RDP" "enabled" "true"
/ vrf "main" virtual-server rule "NAT_RDP" "interface" "wan1"
/ vrf "main" virtual-server rule "NAT_RDP" original-ip "object" "CONSOLE"
/ vrf "main" virtual-server rule "NAT_RDP" map-to "object" "SERVER_11"
/ vrf "main" virtual-server rule "NAT_RDP" map-type "service" "original-service" "RDP" "mapped-service" "RDP"
/ vrf "main" routing policy-route rule "RottaSede1"
/ vrf "main" routing policy-route rule "RottaSede1" "enabled" "true"
/ vrf "main" routing policy-route rule "RottaSede1" match "from" "any"
/ vrf "main" routing policy-route rule "RottaSede1" match "source" "SERVERS"
/ vrf "main" routing policy-route rule "RottaSede1" match "destination" "any"
/ vrf "main" routing policy-route rule "RottaSede1" action "next-hop" "ipsec-vpn" "sp1"
/ vrf "main" interface-group "WAN_Trunk"
/ vrf "main" interface-group "WAN_Trunk" interface "wan1"
/ vrf "main" system default-interface-group "name" "WAN_Trunk"
`

describe('parseUos', () => {
  const cfg = parseUos(CONF)

  it('extracts zones with description and interfaces', () => {
    expect(cfg.zones.map(z => z.name)).toEqual(['LAN', 'WAN', 'DMZ'])
    const lan = cfg.zones.find(z => z.name === 'LAN')!
    expect(lan.description).toBe('Rete interna')
    expect(lan.interfaces).toEqual(['P11'])
  })

  it('extracts interfaces with ip, role and vlan', () => {
    const p11 = cfg.interfaces.find(i => i.name === 'P11')!
    expect(p11.ip).toBe('192.168.1.1/24')
    expect(p11.role).toBe('internal')
    const vlan = cfg.interfaces.find(i => i.name === 'vlan16')!
    expect(vlan.vlanId).toBe(16)
  })

  it('extracts address objects, groups and services', () => {
    expect(cfg.addresses['SERVER_11']).toMatchObject({ type: 'host', value: '10.0.0.11' })
    expect(cfg.addresses['CONSOLE']).toMatchObject({ type: 'range', value: '10.0.0.8-10.0.0.9' })
    expect(cfg.addressGroups['SERVERS'].members).toEqual(['SERVER_11'])
    expect(cfg.services['WEB']).toMatchObject({ proto: 'tcp', value: '80,443' })
    expect(cfg.serviceGroups['GRP_WEB'].members).toEqual(['WEB'])
  })

  it('reads object properties in any order, with nested groups', () => {
    expect(cfg.addresses['DC01']).toMatchObject({ type: 'host', value: '10.0.0.20', description: 'Domain Controller' })
    expect(cfg.addresses['RELAY']).toMatchObject({ type: 'host', value: '192.88.99.1', description: 'Relay' })
    expect(cfg.addresses['LAN1_SUBNET']).toMatchObject({ type: 'interface-subnet', value: 'P11', description: 'type' })
    expect(cfg.addressGroups['ALL_SRV'].members).toEqual(['SERVERS'])
    expect(cfg.services['API']).toMatchObject({ proto: 'tcp', value: '8100' })
    expect(cfg.serviceGroups['GRP_ALL'].members).toEqual(['GRP_WEB'])
  })

  it('extracts rules in definition order', () => {
    expect(cfg.rules.map(r => r.name)).toEqual(['LAN_out', 'WAN_rdp', 'LAN_out_dup'])
    expect(cfg.rules[1]).toMatchObject({
      from: 'WAN', to: 'DMZ', destIp: 'SERVER_11', service: 'RDP', action: 'allow', enabled: true,
    })
  })

  it('extracts VPNs with traffic selectors', () => {
    const v = cfg.vpns[0]
    expect(v.name).toBe('Sede1')
    expect(v.remoteAddress).toBe('sede1.example.org')
    expect(v.localTs).toEqual(['10.0.0.0/24'])
    expect(v.remoteTs).toEqual(['192.168.93.0/24'])
    expect(v.policies).toEqual(['sp1'])
  })

  it('extracts NAT and policy routes', () => {
    expect(cfg.nats[0]).toMatchObject({
      name: 'NAT_RDP', iface: 'wan1', originalIp: 'CONSOLE', mapTo: 'SERVER_11',
    })
    expect(cfg.routes[0]).toMatchObject({
      name: 'RottaSede1', source: 'SERVERS', nextHopType: 'ipsec-vpn', nextHop: 'sp1',
    })
    expect(cfg.defaultTrunk).toBe('WAN_Trunk')
    expect(cfg.ifaceGroups[0].members.map(m => m.name)).toEqual(['wan1'])
  })

  it('never extracts secrets (psk)', () => {
    expect(JSON.stringify(cfg)).not.toContain('SEGRETISSIMO')
  })
})
