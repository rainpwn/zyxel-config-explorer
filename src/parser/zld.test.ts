import { describe, it, expect } from 'vitest'
import { parseZld } from './zld'
import { parseConfig } from '.'

// Synthetic fixture in the real Zyxel ZLD format (CLI blocks, CRLF like the device).
const CONF = `! saved at 2025-01-01 00:00:00
! model: ATP700
!
interface-name ge1 wan1
interface wan1
 type external
 description Fibra
 ip address dhcp metric 0
interface ge2
 type external
 ip address dhcp metric 0
 shutdown
interface ge2_ppp
 account GE2_PPPOE_ACCOUNT
interface ge4
 ip address 192.168.1.1 255.255.255.0
 type internal
 description LAN
interface vlan16
 port ge4
 vlan-id 16
 ip address 10.0.0.1 255.255.255.0
 type internal
interface wan1:1
 ip address 1.2.3.5 255.255.255.255
interface vti1
 no shutdown
 ip address 10.100.100.2 255.255.255.252
!
address-object SERVER_11 10.0.0.11
address-object RETE_LAN 192.168.1.0/24
address-object CONSOLE 10.0.0.8-10.0.0.9
address-object REMOTE_NET 192.168.93.0 255.255.255.0
address-object LAN_SUBNET interface-subnet ge4
address-object DDNS fqdn sede.example.org
object-group address SERVERS
 description Server DMZ
 address-object SERVER_11
!
service-object RDP tcp eq 3389
service-object NETBIOS udp range 137 139
service-object PING icmp echo
service-object GRE protocol 47
service-object PING6 icmpv6 echo-request
object-group service GRP_WEB
 service-object RDP
 object-group GRP_NB
!
zone LAN
 interface ge4
zone WAN
 interface wan1
 interface ge2
 interface ge2_ppp
zone DMZ
 interface vlan16
zone IPSec_VPN
 crypto Sede1
 interface vti1
!
secure-policy 2
 name WAN_rdp
 from WAN
 to DMZ
 destinationip SERVER_11
 service RDP
 log alert
 action allow
secure-policy 1
 name LAN_out
 from LAN
 to WAN
 action allow
secure-policy 3
 name Blocked
 from LAN
 sourceip RETE_LAN
 action deny
 no activate
secure-policy default-rule action deny no log
secure-policy6 1
 name V6_rule
 action allow
!
interface-group WAN_Trunk
 algorithm llf
 interface 1 wan1
 interface 2 ge2 passive
system default-interface-group WAN_Trunk
!
policy 1
 source SERVERS
 destination REMOTE_NET
 dscp any
 next-hop tunnel Sede1
policy 2
 interface ge4
 next-hop trunk WAN_Trunk
 snat outgoing-interface
!
ip virtual-server NAT_RDP interface wan1 source-ip any original-ip any map-to SERVER_11 map-type port protocol tcp original-port 3389 mapped-port 3389 deactivate
!
isakmp policy Sede1
 activate
 peer-ip sede1.example.org 0.0.0.0
 authentication pre-share
 keystring SEGRETISSIMO
 encrypted-keystring Q2lhb0NpYW8=
 local-id type ip 0.0.0.0
crypto map Sede1
 ipsec-isakmp Sede1
 activate
 scenario site-to-site-static
 local-policy RETE_LAN
 remote-policy REMOTE_NET
username admin encrypted-password $4$HASHHASH$ user-type admin
`.replace(/\n/g, '\r\n')

describe('parseZld', () => {
  const cfg = parseZld(CONF)

  it('extracts interfaces with ip, role, vlan and state', () => {
    expect(cfg.interfaces.map(i => i.name)).toEqual(['wan1', 'ge2', 'ge4', 'vlan16', 'wan1:1', 'vti1'])
    expect(cfg.interfaces.find(i => i.name === 'wan1:1')).toMatchObject({ kind: 'alias', ip: '1.2.3.5/32' })
    expect(cfg.interfaces.find(i => i.name === 'ge4')).toMatchObject({
      kind: 'ethernet', ip: '192.168.1.1/24', role: 'internal', enabled: true, description: 'LAN',
    })
    expect(cfg.interfaces.find(i => i.name === 'vlan16')).toMatchObject({ kind: 'vlan', vlanId: 16, link: 'ge4', ip: '10.0.0.1/24' })
    expect(cfg.interfaces.find(i => i.name === 'ge2')!.enabled).toBe(false)
    expect(cfg.interfaces.find(i => i.name === 'wan1')!.ip).toBeUndefined()
    expect(cfg.interfaces.find(i => i.name === 'vti1')).toMatchObject({ kind: 'vti', ip: '10.100.100.2/30' })
  })

  it('extracts zones with their interfaces', () => {
    expect(cfg.zones.map(z => z.name)).toEqual(['LAN', 'WAN', 'DMZ', 'IPSec_VPN'])
    expect(cfg.zones.find(z => z.name === 'WAN')!.interfaces).toEqual(['wan1', 'ge2'])
    expect(cfg.zones.find(z => z.name === 'IPSec_VPN')!.interfaces).toEqual(['vti1'])
  })

  it('extracts address and service objects in the uOS shapes', () => {
    expect(cfg.addresses['SERVER_11']).toMatchObject({ type: 'host', value: '10.0.0.11' })
    expect(cfg.addresses['RETE_LAN']).toMatchObject({ type: 'cidr', value: '192.168.1.0/24' })
    expect(cfg.addresses['CONSOLE']).toMatchObject({ type: 'range', value: '10.0.0.8-10.0.0.9' })
    expect(cfg.addresses['REMOTE_NET']).toMatchObject({ type: 'cidr', value: '192.168.93.0/24' })
    expect(cfg.addresses['LAN_SUBNET']).toMatchObject({ type: 'interface-subnet', value: 'ge4' })
    expect(cfg.addresses['DDNS']).toMatchObject({ type: 'fqdn', value: 'sede.example.org' })
    expect(cfg.addressGroups['SERVERS']).toMatchObject({ members: ['SERVER_11'], description: 'Server DMZ' })
    expect(cfg.services['RDP']).toMatchObject({ proto: 'tcp', value: '3389' })
    expect(cfg.services['NETBIOS']).toMatchObject({ proto: 'udp', value: '137-139' })
    expect(cfg.services['GRE']).toMatchObject({ proto: 'protocol', value: '47' })
    expect(cfg.services['PING6'].proto).toBe('icmp6')
    expect(cfg.serviceGroups['GRP_WEB'].members).toEqual(['RDP', 'GRP_NB'])
  })

  it('extracts IPv4 rules in priority order with defaults', () => {
    expect(cfg.rules.map(r => r.name)).toEqual(['LAN_out', 'WAN_rdp', 'Blocked'])
    expect(cfg.rules.map(r => r.order)).toEqual([0, 1, 2])
    expect(cfg.rules[0]).toMatchObject({ sourceIp: 'any', destIp: 'any', service: 'any', enabled: true })
    expect(cfg.rules[1]).toMatchObject({ from: 'WAN', to: 'DMZ', destIp: 'SERVER_11', service: 'RDP', action: 'allow', logging: 'alert' })
    expect(cfg.rules[2]).toMatchObject({ to: 'any', action: 'deny', enabled: false })
  })

  it('extracts trunks, policy routes and NAT', () => {
    expect(cfg.defaultTrunk).toBe('WAN_Trunk')
    expect(cfg.ifaceGroups[0].members).toEqual([{ name: 'wan1', passive: false }, { name: 'ge2', passive: true }])
    expect(cfg.routes[0]).toMatchObject({ source: 'SERVERS', destination: 'REMOTE_NET', nextHopType: 'ipsec-vpn', nextHop: 'Sede1' })
    expect(cfg.routes[1]).toMatchObject({ from: 'ge4', nextHopType: 'trunk', nextHop: 'WAN_Trunk' })
    expect(cfg.nats[0]).toMatchObject({
      name: 'NAT_RDP', enabled: false, iface: 'wan1', originalIp: 'any', mapTo: 'SERVER_11',
      mapType: 'port protocol tcp original-port 3389 mapped-port 3389',
    })
  })

  it('extracts VPNs with peer and resolved traffic selectors', () => {
    expect(cfg.vpns[0]).toMatchObject({
      name: 'Sede1', enabled: true, remoteAddress: 'sede1.example.org',
      localTs: ['192.168.1.0/24'], remoteTs: ['192.168.93.0/24'], policies: ['Sede1'],
    })
  })

  it('never extracts secrets (keystring, password hash)', () => {
    const json = JSON.stringify(cfg)
    for (const secret of ['SEGRETISSIMO', 'Q2lhb0NpYW8=', 'HASHHASH']) expect(json).not.toContain(secret)
  })
})

describe('parseConfig', () => {
  it('detects the format', () => {
    expect(parseConfig(CONF).rules).toHaveLength(3)
    expect(parseConfig('/ vrf "main" secure-policy rule "A" "action" "allow"').rules[0].name).toBe('A')
  })
})
