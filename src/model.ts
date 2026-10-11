// Neutral data model extracted from a Zyxel config (uOS or ZLD)

export interface Zone {
  name: string
  description?: string
  interfaces: string[]
}

export interface Iface {
  name: string
  kind: string // ethernet | vlan | lag | ...
  description?: string
  enabled: boolean
  role?: string // internal | external | general
  ip?: string // CIDR, e.g. 192.168.10.1/24
  vlanId?: number
  link?: string // link-interface
}

export interface AddressObject {
  name: string
  type: string // host | range | cidr | interface-subnet | fqdn | geography
  value: string
  description?: string
}

export interface AddressGroup {
  name: string
  members: string[]
  description?: string
}

export interface ServiceObject {
  name: string
  proto: string // tcp | udp | icmp | icmp6 | protocol
  value: string // port, range or protocol number
}

export interface ServiceGroup {
  name: string
  members: string[]
}

export interface Rule {
  order: number
  name: string
  from: string
  to: string
  sourceIp: string
  destIp: string
  service: string
  user: string
  schedule: string
  action: string // allow | deny
  enabled: boolean
  logging?: string
  description?: string
}

export interface VpnSite {
  name: string
  remoteAddress?: string
  enabled: boolean
  localTs: string[]
  remoteTs: string[]
  // security-policy names: policy routes reference them as next-hop
  policies: string[]
}

export interface NatRule {
  name: string
  enabled: boolean
  iface?: string
  sourceIp?: string
  originalIp?: string
  mapTo?: string
  mapType?: string
}

export interface RouteRule {
  order: number
  name: string
  enabled: boolean
  from: string
  source: string
  destination: string
  service: string
  nextHopType?: string // ipsec-vpn | trunk | interface
  nextHop?: string
}

export interface InterfaceGroup {
  name: string
  members: { name: string; passive: boolean }[]
}

export interface FirewallConfig {
  routes: RouteRule[]
  ifaceGroups: InterfaceGroup[]
  defaultTrunk?: string
  zones: Zone[]
  interfaces: Iface[]
  addresses: Record<string, AddressObject>
  addressGroups: Record<string, AddressGroup>
  services: Record<string, ServiceObject>
  serviceGroups: Record<string, ServiceGroup>
  rules: Rule[]
  vpns: VpnSite[]
  nats: NatRule[]
}
