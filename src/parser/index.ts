import type { FirewallConfig } from '../model'
import { parseUos } from './uos'
import { parseZld } from './zld'

// uOS (USG FLEX H) writes one property per line starting with "/";
// ZLD (USG FLEX, ATP, VPN) writes CLI blocks.
export function parseConfig(text: string): FirewallConfig {
  return /^\/ /m.test(text) ? parseUos(text) : parseZld(text)
}
