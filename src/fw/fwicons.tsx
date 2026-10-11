// Material-style icons (24x24) for the Zyxel clone, inline so the
// Material Icons font is not a dependency.

interface P { size?: number }

function I({ size = 20, d, fill }: P & { d: string; fill?: boolean }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24"
      fill={fill ? 'currentColor' : 'none'} stroke={fill ? 'none' : 'currentColor'}
      strokeWidth={1.8} strokeLinecap="round" strokeLinejoin="round" aria-hidden>
      <path d={d} />
    </svg>
  )
}

// sidebar sections
export const FwShield = (p: P) => <I {...p} d="M12 3l7 3v5c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6l7-3z" />
export const FwNetwork = (p: P) => <I {...p} d="M12 3a9 9 0 100 18 9 9 0 000-18zM3 12h18M12 3c2.5 2.5 2.5 15.5 0 18M12 3c-2.5 2.5-2.5 15.5 0 18" />
export const FwLock = (p: P) => <I {...p} d="M6 11h12v9H6zM8 11V7a4 4 0 018 0v4" />
export const FwBox = (p: P) => <I {...p} d="M12 3l8 4.5v9L12 21l-8-4.5v-9L12 3zM4 7.5l8 4.5 8-4.5M12 12v9" />

// chrome
export const FwSearch = (p: P) => <I {...p} d="M11 4a7 7 0 105.2 11.7L21 21M11 4a7 7 0 00-5 12" />
export const FwBack = (p: P) => <I {...p} d="M15 6l-6 6 6 6" />
export const FwChevron = (p: P) => <I {...p} d="M6 9l6 6 6-6" />

export const FwStatus = ({ size = 15 }: P) => (
  // status light, like the rule state on the device
  <svg width={size} height={size} viewBox="0 0 24 24" fill="currentColor" aria-hidden>
    <path d="M9 21h6v-1H9v1zm3-19a7 7 0 00-4 12.7V17h8v-2.3A7 7 0 0012 2z" />
  </svg>
)
