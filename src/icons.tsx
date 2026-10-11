// Inline icons: a lucide-react dependency would cost more than this file.
// Lucide style: 24x24, stroke, currentColor. Navigation icons use a lighter
// 1.8 stroke, as in the approved mockup.

interface P { size?: number; className?: string; sw?: number }

function Svg({ size = 16, className, sw = 2, children }: P & { children: React.ReactNode }) {
  return (
    <svg
      width={size} height={size} viewBox="0 0 24 24" fill="none"
      stroke="currentColor" strokeWidth={sw} strokeLinecap="round" strokeLinejoin="round"
      className={className} aria-hidden focusable="false"
    >
      {children}
    </svg>
  )
}

export const IconSun = (p: P) => (
  <Svg {...p}>
    <circle cx="12" cy="12" r="4" />
    <path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M6.34 17.66l-1.41 1.41M19.07 4.93l-1.41 1.41" />
  </Svg>
)

export const IconMoon = (p: P) => (
  <Svg {...p}><path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9Z" /></Svg>
)

export const IconX = (p: P) => (
  <Svg {...p}><path d="M18 6 6 18M6 6l12 12" /></Svg>
)

export const IconCheck = (p: P) => (
  <Svg {...p}><path d="M20 6 9 17l-5-5" /></Svg>
)

export const IconBan = (p: P) => (
  <Svg {...p}><circle cx="12" cy="12" r="10" /><path d="m4.9 4.9 14.2 14.2" /></Svg>
)

export const IconAlert = (p: P) => (
  <Svg {...p}>
    <path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0Z" />
    <path d="M12 9v4M12 17h.01" />
  </Svg>
)

export const IconArrowRight = (p: P) => (
  <Svg {...p}><path d="M5 12h14M12 5l7 7-7 7" /></Svg>
)

export const IconUpload = (p: P) => (
  <Svg {...p}>
    <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
    <path d="M17 8l-5-5-5 5M12 3v12" />
  </Svg>
)

export const IconLock = (p: P) => (
  <Svg {...p}>
    <rect x="3" y="11" width="18" height="11" rx="2" />
    <path d="M7 11V7a5 5 0 0 1 10 0v4" />
  </Svg>
)

// Logo: one node feeding two, the topology.
export const IconTopology = (p: P) => (
  <Svg sw={2.5} {...p}>
    <circle cx="12" cy="5" r="2.5" /><circle cx="5" cy="19" r="2.5" /><circle cx="19" cy="19" r="2.5" />
    <path d="M12 7.5v4M12 11.5 6.5 17M12 11.5l5.5 5.5" />
  </Svg>
)

export const IconSearch = (p: P) => (
  <Svg {...p}><circle cx="11" cy="11" r="7" /><path d="m20 20-3.5-3.5" /></Svg>
)

// Sidebar, one per view
const NAV = { sw: 1.8 }
export const IconMap = (p: P) => (
  <Svg {...NAV} {...p}>
    <rect x="3" y="3" width="7" height="6" rx="1.5" /><rect x="14" y="15" width="7" height="6" rx="1.5" />
    <rect x="3" y="15" width="7" height="6" rx="1.5" /><path d="M6.5 9v6M10 18h4" />
  </Svg>
)
export const IconGrid = (p: P) => (
  <Svg {...NAV} {...p}><rect x="3" y="3" width="18" height="18" rx="2" /><path d="M3 9h18M3 15h18M9 3v18M15 3v18" /></Svg>
)
export const IconRoute = (p: P) => (
  <Svg {...NAV} {...p}>
    <circle cx="6" cy="19" r="2.5" /><circle cx="18" cy="5" r="2.5" />
    <path d="M8.5 19H15a3.5 3.5 0 0 0 0-7H9a3.5 3.5 0 0 1 0-7h6.5" />
  </Svg>
)
export const IconList = (p: P) => (
  <Svg {...NAV} {...p}><path d="M4 6h16M4 12h16M4 18h10" /></Svg>
)
export const IconGlobe = (p: P) => (
  <Svg {...NAV} {...p}><circle cx="12" cy="12" r="9" /><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18" /></Svg>
)
export const IconLayers = (p: P) => (
  <Svg {...NAV} {...p}><path d="M12 3 3 8l9 5 9-5-9-5Z" /><path d="m3 13 9 5 9-5" /></Svg>
)
export const IconWarn = (p: P) => (
  <Svg {...NAV} {...p}><path d="M12 3 2 20h20L12 3Z" /><path d="M12 10v4M12 17v.5" /></Svg>
)
export const IconPlay = (p: P) => (
  <Svg {...NAV} {...p}><path d="M5 4v16l14-8L5 4Z" /></Svg>
)
export const IconDiff = (p: P) => (
  <Svg {...NAV} {...p}><path d="M8 3v12M16 9v12M4 7l4-4 4 4M12 17l4 4 4-4" /></Svg>
)
