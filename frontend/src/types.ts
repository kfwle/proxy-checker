export type CheckResult = {
  index: number
  link: string
  protocol: string
  host: string
  alive: boolean
  latencyMs: number
  core: string
  error?: string
  checkedAt: string
}

export type CoreInfo = {
  id: string
  name: string
  description: string
  binary: string
  installed: boolean
  version?: string
  latest: string
  updateAvailable: boolean
  supports: string[]
  downloadUrl?: string
}

export type SpeedResult = {
  ok: boolean
  core?: string
  server?: string
  downMbps?: number
  upMbps?: number
  downMb?: number
  upMb?: number
  latencyMs?: number
  error?: string
  upError?: string
}

export type SpeedServer = {
  id: string
  name: string
  region: string
  upload: boolean
}

export type UnlockService = {
  id: string
  name: string
  status: 'yes' | 'no' | 'unknown' | 'error'
  region?: string
  detail?: string
}

export type UnlockResult = {
  ok: boolean
  core?: string
  services?: UnlockService[]
  error?: string
}

export type DNSBLList = {
  name: string
  zone: string
  status: 'listed' | 'clean' | 'unknown'
  detail?: string
}

export type ReputationResult = {
  ok: boolean
  core?: string
  exitIp?: string
  country?: string
  asn?: string
  listed?: number
  lists?: DNSBLList[]
  error?: string
}
