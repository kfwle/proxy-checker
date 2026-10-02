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
