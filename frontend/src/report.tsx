import { useMemo, useRef, useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { CheckCircle2, XCircle, Radar, ChevronDown, SlidersHorizontal } from 'lucide-react'
import RussiaMap, { groupByGeo, rankVerdict } from './RussiaMap'
import type { CheckResult } from './types'

export function stripHost(hostPort: string): string {
  return hostPort.includes('://') ? hostPort : hostPort.split(':')[0] || hostPort
}

export type ExtChecks = Record<string, { state: string; summary?: string; error?: string; link?: string; nodes?: Record<string, { code?: string; country: string; city: string }>; results?: Record<string, unknown> }>
export type Rkn = { loading: boolean; blocked?: boolean; targetType?: string; ips?: string[]; blockedSubnets?: string[]; geo?: { asn: string; organisation: string; location: string; country_code?: string }; reverseLookup?: string[]; whitelist?: { rank: number }; rknDomain?: string; error?: string }
export type PrbProbe = { probeId: string; region: string; provider: string; asn: string; verdicts: string[]; dpiHop?: number | null; targetHop?: number | null; evidence?: string[] }
export type Prb = { loading: boolean; done?: boolean; online?: number; totals?: Record<string, number>; probes?: PrbProbe[]; error?: string }
export type Gp = { loading: boolean; done?: boolean; results?: { probe: string; country: string; city: string; network: string; min: number; avg: number; max: number; loss: number; ok: boolean }[]; error?: string }
export type Kp = { loading: boolean; done?: boolean; results?: { loc: string; name: string; min: number; avg: number; max: number; loss: number; ok: boolean }[]; error?: string }
export type T2 = { kind?: string; loading?: boolean; data?: unknown; error?: string }
export type DnsOne = { ok: boolean; ms: number; answers?: string[]; rcode?: string; error?: string }
export type DnsT = { loading: boolean; target?: string; udp?: DnsOne; tcp?: DnsOne; dot?: DnsOne; error?: string }
export type ExitI = { loading: boolean; ok?: boolean; latencyMs?: number; exitIp?: string; country?: string; code?: string; emoji?: string; city?: string; asn?: string; hosting?: boolean; error?: string }

export type CheckKey = 'ping' | 'tcp' | 'udp' | 'dns' | 'http' | 'gp' | 'kp' | 'rkn' | 'probe' | 'abuse' | 'domains' | 'whois' | 'revdns' | 'exit' | 'dnstest'

const ALL_KEYS: CheckKey[] = ['ping', 'tcp', 'udp', 'dns', 'http', 'gp', 'kp', 'rkn', 'probe', 'abuse', 'domains', 'whois', 'revdns', 'exit', 'dnstest']

const EXT_KEYS: CheckKey[] = ['ping', 'tcp', 'udp', 'dns', 'http']

function allSel(): Record<CheckKey, boolean> {
  return Object.fromEntries(ALL_KEYS.map((k) => [k, true])) as Record<CheckKey, boolean>
}

export const CHECK_GROUPS: { name: string; keys: CheckKey[] }[] = [
  { name: 'CHECK-HOST', keys: ['ping', 'tcp', 'udp', 'dns', 'http'] },
  { name: 'ПИНГЕРЫ', keys: ['gp', 'kp'] },
  { name: 'ЧЕБУРЧЕК', keys: ['rkn', 'probe'] },
  { name: '2IP', keys: ['abuse', 'domains', 'whois', 'revdns', 'exit'] },
  { name: 'DNS', keys: ['dnstest'] },
]

export const CHECK_LABELS: Record<CheckKey, string> = {
  ping: 'ping', tcp: 'tcp', udp: 'udp', dns: 'dns', http: 'http',
  gp: 'globalping', kp: 'keycdn', rkn: 'ркн', probe: 'пробы',
  abuse: 'abuse', domains: 'домены', whois: 'whois', revdns: 'revdns', exit: 'выход', dnstest: 'днс-тест',
}

export function Switch({ on, onClick, title }: { on: boolean; onClick: () => void; title?: string }) {
  return (
    <button onClick={onClick} title={title}
      className={`relative rounded-full transition-colors ${on ? 'bg-emerald-500' : 'bg-stone-300 dark:bg-stone-700'}`}
      style={{ width: 28, height: 17 }}>
      <span className="absolute top-[2px] w-[13px] h-[13px] rounded-full bg-white shadow transition-all" style={{ left: on ? 13 : 2 }} />
    </button>
  )
}

export const KP_CC: Record<string, string> = { defr: 'de', nlam: 'nl', uklo: 'gb', usny: 'us', ussf: 'us', sgsg: 'sg', ausy: 'au', inba: 'in' }

export type FullData = {
  ext: { host: string; done: boolean; checks?: ExtChecks } | undefined
  rk: Rkn | undefined
  pr: Prb | undefined
  gp: Gp | undefined
  kp: Kp | undefined
  t2: Record<string, T2>
  exitI: ExitI | undefined
  dnsT: DnsT | undefined
  started: boolean
  sel: Record<CheckKey, boolean>
  toggle: (k: CheckKey) => void
  ruOnly: boolean
  toggleRu: () => void
  runAll: () => void
  runSelected: () => void
  ccSel: string[]
  ccAvail: string[]
  toggleCC: (code: string) => void
  ccOk: (code?: string) => boolean
  t2fetch: (host: string, kind: 'abuse' | 'domains' | 'whois' | 'revdns', force?: boolean) => void
  exitCheck: () => void
}

export function useFullReport(host: string, link: string, timeoutSec: number, initialSel?: Record<CheckKey, boolean>): FullData {
  const [ext, setExt] = useState<FullData['ext']>(undefined)
  const [rk, setRk] = useState<Rkn | undefined>(undefined)
  const [pr, setPr] = useState<Prb | undefined>(undefined)
  const [gp, setGp] = useState<Gp | undefined>(undefined)
  const [kp, setKp] = useState<Kp | undefined>(undefined)
  const [t2, setT2] = useState<Record<string, T2>>({})
  const [exitI, setExitI] = useState<ExitI | undefined>(undefined)
  const [dnsT, setDnsT] = useState<DnsT | undefined>(undefined)
  const [started, setStarted] = useState(false)
  const [sel, setSel] = useState<Record<CheckKey, boolean>>(initialSel || allSel())
  const selRef = useRef<Record<CheckKey, boolean>>(initialSel || allSel())
  const [ruOnly, setRuOnly] = useState(false)
  const ruRef = useRef(false)
  const [ccSel, setCcSel] = useState<string[]>([])

  // доступные страны из загруженных данных (ноды check-host + пробы globalping + точки keycdn)
  const ccAvail: string[] = useMemo(() => {
    const s = new Set<string>()
    const add = (code?: string) => {
      if (!code) return
      s.add(code.toLowerCase())
    }
    for (const t of Object.values(ext?.checks || {})) {
      for (const n of Object.values((t as { nodes?: Record<string, { code?: string }> }).nodes || {})) {
        add(n.code)
      }
    }
    for (const p of gp?.results || []) add(p.country)
    for (const p of kp?.results || []) add(KP_CC[p.loc])
    return [...s].sort()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ext, gp, kp])

  function toggleCC(code: string) {
    const c = code.toLowerCase()
    setCcSel((prev) => (prev.includes(c) ? prev.filter((x) => x !== c) : [...prev, c]))
  }

  function ccOk(code?: string): boolean {
    if (!ccSel.length) return true
    if (!code) return false
    return ccSel.includes(code.toLowerCase())
  }

  async function pollJob(url: string, tries: number, onData: (d: { done: boolean; results?: unknown; error?: string }) => boolean): Promise<void> {
    for (let i = 0; i < tries; i++) {
      await new Promise((res) => setTimeout(res, 3000))
      try {
        const jr = await fetch(url)
        if (!jr.ok) break
        if (onData(await jr.json())) break
      } catch { break }
    }
  }

  const startedRef = useRef<Set<string>>(new Set())
  function mark(key: string): boolean {
    if (startedRef.current.has(key)) return false
    startedRef.current.add(key)
    return true
  }

  async function extCheck(only?: CheckKey[]) {
    const types = ((only || EXT_KEYS.filter((k) => selRef.current[k])) as string[]).filter((t) => ['ping','tcp','udp','dns','http'].includes(t))
    if (!types.length) return
    if (!mark('ext:' + types.sort().join(',') + (ruRef.current ? '|ru' : ''))) return
    setExt((prev) => prev || { host, done: false })
    try {
      const r = await fetch('/api/extcheck', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ host, types, onlyRU: ruRef.current }),
      })
      if (!r.ok) {
        const msg = await r.text()
        setExt({ host, done: true, checks: { ping: { state: 'error', error: msg } } })
        return
      }
      const { id } = await r.json()
      for (let i = 0; i < 15; i++) {
        await new Promise((res) => setTimeout(res, 3000))
        const jr = await fetch(`/api/extcheck/${id}`)
        if (!jr.ok) break
        const data = await jr.json()
        setExt({ host, done: data.done, checks: data.checks })
        if (data.done) break
      }
    } catch (e) {
      setExt({ host, done: true, checks: { ping: { state: 'error', error: String(e) } } })
    }
  }

  async function rknCheck() {
    if (!mark('rkn')) return
    const target = stripHost(host)
    setRk((prev) => prev || { loading: true })
    try {
      const r = await fetch(`/api/rkn?target=${encodeURIComponent(target)}`)
      if (!r.ok) throw new Error(await r.text())
      setRk({ loading: false, ...(await r.json()) })
    } catch (e) {
      startedRef.current.delete('rkn')
      setRk({ loading: false, error: String(e) })
    }
  }

  async function probeCheck() {
    const target = stripHost(host)
    if (!target) return
    if (!mark('probe')) return
    setPr((prev) => prev || { loading: true })
    try {
      const r = await fetch('/api/probe', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ target }) })
      if (!r.ok) throw new Error(await r.text())
      const { job } = await r.json()
      for (let i = 0; i < 40; i++) {
        await new Promise((res) => setTimeout(res, 3000))
        const jr = await fetch(`/api/probe/${job}`)
        if (!jr.ok) throw new Error(await jr.text())
        const data = await jr.json()
        setPr({ loading: !data.done, done: data.done, online: data.online, totals: data.totals, probes: data.probes })
        if (data.done) break
      }
    } catch (e) {
      startedRef.current.delete('probe')
      setPr({ loading: false, error: String(e) })
    }
  }

  async function gpCheck() {
    if (!mark('gp' + (ruRef.current ? '|ru' : ''))) return
    setGp((prev) => prev || { loading: true })
    try {
      const r = await fetch('/api/gping', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ target: stripHost(host), country: ruRef.current ? 'RU' : '' }) })
      if (!r.ok) throw new Error(await r.text())
      const { id } = await r.json()
      type GpR = NonNullable<Gp['results']>
      await pollJob(`/api/gping/${id}`, 35, (data) => {
        setGp({ loading: !data.done, done: data.done, results: data.results as GpR, error: data.error })
        return data.done
      })
    } catch (e) {
      startedRef.current.delete('gp')
      setGp({ loading: false, error: String(e) })
    }
  }

  async function kpCheck() {
    if (!mark('kp')) return
    if (ruRef.current) {
      setKp({ loading: false, error: 'у KeyCDN нет точек в РФ — выключите 🇷🇺 Только РФ для этого блока' })
      return
    }
    setKp((prev) => prev || { loading: true })
    try {
      const r = await fetch('/api/keyping', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ target: stripHost(host) }) })
      if (!r.ok) throw new Error(await r.text())
      const { id } = await r.json()
      type KpR = NonNullable<Kp['results']>
      await pollJob(`/api/keyping/${id}`, 15, (data) => {
        setKp({ loading: !data.done, done: data.done, results: data.results as KpR, error: data.error })
        return data.done
      })
    } catch (e) {
      startedRef.current.delete('kp')
      setKp({ loading: false, error: String(e) })
    }
  }

  async function t2fetch(h: string, kind: 'abuse' | 'domains' | 'whois' | 'revdns', force?: boolean) {
    const key = `${kind}:${h}`
    let skip = false
    setT2((p) => {
      if (p[key] && !force) {
        skip = true
        return p
      }
      return { ...p, [key]: { kind, loading: true } }
    })
    if (skip) return
    try {
      const target = kind === 'domains' || kind === 'revdns' ? stripHost(h) : h
      const url = kind === 'revdns' ? `/api/revdns?ip=${encodeURIComponent(target)}` : `/api/twoip/${kind}?target=${encodeURIComponent(target)}`
      const r = await fetch(url)
      if (!r.ok) throw new Error(await r.text())
      const data = await r.json()
      setT2((p) => ({ ...p, [key]: { kind, loading: false, data } }))
    } catch (e) {
      setT2((p) => ({ ...p, [key]: { kind, loading: false, error: String(e), retry: true } }))
    }
  }

  async function exitCheck() {
    if (!mark('exit')) return
    setExitI((prev) => prev || { loading: true })
    try {
      const r = await fetch('/api/exitip', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ link, timeoutSec }) })
      setExitI({ loading: false, ...(await r.json()) })
    } catch (e) {
      startedRef.current.delete('exit')
      setExitI({ loading: false, error: String(e) })
    }
  }

  async function dnsCheck() {
    if (!mark('dnstest')) return
    setDnsT({ loading: true })
    try {
      const r = await fetch('/api/dnstest', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ host }) })
      if (!r.ok) throw new Error(await r.text())
      const data = await r.json()
      setDnsT({ loading: false, target: data.target, udp: data.udp, tcp: data.tcp, dot: data.dot })
    } catch (e) {
      startedRef.current.delete('dnstest')
      setDnsT({ loading: false, error: String(e) })
    }
  }

  function runOne(k: CheckKey) {
    if (k === 'rkn') return void rknCheck()
    if (k === 'probe') return void probeCheck()
    if (k === 'gp') return void gpCheck()
    if (k === 'kp') return void kpCheck()
    if (k === 'exit') return void exitCheck()
    if (k === 'dnstest') return void dnsCheck()
    if (k === 'abuse' || k === 'domains' || k === 'whois' || k === 'revdns') return void t2fetch(host, k)
    void extCheck([k])
  }

  function toggle(k: CheckKey) {
    const on = !selRef.current[k]
    selRef.current = { ...selRef.current, [k]: on }
    setSel({ ...selRef.current })
    if (on) runOne(k)
  }

  function runAll() {
    setStarted(true)
    selRef.current = allSel()
    setSel({ ...selRef.current })
    void extCheck()
    void rknCheck()
    void probeCheck()
    void gpCheck()
    void kpCheck()
    void dnsCheck()
    // бесплатное тоже сразу: revdns + выход (abuse/domains/whois жрут квоту — только руками)
    if (host) {
      void t2fetch(host, 'revdns')
      if (link) void exitCheck()
    }
  }

  function runSelected() {
    setStarted(true)
    const s = selRef.current
    const extTypes = EXT_KEYS.filter((k) => s[k])
    if (extTypes.length) void extCheck(extTypes)
    if (s.rkn) void rknCheck()
    if (s.probe) void probeCheck()
    if (s.gp) void gpCheck()
    if (s.kp) void kpCheck()
    if (s.dnstest) void dnsCheck()
  }

  function toggleRu() {
    const on = !ruRef.current
    ruRef.current = on
    setRuOnly(on)
  }

  return { ext, rk, pr, gp, kp, t2, exitI, dnsT, started, sel, toggle, runAll, runSelected, t2fetch, exitCheck, ccSel, ccAvail, toggleCC, ccOk, ruOnly, toggleRu }
}

export function rknDomainSuffix(d?: string) {
  return d ? ` (${d})` : ''
}

export function verdictRu(v: string): string {
  const m: Record<string, string> = {
    tspu_block: 'ТСПУ блок', sni_block: 'ТСПУ блок', dns_spoofing: 'DNS-подмена',
    ok: 'Доступен', clean: 'Доступен', uncertain: 'Неясно',
  }
  return m[v] || v
}

export function KV({ k, v, mono }: { k: string; v: string; mono?: boolean }) {
  return (
    <div className="flex items-center gap-2 min-w-0">
      <span className="text-stone-500 shrink-0">{k}</span>
      <span className={`ml-auto text-right truncate min-w-0 ${mono ? 'font-mono text-[11px]' : ''}`} title={v}>{v}</span>
    </div>
  )
}

function T2View({ kind, data }: { kind: string; data: unknown }) {
  const d = data as Record<string, unknown>
  if (kind === 'abuse') {
    const items = (d.items as { description: string; comment: string; author: string; date: string }[]) || []
    return (
      <div className="grid gap-0.5 text-[11px]">
        <span className={d.rkn ? 'text-red-500 font-semibold' : 'text-emerald-600 font-semibold'}>
          {d.rkn ? 'Есть RKN-запись!' : items.length ? `Жалоб: ${items.length}` : 'Жалоб нет — чист'}
        </span>
        {items.slice(0, 5).map((it, i) => (
          <span key={i} className="font-mono text-stone-500 truncate" title={`${it.author} ${it.date}`}>
            {it.description}{it.comment ? ` · ${it.comment}` : ''} · {it.author} · {String(it.date).slice(0, 10)}
          </span>
        ))}
      </div>
    )
  }
  if (kind === 'domains') {
    const list = (d.domains as string[]) || []
    return <span className="font-mono text-[11px] text-stone-500">Доменов на IP: {d.count as number}{list.length ? ` — ${list.slice(0, 6).join(', ')}${list.length > 6 ? '…' : ''}` : ''}</span>
  }
  if (kind === 'revdns') {
    const ht = (d.hackertarget as string[]) || []
    const us = (d.urlscan as string[]) || []
    const shown = [...us.slice(0, 4), ...ht.slice(0, 4)]
    return (
      <span className="font-mono text-[11px] text-stone-500">
        free: urlscan {us.length} · HT {ht.length}{shown.length ? ` — ${shown.join(', ')}${ht.length + us.length > shown.length ? '…' : ''}` : ''}
      </span>
    )
  }
  const w = d.whois as Record<string, unknown> | undefined
  return <span className="font-mono text-[11px] text-stone-500">{w ? JSON.stringify(w).slice(0, 300) : '—'}</span>
}

export function T2Row({ host, k, label, t2, t2fetch, hasToken }: {
  host: string; k: 'abuse' | 'domains' | 'whois' | 'revdns'; label: string;
  t2: Record<string, T2>; t2fetch: (host: string, kind: 'abuse' | 'domains' | 'whois' | 'revdns', force?: boolean) => void; hasToken?: boolean;
}) {
  if (k !== 'revdns' && !hasToken) return null
  const st = t2[`${k}:${host}`]
  return (
    <div>
      {!st && <button onClick={() => t2fetch(host, k)} className="text-xs text-blue-600 dark:text-blue-400 underline">{label} →</button>}
      {st?.loading && <span className="text-stone-500 animate-pulse text-xs">{k}…</span>}
      {st?.error && <span className="text-red-500 font-mono text-[11px]">{k}: {st.error} <button onClick={() => t2fetch(host, k, true)} className="underline text-stone-500">повторить</button></span>}
      {st?.data !== undefined && !st.loading && !st.error && <T2View kind={k} data={st.data} />}
    </div>
  )
}

function Flag({ code, country }: { code?: string; country?: string }) {
  if (!code) return null
  const cc = code.toLowerCase()
  return <img src={`https://flagcdn.com/${cc}.svg`} alt={country || code} title={country || code} width={16} height={12} className="inline rounded-[2px] shrink-0" loading="lazy" />
}

function nodeSummary(t: string, raw: unknown): { text: string; ok: boolean } {
  if (raw == null) return { text: 'считает…', ok: false }
  try {
    if (t === 'tcp' || t === 'udp') {
      const arr = raw as { time?: number; address?: string; error?: string; timeout?: number }[]
      const r = arr?.[0]
      if (!r) return { text: '?', ok: false }
      if (r.error) return { text: r.error.slice(0, 60), ok: false }
      if (r.time == null) return { text: r.timeout != null ? `таймаут ${r.timeout}с` : 'нет ответа', ok: false }
      return { text: `${(r.time * 1000).toFixed(0)} мс · ${r.address || ''}`, ok: true }
    }
    if (t === 'ping') {
      const arr = ((raw as unknown[][][])[0] || []) as [string, number, string?][]
      const oks = arr.filter((p) => p[0] === 'OK')
      if (!oks.length) return { text: `loss 100% (${arr.length})`, ok: false }
      const avg = oks.reduce((s, p) => s + Number(p[1]) * 1000, 0) / oks.length
      return { text: `${avg.toFixed(0)} мс · ${oks.length}/${arr.length}`, ok: true }
    }
    if (t === 'http') {
      const row = (raw as unknown[][])[0] as [number, number, string, string | null, string | null] | undefined
      if (!row) return { text: '?', ok: false }
      if (!row[0]) return { text: `${row[2]} ${row[3] || ''}`.slice(0, 60), ok: false }
      return { text: `${(Number(row[1]) * 1000).toFixed(0)} мс · ${row[3]} ${row[2]}`, ok: true }
    }
    if (t === 'dns') {
      const r = (raw as { A?: string[]; AAAA?: string[] }[])[0]
      if (!r) return { text: '?', ok: false }
      const a = [...(r.A || []), ...(r.AAAA || [])]
      if (!a.length) return { text: 'NXDOMAIN', ok: false }
      return { text: `${a[0]}${a.length > 1 ? ` +${a.length - 1}` : ''}`, ok: true }
    }
  } catch { /* fallthrough */ }
  return { text: String(raw).slice(0, 60), ok: false }
}

function ExtTypeRow({ t, c, ccOk }: { t: string; c: NonNullable<ExtChecks[string]>; ccOk: (code?: string) => boolean }) {
  const [open, setOpen] = useState(false)
  const nodes = c.nodes || {}
  const ids = Object.keys(nodes).filter((id) => ccOk(nodes[id].code))
  const results = (c.results || {}) as Record<string, unknown>
  return (
    <div>
      <div className="flex items-center gap-2 font-mono text-[11px] flex-wrap">
        <span className="w-10 font-semibold">{t}</span>
        <span className={c.state === 'error' ? 'text-red-500' : c.summary?.startsWith('OK') ? 'text-emerald-600' : 'text-stone-500'}>
          {c.state === 'running' ? '…' : c.state === 'error' ? c.error : c.summary}
        </span>
        {c.link && <a href={c.link} target="_blank" rel="noreferrer" className="text-blue-600 dark:text-blue-400 underline">отчёт</a>}
        {ids.length > 0 && (
          <button onClick={() => setOpen(!open)} className="flex items-center gap-0.5 text-stone-500 hover:text-stone-800 dark:hover:text-stone-200" title="Ноды">
            <ChevronDown size={13} className={`transition-transform ${open ? 'rotate-180' : ''}`} />
            <span className="flex -space-x-1">
              {ids.slice(0, 5).map((id) => <Flag key={id} code={nodes[id].code} country={nodes[id].country} />)}
            </span>
          </button>
        )}
      </div>
      <AnimatePresence initial={false}>
      {open && ids.length > 0 && (
        <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }}
          transition={{ duration: 0.25, ease: 'easeInOut' }} className="overflow-hidden">
        <div className="ml-12 mt-0.5 grid gap-px rounded-lg overflow-hidden border border-stone-200 dark:border-stone-800">
          {ids.map((id) => {
            const n = nodes[id]
            const s = nodeSummary(t, results[id])
            const short = id.split('.')[0]
            return (
              <div key={id} className="flex items-center gap-2 px-2 py-1 bg-stone-50 dark:bg-stone-950 font-mono text-[11px]">
                <Flag code={n.code} country={n.country} />
                <span className="shrink-0 text-stone-500">{short}</span>
                <span className="truncate text-stone-400">{n.city}</span>
                <span className={`ml-auto shrink-0 ${s.ok ? 'text-emerald-600' : 'text-stone-500'}`}>{s.text}</span>
              </div>
            )
          })}
        </div>
        </motion.div>
      )}
      </AnimatePresence>
    </div>
  )
}

export function ResultRow({ r, hasToken }: { r: CheckResult; hasToken: boolean }) {
  const f = useFullReport(r.host, r.link, 8)
  const rk = f.rk
  const badge = rk && !rk.loading && rk.blocked !== undefined
    ? rk.blocked
      ? <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-red-100 dark:bg-red-900 text-red-700 dark:text-red-200 shrink-0">РКН</span>
      : <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-emerald-100 dark:bg-emerald-900 text-emerald-700 dark:text-emerald-200 shrink-0">чист</span>
    : null
  const hasFull = f.started
  return (
    <div className="rounded-xl border border-stone-200 dark:border-stone-800 px-3 py-2 text-sm grid gap-1.5">
      <div className="flex items-center gap-3">
        {r.alive ? <CheckCircle2 size={17} className="text-emerald-500 shrink-0" /> : <XCircle size={17} className="text-stone-400 shrink-0" />}
        <span className="text-[11px] font-mono px-1.5 py-0.5 rounded bg-stone-100 dark:bg-stone-800 shrink-0">{r.protocol || '?'}</span>
        <span className="font-mono text-xs truncate flex-1" title={r.link}>{r.host || r.link.slice(0, 60)}</span>
        {r.alive
          ? <span className="text-xs font-mono text-emerald-600 dark:text-emerald-400 shrink-0">{r.latencyMs} мс</span>
          : <span className="text-[11px] text-stone-500 truncate max-w-[40%] shrink-0" title={r.error}>{r.error}</span>}
        <span className="text-[10px] font-mono text-stone-400 shrink-0 hidden sm:inline">{r.core}</span>
        {badge}
        {r.host && (
          <button onClick={f.runAll} title="Вся проверка сразу: внешний вид + РКН/GEO + пробы РФ"
            className="px-2.5 py-1.5 rounded-lg bg-stone-900 dark:bg-stone-100 text-white dark:text-stone-900 flex items-center gap-1.5 shrink-0 text-xs">
            <Radar size={14} /> Всё сразу
          </button>
        )}
      </div>
      {hasFull && (
        <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }}
          transition={{ duration: 0.35, ease: 'easeInOut' }} className="overflow-hidden">
          <FullPanel r={r} f={f} hasToken={hasToken} />
        </motion.div>
      )}
    </div>
  )
}

export function FilterBar({ sel, toggle, ccSel, ccAvail, toggleCC, ruOnly, toggleRu }: {
  sel: Record<CheckKey, boolean>; toggle: (k: CheckKey) => void;
  ccSel?: string[]; ccAvail?: string[]; toggleCC?: (code: string) => void;
  ruOnly?: boolean; toggleRu?: () => void;
}) {
  const [open, setOpen] = useState(false)
  const n = Object.values(sel).filter(Boolean).length
  return (
    <div>
      <button onClick={() => setOpen(!open)}
        className="flex items-center gap-1.5 text-xs px-2.5 py-1.5 rounded-xl border border-stone-300 dark:border-stone-700 hover:bg-stone-100 dark:hover:bg-stone-800">
        <SlidersHorizontal size={14} />
        Фильтры проверок · {n}/{ALL_KEYS.length}{ccSel?.length ? ` · стран: ${ccSel.length}` : ''}
        <ChevronDown size={14} className={`transition-transform duration-300 ${open ? 'rotate-180' : ''}`} />
      </button>
      <AnimatePresence initial={false}>
        {open && (
          <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.25, ease: 'easeInOut' }} className="overflow-hidden">
            <div className="flex gap-3 flex-wrap pt-2">
              {toggleRu && (
                <div className="flex items-center gap-1.5">
                  <Switch on={!!ruOnly} onClick={toggleRu} title="Мерить только из России (check-host RU-ноды, globalping RU, пробы РФ)" />
                  <span className="text-[11px] font-medium">🇷🇺 Только РФ</span>
                  <span className="text-[10px] font-mono text-stone-500">check-host·globalping·пробы</span>
                </div>
              )}
            </div>
            <div className="flex gap-3 flex-wrap pt-2">
              {CHECK_GROUPS.map((g) => (
                <div key={g.name} className="flex items-center gap-1.5 flex-wrap">
                  <span className="text-[10px] font-semibold tracking-wide text-stone-500">{g.name}</span>
                  {g.keys.map((k) => (
                    <span key={k} className="flex items-center gap-1">
                      <Switch on={sel[k]} onClick={() => toggle(k)} title={CHECK_LABELS[k]} />
                      <span className="text-[10px] font-mono text-stone-500">{CHECK_LABELS[k]}</span>
                    </span>
                  ))}
                </div>
              ))}
            </div>
            <div className="flex items-center gap-1.5 flex-wrap pt-2">
              <span className="text-[10px] font-semibold tracking-wide text-stone-500">СТРАНЫ ПИНГЕРОВ</span>
              {(!ccAvail || !ccAvail.length) && <span className="text-[11px] text-stone-500">появятся после загрузки нод</span>}
              {(ccAvail || []).map((c) => {
                const on = !ccSel?.length || ccSel.includes(c)
                return (
                  <button key={c} onClick={() => toggleCC?.(c)} title={c.toUpperCase()}
                    className={`flex items-center gap-1 px-1.5 py-0.5 rounded-lg border font-mono text-[11px] transition-all ${on ? 'border-emerald-500 bg-emerald-50 dark:bg-emerald-950' : 'border-stone-300 dark:border-stone-700 opacity-50'}`}>
                    <Flag code={c} country={c.toUpperCase()} />{c.toUpperCase()}
                  </button>
                )
              })}
              {!!ccSel?.length && (
                <button onClick={() => ccSel.forEach((c) => toggleCC?.(c))} className="text-[11px] text-stone-500 underline">сбросить</button>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}

export function FullPanel({ r, f, hasToken, showFilters = true }: { r: { host: string; link: string; protocol: string; core: string; latencyMs: number }; f: FullData; hasToken: boolean; showFilters?: boolean }) {
  const { ext, rk, pr, gp, kp, sel } = f
  const [selRegion, setSelRegion] = useState<string | null>(null)
  const regionDetail = pr?.probes?.length && selRegion ? groupByGeo(pr.probes).verdictByGeo.get(selRegion) : undefined
  const extVisible = (['ping', 'tcp', 'udp', 'dns', 'http'] as CheckKey[]).some((k) => sel[k])
  return (
    <div className="rounded-xl border border-stone-200 dark:border-stone-800 p-3 grid gap-3">
      {showFilters && <FilterBar sel={f.sel} toggle={f.toggle} ruOnly={f.ruOnly} toggleRu={f.toggleRu} />}
      <div className="grid gap-3 md:grid-cols-2">
      <div className="grid gap-2 content-start min-w-0">
        <h4 className="text-[11px] font-semibold tracking-wide text-stone-500">СЕТЕВЫЕ ДАННЫЕ</h4>
        <div className="grid gap-1 text-xs">
          <KV k="Хост" v={r.host} mono />
          <KV k="Протокол" v={`${r.protocol} · ${r.core} · ${r.latencyMs} мс`} mono />
          {sel.rkn && rk && !rk.loading && !rk.error && rk.ips?.length ? <KV k="IP-адреса" v={rk.ips.slice(0, 4).join(', ')} mono /> : null}
          {sel.rkn && rk && !rk.loading && !rk.error && rk.geo && (rk.geo.organisation || rk.geo.asn)
            ? <><KV k="Хостинг / ISP" v={rk.geo.organisation || '—'} /><KV k="ASN" v={rk.geo.asn || '—'} mono />
              <div className="flex items-center gap-2">
                <span className="text-stone-500 shrink-0">Локация</span>
                <span className="ml-auto text-right truncate flex items-center gap-1.5" title={rk.geo.location || ''}>
                  <Flag code={rk.geo.country_code} country={rk.geo.location} />{rk.geo.location || '—'}
                </span>
              </div></> : null}
          {sel.rkn && rk && !rk.loading && !rk.error && rk.reverseLookup?.length ? <KV k="PTR" v={rk.reverseLookup.slice(0, 2).join(', ')} mono /> : null}
          {sel.rkn && rk?.loading ? <span className="text-stone-500 animate-pulse text-xs">Спрашиваю cheburcheck.ru…</span> : null}
          {sel.rkn && rk?.error ? <span className="text-red-500 font-mono text-[11px]">{rk.error}</span> : null}
          {sel.exit && (() => {
            // выход имеет смысл только для прокси-ссылки (схема или host:port)
            const t = r.link.trim()
            const isProxy = /:\/\//.test(t) || /:[0-9]{1,5}([/?#]|$)/.test(t)
            if (!isProxy) return null
            const ex = f.exitI
            if (!ex) return <button onClick={f.exitCheck} className="text-xs text-blue-600 dark:text-blue-400 underline w-fit">Узнать выходной IP →</button>
            if (ex.loading) return <span className="text-stone-500 animate-pulse text-xs">Смотрю выход через прокси…</span>
            if (ex.error || !ex.ok) return <span className="text-red-500 font-mono text-[11px]">Выход: {ex.error || '—'}</span>
            return <KV k="Выход" v={`${ex.emoji || ''} ${ex.exitIp} · ${ex.city || ''} ${ex.country || ''} · ${ex.asn || ''}${ex.hosting !== undefined ? (ex.hosting ? ' · хостинг' : ' · не хостинг') : ''} · ${ex.latencyMs} мс`} mono />
          })()}
        </div>
        {sel.rkn && (<>
        <h4 className="text-[11px] font-semibold tracking-wide text-stone-500 mt-1">НАХОЖДЕНИЕ В СПИСКАХ</h4>
        <div className="grid gap-1 text-xs">
          {rk && !rk.loading && !rk.error
            ? <>
              <div className="flex items-center gap-2"><span className="text-stone-500">Реестр РКН</span>
                <span className="ml-auto font-semibold" style={{ color: rk.blocked ? '#dc2626' : '#16a34a' }}>
                  {rk.blocked ? `Найден${rknDomainSuffix(rk.rknDomain)}` : 'Не найден'}</span></div>
              {rk.blockedSubnets?.length ? <KV k="Подсети в блоке" v={rk.blockedSubnets.join(', ')} mono /> : null}
              {rk.whitelist ? <KV k="Tranco rank" v={`#${rk.whitelist.rank}`} mono /> : null}
            </>
            : <span className="text-stone-500 text-xs">—</span>}
        </div>
        </>)}
        <h4 className="text-[11px] font-semibold tracking-wide text-stone-500 mt-1">2IP — РЕПУТАЦИЯ И ОКРУЖЕНИЕ</h4>
        <div className="grid gap-1">
          {sel.revdns && <T2Row host={r.host} k="revdns" label="Кто ещё на IP (free)" t2={f.t2} t2fetch={f.t2fetch} />}
          {!hasToken && <span className="text-xs text-stone-500">Остальное — по токену 2ip.io/free из Настроек.</span>}
          {sel.abuse && <T2Row host={r.host} k="abuse" label="Проверить abuse (10к/мес)" t2={f.t2} t2fetch={f.t2fetch} hasToken={hasToken} />}
          {sel.domains && <T2Row host={r.host} k="domains" label="Кто ещё на IP · 2ip (10/мес)" t2={f.t2} t2fetch={f.t2fetch} hasToken={hasToken} />}
          {sel.whois && <T2Row host={r.host} k="whois" label="WHOIS (100/мес)" t2={f.t2} t2fetch={f.t2fetch} hasToken={hasToken} />}
        </div>
        <h4 className="text-[11px] font-semibold tracking-wide text-stone-500 mt-1">ВНЕШНИЙ ВИД (CHECK-HOST)</h4>
        <div className="grid gap-1">
          {extVisible && !ext && <span className="text-stone-500 text-xs">—</span>}
          {ext && !ext.done && <span className="text-stone-500 animate-pulse text-xs">Опрашиваю ноды…</span>}
          {extVisible && ext?.checks && (['ping', 'tcp', 'udp', 'dns', 'http'] as CheckKey[]).filter((t) => sel[t]).map((t) => {
            const c = ext.checks?.[t]
            if (!c) return null
            // фильтр стран: если ни одна нода не подходит — строку прячем
            if (f.ccSel.length && c.state === 'done') {
              const any = Object.values(c.nodes || {}).some((n) => f.ccOk((n as { code?: string }).code))
              if (!any) return null
            }
            return <ExtTypeRow key={t} t={t} c={c} ccOk={f.ccOk} />
          })}
        </div>
        {sel.dnstest && (
          <>
            <h4 className="text-[11px] font-semibold tracking-wide text-stone-500 mt-1">DNS-ТЕСТ (запрос на сам адрес)</h4>
            <div className="grid gap-1">
              {!f.dnsT && <span className="text-stone-500 text-xs">—</span>}
              {f.dnsT?.loading && <span className="text-stone-500 animate-pulse text-xs">Шлю A google.com…</span>}
              {f.dnsT?.error && <span className="text-red-500 font-mono text-[11px]">{f.dnsT.error}</span>}
              {(['udp', 'tcp', 'dot'] as const).map((k) => {
                const o = f.dnsT?.[k]
                if (!o || f.dnsT?.loading) return null
                const label = k === 'udp' ? 'UDP/53' : k === 'tcp' ? 'TCP/53' : 'DoT/853'
                return (
                  <div key={k} className="flex items-center gap-2 font-mono text-[11px] flex-wrap">
                    <span className="w-14 font-semibold">{label}</span>
                    {o.ok
                      ? <span className="text-emerald-600">{o.ms} мс · {o.answers?.join(', ')}</span>
                      : <span className="text-red-500">{o.error || o.rcode || '—'}</span>}
                  </div>
                )
              })}
            </div>
          </>
        )}
      </div>
      <div className="grid gap-2 content-start min-w-0">
        <h4 className="text-[11px] font-semibold tracking-wide text-stone-500">
          ПРОБЫ РФ{pr?.online ? ` · ${pr.probes?.length || 0} из ${pr.online} ответов` : ''}</h4>
        {!sel.probe && <span className="text-stone-500 text-xs">выключено тумблером выше</span>}
        {sel.probe && !pr && <span className="text-stone-500 text-xs">—</span>}
        {sel.probe && pr?.loading && !pr.probes?.length && <span className="text-stone-500 animate-pulse text-xs">Жду добровольные пробы… (до ~1.5 мин)</span>}
        {sel.probe && pr?.error && <span className="text-red-500 font-mono text-[11px]">{pr.error}</span>}
        {sel.probe && pr?.totals && Object.keys(pr.totals).length > 0 && (
          <div className="grid gap-1.5">
            {Object.entries(pr.totals).map(([k, v]) => {
              const total = pr.online || Object.values(pr.totals!).reduce((s, n) => s + n, 0)
              const pct = total ? Math.round((v / total) * 100) : 0
              const bad = k !== 'clean' && k !== 'ok'
              return (
                <div key={k} className="rounded-lg border border-stone-200 dark:border-stone-800 px-2.5 py-1.5">
                  <div className="flex items-baseline gap-2 text-xs">
                    <span className="font-medium" style={{ color: bad ? '#dc2626' : '#16a34a' }}>{verdictRu(k)}</span>
                    <span className="ml-auto font-mono">{v} / {total}</span>
                  </div>
                  <div className="h-1 rounded bg-stone-200 dark:bg-stone-800 mt-1">
                    <div className="h-1 rounded" style={{ width: `${pct}%`, background: bad ? '#dc2626' : '#16a34a' }} />
                  </div>
                </div>
              )
            })}
          </div>
        )}
        {sel.probe && pr?.probes?.length ? <RussiaMap probes={pr.probes} selected={selRegion} onSelect={setSelRegion} /> : null}
        <AnimatePresence initial={false}>
        {selRegion && regionDetail && (
          <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.3, ease: 'easeInOut' }} className="overflow-hidden">
          <div className="rounded-xl border border-stone-200 dark:border-stone-800 p-3 grid gap-2">
            <div className="flex items-center gap-2">
              <div>
                <div className="text-sm font-semibold">{selRegion}</div>
                <div className="text-[11px] text-stone-500">Ответили {regionDetail.probes.length} сканера</div>
              </div>
              <button onClick={() => setSelRegion(null)} className="ml-auto text-xs px-2 py-1 rounded-lg border border-stone-300 dark:border-stone-700 hover:bg-stone-100 dark:hover:bg-stone-800">
                Закрыть
              </button>
            </div>
            <div className="grid gap-px rounded-lg overflow-hidden border border-stone-200 dark:border-stone-800 text-xs">
              <div className="grid grid-cols-[1fr_1fr_auto] gap-2 px-2.5 py-1.5 bg-stone-100 dark:bg-stone-800 font-semibold text-[11px] text-stone-500">
                <span>Регион</span><span>Провайдер / AS</span><span>Вердикт</span>
              </div>
              {regionDetail.probes.map((p, i) => (
                <div key={p.probeId || i} className="grid gap-1 px-2.5 py-1.5 bg-white dark:bg-stone-900">
                  <div className="grid grid-cols-[1fr_1fr_auto] gap-2 items-center">
                    <span className="truncate">{p.region}</span>
                    <span className="truncate text-stone-500">{p.provider}<br /><span className="font-mono text-[10px]">{p.asn}</span></span>
                    <span className="flex gap-1 justify-end flex-wrap">
                      {p.verdicts.length === 0
                        ? <span className="px-1.5 py-0.5 rounded bg-emerald-100 dark:bg-emerald-900 text-emerald-700 dark:text-emerald-200 font-mono text-[11px]">Доступен</span>
                        : p.verdicts.map((v) => (
                          <span key={v} className={`px-1.5 py-0.5 rounded font-mono text-[11px] ${rankVerdict(v) === 'block' ? 'bg-red-100 dark:bg-red-900 text-red-700 dark:text-red-200' : 'bg-stone-200 dark:bg-stone-700 text-stone-600 dark:text-stone-300'}`}>
                            {verdictRu(v)}
                          </span>
                        ))}
                    </span>
                  </div>
                  {(p.dpiHop != null || p.targetHop != null || (p.evidence?.length || 0) > 0) && (
                    <div className="font-mono text-[11px] text-stone-500">
                      {p.dpiHop != null && p.verdicts.some((v) => v === 'tspu_block' || v === 'sni_block')
                        ? <span className="text-red-500">⚠ Блокировка на ТСПУ обнаружена после {p.dpiHop} прыжка{p.dpiHop === 1 ? '' : p.dpiHop < 5 ? 'а' : 'ов'} · </span> : null}
                      {p.targetHop != null ? <span>цель на {p.targetHop} прыжке · </span> : null}
                      {p.evidence?.length ? <span>evidence: {p.evidence.join(', ')}</span> : null}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
          </motion.div>
        )}
        </AnimatePresence>
      </div>
      <div className="md:col-span-2">
        <h4 className="text-[11px] font-semibold tracking-wide text-stone-500 mt-1">ГЛОБАЛЬНЫЙ ПИНГ</h4>
        <div className="grid gap-3 md:grid-cols-2 mt-1">
          {sel.gp && (() => {
            const g = f.gp
            if (!g) return null
            return (
              <div>
                <div className="text-[11px] text-stone-500 mb-0.5">Globalping · {g.results?.length || 0} проб{g.loading && !g.results?.length ? <span className="animate-pulse">…</span> : null}</div>
                {g.error && <span className="text-red-500 font-mono text-[11px]">{g.error}</span>}
                <div className="grid gap-px max-h-64 overflow-y-auto">
                {g.results?.filter((p) => f.ccOk(p.country)).map((p, i) => (
                  <div key={i} className="flex items-center gap-2 font-mono text-[11px]">
                    <span className="truncate flex items-center gap-1"><Flag code={p.country} country={p.country} />{p.city}, {p.country} · {p.network}</span>
                    <span className={`ml-auto shrink-0 ${p.loss >= 100 ? 'text-red-500' : 'text-emerald-600'}`}>{p.avg.toFixed(1)} мс{p.loss > 0 ? ` · −${p.loss}%` : ''}</span>
                  </div>
                ))}
                </div>
              </div>
            )
          })()}
          {sel.kp && (() => {
            const k = f.kp
            if (!k) return null
            return (
              <div>
                <div className="text-[11px] text-stone-500 mb-0.5">KeyCDN 8 точек {k.loading && !k.results?.length ? <span className="animate-pulse">…</span> : null}</div>
                {k.error && <span className="text-red-500 font-mono text-[11px]">{k.error}</span>}
                {k.results?.filter((p) => f.ccOk(KP_CC[p.loc])).map((p) => (
                  <div key={p.loc} className="flex items-center gap-2 font-mono text-[11px]">
                    <span className="flex items-center gap-1"><Flag code={KP_CC[p.loc]} country={p.name} />{p.name}</span>
                    <span className="ml-auto shrink-0 text-emerald-600">{p.avg.toFixed(2)} мс{p.loss > 0 ? ` · −${p.loss}%` : ''}</span>
                  </div>
                ))}
              </div>
            )
          })()}
        </div>
      </div>
      </div>
    </div>
  )
}
