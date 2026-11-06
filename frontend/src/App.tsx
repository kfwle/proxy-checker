import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Play, Square, Trash2, Download, Copy,
  Cpu, RefreshCw, Settings2, Moon, Sun, Zap, Filter, FlaskConical, Image,
  Gauge, Globe, Shield,
} from 'lucide-react'
import { ResultRow } from './report'
import TestPage from './TestPage'
import TracePage from './TracePage'
import DNSPage from './DNSPage'
import { SpeedPage, UnlockPage, IpPage } from './QualityPages'
import type { CheckResult, CoreInfo } from './types'

const PROTO_LIST = [
  'vless','vmess','ss','trojan','hysteria2','hysteria','anytls',
  'tuic','juicity','naive','shadowtls','mieru','socks5','http','mtproto','webproxy','wireguard',
]

export type CoreRule = { proto: string; transport: string; security: string; core: string }

const ALL_CORES = ['sing-box', 'xray', 'mihomo']

function loadLS(key: string, fallback: string[]): string[] {
  try {
    const v = JSON.parse(localStorage.getItem(key) || 'null')
    if (Array.isArray(v)) return v.filter((x) => typeof x === 'string')
  } catch {}
  return fallback
}

function tabFromPath(path: string): string {
  switch (path) {
    case '/test': return 'test'
    case '/dns': return 'dns'
    case '/trace': return 'trace'
    case '/speed': return 'speed'
    case '/unlock': return 'unlock'
    case '/ip': return 'ip'
    default: return 'home'
  }
}

export default function App() {
  const [text, setText] = useState('')
  const [concurrency, setConcurrency] = useState(16)
  const [timeoutSec, setTimeoutSec] = useState(8)
  const [testUrl, setTestUrl] = useState('https://www.gstatic.com/generate_204')
  const [full, setFull] = useState(true)
  const [mode, setMode] = useState<'url' | 'tcp' | 'ping'>('url')
  const [saved, setSaved] = useState<{ name: string; path: string; kind: string; size: number }[]>([])
  const [daily, setDaily] = useState<{ enabled: boolean; lastRun?: string; lastTotal?: number; lastAlive?: number; running?: boolean; lastError?: string }>({ enabled: false })
  const [twoip, setTwoip] = useState<{ hasToken: boolean; twoipToken: string; abuseAuto: boolean }>({ hasToken: false, twoipToken: '', abuseAuto: true })
  const [tokenInput, setTokenInput] = useState('')
  const [filter, setFilter] = useState<'all' | 'alive' | 'dead'>('all')
  const [protoSel, setProtoSel] = useState<string[]>([])
  const [selCores, setSelCores] = useState<string[]>(() => loadLS('pc-cores', ALL_CORES))
  const [rules, setRules] = useState<CoreRule[]>(() => {
    try {
      const v = JSON.parse(localStorage.getItem('pc-rules') || 'null')
      if (Array.isArray(v)) return v
    } catch {}
    return [
      { proto: 'vless', transport: 'tcp', security: 'tls', core: 'sing-box' },
      { proto: 'vless', transport: 'tcp', security: 'reality', core: 'xray' },
      { proto: 'vless', transport: 'grpc', security: '', core: 'mihomo' },
    ]
  })

  function toggleCore(id: string) {
    setSelCores((s) => {
      const next = s.includes(id) ? s.filter((x) => x !== id) : [...s, id]
      try { localStorage.setItem('pc-cores', JSON.stringify(next)) } catch {}
      return next
    })
  }

  function saveRules(next: CoreRule[]) {
    setRules(next)
    try { localStorage.setItem('pc-rules', JSON.stringify(next)) } catch {}
  }
  const [results, setResults] = useState<CheckResult[]>([])
  const [jobId, setJobId] = useState<string | null>(null)
  const [running, setRunning] = useState(false)
  const [progress, setProgress] = useState({ done: 0, total: 0 })
  const [cores, setCores] = useState<CoreInfo[]>([])
  const [dlProg, setDlProg] = useState<Record<string, { state: string; percent: number; stage: string; error?: string }>>({})
  const [autoUpdate, setAutoUpdate] = useState(true)
  const [dark, setDark] = useState(false)
  const [showSettings, setShowSettings] = useState(false)
  const [toast, setToast] = useState<string | null>(null)
  const esRef = useRef<EventSource | null>(null)

  useEffect(() => {
    document.documentElement.classList.toggle('dark', dark)
  }, [dark])

  const loadCores = useCallback(async (live = false) => {
    try {
      const url = live ? '/api/cores/check-updates' : '/api/cores'
      const r = await fetch(url, live ? { method: 'POST' } : {})
      const data = await resJson<CoreInfo[]>(r)
      setCores(data)
      if (live && autoUpdate === false) return
      if (live) {
        const upd = data.filter((c) => c.updateAvailable)
        if (upd.length > 0) showToast(`Доступно обновлений ядер: ${upd.map((c) => c.name + ' ' + c.latest).join(', ')}`)
      }
    } catch {}
  }, [autoUpdate])

  useEffect(() => {
    loadCores(false)
    fetch('/api/daily').then((r) => r.json()).then(setDaily).catch(() => {})
    fetch('/api/settings').then((r) => r.json()).then(setTwoip).catch(() => {})
    if (autoUpdate) {
      const t = setTimeout(() => loadCores(true), 2000)
      return () => clearTimeout(t)
    }
  }, [loadCores, autoUpdate])

  async function toggleDaily(on: boolean) {
    const r = await fetch('/api/daily', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ enabled: on }) })
    const data = await r.json()
    setDaily(data)
    showToast(on ? 'Ежедневный socks5 включён: качаю 1к прямо сейчас, файлы — в results/daily/' : 'Ежедневный socks5 выключен')
  }

  async function dailyRunNow() {
    await fetch('/api/daily/run', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ limit: 1000 }) })
    showToast('Прогон 1к запущен, статус обновится в настройках')
    setTimeout(() => fetch('/api/daily').then((r) => r.json()).then(setDaily).catch(() => {}), 5000)
  }

  async function saveToken() {
    const r = await fetch('/api/settings', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ twoipToken: tokenInput }) })
    const data = await r.json()
    setTwoip(data)
    setTokenInput('')
    showToast(data.hasToken ? 'Токен 2ip сохранён' : 'Токен стёрт')
  }

  async function toggleAbuseAuto(on: boolean) {
    const r = await fetch('/api/settings', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ abuseAuto: on }) })
    setTwoip(await r.json())
  }

  // поллинг прогресса скачивания ядер (раз в секунду, дёшево)
  const dlBusyRef = useRef(false)
  useEffect(() => {
    let alive = true
    const t = setInterval(async () => {
      try {
        const r = await fetch('/api/cores/progress')
        const data = await r.json()
        if (!alive) return
        const wasBusy = dlBusyRef.current
        const busy = Object.values(data as Record<string, { state: string }>).some((p) => ['downloading', 'extracting', 'installing'].includes(p.state))
        dlBusyRef.current = busy
        setDlProg((prev) => {
          // не дёргаем стейт если ничего не меняется и всё idle
          if (!busy && Object.keys(prev).length === 0) return prev
          return data
        })
        if (wasBusy && !busy) loadCores(false)
      } catch {}
    }, 1000)
    return () => { alive = false; clearInterval(t) }
  }, [loadCores])

  async function downloadCore(id: string) {
    const r = await fetch('/api/cores/download', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id }),
    })
    const data = await r.json()
    if (!data.ok) { showToast(data.message || 'Не запустилось'); return }
    showToast(`Скачиваю ${id} ${data.version || ''}…`)
    setDlProg((p) => ({ ...p, [id]: { state: 'downloading', percent: 1, stage: 'старт…' } }))
  }

  async function downloadAll() {
    const r = await fetch('/api/cores/download-all', { method: 'POST' })
    const data = await r.json()
    if (data.started?.length) {
      showToast(`Скачиваю: ${data.started.join(', ')}`)
      const init: Record<string, { state: string; percent: number; stage: string }> = {}
      for (const id of data.started) init[id] = { state: 'downloading', percent: 1, stage: 'старт…' }
      setDlProg((p) => ({ ...p, ...init }))
    } else {
      showToast('Всё уже установлено и актуально')
      loadCores(true)
    }
  }

  function showToast(msg: string) {
    setToast(msg)
    setTimeout(() => setToast(null), 5000)
  }

  function splitInput(s: string): string[] {
    // та же склейка, что на бэкенде: разорванные ссылки + многострочные JSON
    const joined: string[] = []
    let jsonBuf = ''
    let jsonDepth = 0
    let inJSON = false
    const pushJSON = () => {
      // грубая оценка: считаем строки-ссылки внутри; точное число даст бэкенд
      const m = jsonBuf.match(/"(?:type|protocol)"\s*:/g)
      joined.push(`__json_${m ? m.length : 1}__`)
      jsonBuf = ''
      jsonDepth = 0
      inJSON = false
    }
    for (const raw of s.split('\n')) {
      const line = raw.trim()
      if (!inJSON && (!line || line.startsWith('#') || line.startsWith('//'))) continue
      if (!inJSON && line.startsWith('{')) inJSON = true
      if (inJSON) {
        jsonBuf += line + '\n'
        jsonDepth += (line.match(/\{/g) || []).length - (line.match(/\}/g) || []).length
        if (jsonDepth <= 0) pushJSON()
        continue
      }
      if (joined.length > 0 && !line.includes('://')) {
        const prev = joined[joined.length - 1]
        if (prev.endsWith('?') || prev.endsWith('&')) {
          joined[joined.length - 1] = prev + line
          continue
        }
      }
      joined.push(line)
    }
    if (inJSON) pushJSON()
    return joined.flatMap((l) => (l.startsWith('__json_') ? [l] : l.split(/\s+/).filter(Boolean)))
  }

  function countLinks(): number {
    return splitInput(text).length
  }

  async function start() {
    if (!text.trim()) { showToast('Вставьте хотя бы одну ссылку'); return }
    setResults([])
    setSaved([])
    setProgress({ done: 0, total: 0 })
    const r = await fetch('/api/check', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        text,
        options: { concurrency, timeoutSec, testUrl, full, mode, cores: selCores, rules },
      }),
    })
    if (!r.ok) { showToast('Ошибка запуска: ' + (await r.text())); return }
    const { id, total } = await r.json()
    setJobId(id)
    setRunning(true)
    setProgress({ done: 0, total })
    const es = new EventSource(`/api/jobs/${id}/stream`)
    esRef.current = es
    es.onmessage = (e) => {
      try {
        const res = JSON.parse(e.data) as CheckResult
        setResults((prev) => (prev.some((x) => x.index === res.index) ? prev : [...prev, res]))
        setProgress((p) => ({ ...p, done: Math.min(p.total, p.done + 1) }))
      } catch {}
    }
    es.addEventListener('done', () => { stop(false); fetchSaved(id) })
    es.onerror = () => { /* держим до done */ }
  }

  async function fetchSaved(id: string) {
    // бэкенд пишет файлы после finish — подождём чуть и заберём список,
    // заодно добираем потерянные по SSE строки (сверка по index)
    for (let i = 0; i < 10; i++) {
      try {
        const r = await fetch(`/api/jobs/${id}`)
        if (r.ok) {
          const j = await r.json()
          if (j.results?.length) {
            setResults((prev) => {
              const have = new Set(prev.map((x) => x.index))
              const add = (j.results as CheckResult[]).filter((x) => !have.has(x.index))
              return add.length ? [...prev, ...add] : prev
            })
            setProgress({ done: j.done, total: j.total })
          }
          if (j.saved?.length) { setSaved(j.saved); return }
          if (j.finished) { setSaved(j.saved || []); return }
        }
      } catch {}
      await new Promise((res) => setTimeout(res, 500))
    }
  }

  function stop(clear = true) {
    esRef.current?.close()
    esRef.current = null
    setRunning(false)
    if (clear && jobId) fetch(`/api/jobs/${jobId}`, { method: 'DELETE' })
  }

  const filtered = useMemo(() => {
    return results.filter((r) => {
      if (filter === 'alive' && !r.alive) return false
      if (filter === 'dead' && r.alive) return false
      if (protoSel.length > 0 && !protoSel.includes(r.protocol)) return false
      return true
    }).sort((a, b) => Number(b.alive) - Number(a.alive) || a.latencyMs - b.latencyMs)
  }, [results, filter, protoSel])

  const stats = useMemo(() => {
    const alive = results.filter((r) => r.alive)
    const avg = alive.length ? Math.round(alive.reduce((s, r) => s + r.latencyMs, 0) / alive.length) : 0
    return { total: results.length, alive: alive.length, dead: results.length - alive.length, avg }
  }, [results])

  function exportAlive() {
    const alive = results.filter((r) => r.alive).map((r) => r.link).join('\n')
    download('alive.txt', alive)
  }
  function exportJSON() { download('results.json', JSON.stringify(results, null, 2)) }
  function exportCSV() {
    const csv = 'link,protocol,host,alive,latencyMs,core,error\n' +
      results.map((r) => [csvq(r.link), r.protocol, csvq(r.host), r.alive, r.latencyMs, r.core, csvq(r.error ?? '')].join(',')).join('\n')
    download('results.csv', csv)
  }
  function copyAlive() {
    navigator.clipboard.writeText(results.filter((r) => r.alive).map((r) => r.link).join('\n'))
    showToast('Живые ссылки скопированы')
  }

  const pct = progress.total ? Math.round((progress.done / progress.total) * 100) : 0
  const [tab, setTab] = useState<string>(() => tabFromPath(typeof location !== 'undefined' ? location.pathname : '/'))

  function go(t: string) {
    setTab(t)
    try {
      history.pushState(null, '', t === 'home' ? '/' : '/' + t)
    } catch {}
  }

  useEffect(() => {
    const onPop = () => setTab(tabFromPath(location.pathname))
    addEventListener('popstate', onPop)
    return () => removeEventListener('popstate', onPop)
  }, [])

  return (
    <div className="min-h-screen bg-stone-100 dark:bg-stone-950 text-stone-900 dark:text-stone-100">
      <header className="sticky top-0 z-10 border-b border-stone-200 dark:border-stone-800 bg-white/80 dark:bg-stone-950/80 backdrop-blur">
        <div className="max-w-6xl mx-auto px-4 py-3 flex items-center gap-3">
          <div className="w-9 h-9 rounded-xl bg-stone-900 dark:bg-stone-100 text-white dark:text-stone-900 grid place-items-center">
            <Zap size={18} />
          </div>
          <div>
            <h1 className="font-semibold leading-tight">Proxy Checker</h1>
            <p className="text-xs text-stone-500">vless · vmess · ss · trojan · hysteria · tuic · naive · mtproto · socks · http</p>
          </div>
          <nav className="ml-4 flex flex-wrap items-center gap-1 text-sm">
            <button onClick={() => go('home')} className={`px-3 py-1.5 rounded-xl ${tab === 'home' ? 'bg-stone-900 dark:bg-stone-100 text-white dark:text-stone-900' : 'hover:bg-stone-200 dark:hover:bg-stone-800'}`}>
              Чекер
            </button>
            <button onClick={() => go('test')} className={`px-3 py-1.5 rounded-xl flex items-center gap-1.5 ${tab === 'test' ? 'bg-stone-900 dark:bg-stone-100 text-white dark:text-stone-900' : 'hover:bg-stone-200 dark:hover:bg-stone-800'}`}>
              <FlaskConical size={15} /> Тесты
            </button>
            <button onClick={() => go('dns')} className={`px-3 py-1.5 rounded-xl ${tab === 'dns' ? 'bg-stone-900 dark:bg-stone-100 text-white dark:text-stone-900' : 'hover:bg-stone-200 dark:hover:bg-stone-800'}`}>
              DNS
            </button>
            <button onClick={() => go('trace')} className={`px-3 py-1.5 rounded-xl ${tab === 'trace' ? 'bg-stone-900 dark:bg-stone-100 text-white dark:text-stone-900' : 'hover:bg-stone-200 dark:hover:bg-stone-800'}`}>
              Трейс
            </button>
            <button onClick={() => go('speed')} className={`px-3 py-1.5 rounded-xl flex items-center gap-1.5 ${tab === 'speed' ? 'bg-stone-900 dark:bg-stone-100 text-white dark:text-stone-900' : 'hover:bg-stone-200 dark:hover:bg-stone-800'}`}>
              <Gauge size={15} /> Скорость
            </button>
            <button onClick={() => go('unlock')} className={`px-3 py-1.5 rounded-xl flex items-center gap-1.5 ${tab === 'unlock' ? 'bg-stone-900 dark:bg-stone-100 text-white dark:text-stone-900' : 'hover:bg-stone-200 dark:hover:bg-stone-800'}`}>
              <Globe size={15} /> Unlock
            </button>
            <button onClick={() => go('ip')} className={`px-3 py-1.5 rounded-xl flex items-center gap-1.5 ${tab === 'ip' ? 'bg-stone-900 dark:bg-stone-100 text-white dark:text-stone-900' : 'hover:bg-stone-200 dark:hover:bg-stone-800'}`}>
              <Shield size={15} /> IP
            </button>
          </nav>
          <div className="ml-auto flex items-center gap-2">
            <button onClick={() => setShowSettings(!showSettings)} className="p-2 rounded-lg hover:bg-stone-200 dark:hover:bg-stone-800" title="Настройки">
              <Settings2 size={18} />
            </button>
            <button onClick={() => setDark(!dark)} className="p-2 rounded-lg hover:bg-stone-200 dark:hover:bg-stone-800" title="Тема">
              {dark ? <Sun size={18} /> : <Moon size={18} />}
            </button>
          </div>
        </div>
        {progress.total > 0 && (
          <div className="h-1 bg-stone-200 dark:bg-stone-800">
            <motion.div className="h-1 bg-emerald-500" animate={{ width: `${pct}%` }} />
          </div>
        )}
      </header>

      <main className="max-w-6xl mx-auto px-4 py-6 grid gap-4">
        <AnimatePresence>{toast && (
          <motion.div initial={{ opacity: 0, y: -8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}
            className="rounded-xl border border-amber-300 bg-amber-50 dark:bg-amber-950 dark:border-amber-800 px-4 py-2 text-sm">
            {toast}
          </motion.div>
        )}</AnimatePresence>

        {tab === 'test' ? <TestPage hasToken={twoip.hasToken} showToast={showToast} /> : tab === 'dns' ? <DNSPage showToast={showToast} /> : tab === 'trace' ? <TracePage /> : tab === 'speed' ? <SpeedPage /> : tab === 'unlock' ? <UnlockPage /> : tab === 'ip' ? <IpPage /> : (<>
        {showSettings && (
          <motion.section initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="rounded-2xl border border-stone-200 dark:border-stone-800 bg-white dark:bg-stone-900 p-4 grid gap-3 md:grid-cols-4">
            <label className="grid gap-1 text-sm">Параллельно
              <input type="number" value={concurrency} min={1} max={128} onChange={(e) => setConcurrency(+e.target.value)}
                className="rounded-lg border border-stone-300 dark:border-stone-700 bg-transparent px-2 py-1" />
            </label>
            <label className="grid gap-1 text-sm">Таймаут, сек
              <input type="number" value={timeoutSec} min={2} max={60} onChange={(e) => setTimeoutSec(+e.target.value)}
                className="rounded-lg border border-stone-300 dark:border-stone-700 bg-transparent px-2 py-1" />
            </label>
            <label className="grid gap-1 text-sm md:col-span-2">Test URL
              <input value={testUrl} onChange={(e) => setTestUrl(e.target.value)}
                className="rounded-lg border border-stone-300 dark:border-stone-700 bg-transparent px-2 py-1 font-mono text-xs" />
            </label>
            <Toggle on={full} onClick={() => setFull(!full)} label="Полный handshake (mtproto --full)" />
            <Toggle on={autoUpdate} onClick={() => setAutoUpdate(!autoUpdate)} label="Авто-проверка обновлений ядер" />
            <div className="md:col-span-4 grid gap-1.5 rounded-xl border border-stone-200 dark:border-stone-800 p-2.5">
              <span className="text-sm">Ядро под протокол / транспорт / защиту <span className="text-xs text-stone-500">(первое совпадение побеждает, пусто = любое)</span></span>
              {rules.map((rl, i) => (
                <div key={i} className="flex gap-1.5 flex-wrap items-center">
                  <select value={rl.proto} onChange={(e) => saveRules(rules.map((x, j) => (j === i ? { ...x, proto: e.target.value } : x)))}
                    className="text-xs rounded-lg border border-stone-300 dark:border-stone-700 bg-transparent px-1.5 py-1">
                    <option value="">протокол…</option>
                    {PROTO_LIST.map((p) => <option key={p} value={p}>{p}</option>)}
                  </select>
                  <select value={rl.transport} onChange={(e) => saveRules(rules.map((x, j) => (j === i ? { ...x, transport: e.target.value } : x)))}
                    className="text-xs rounded-lg border border-stone-300 dark:border-stone-700 bg-transparent px-1.5 py-1">
                    <option value="">транспорт…</option>
                    {['tcp', 'ws', 'grpc', 'httpupgrade', 'quic'].map((p) => <option key={p} value={p}>{p}</option>)}
                  </select>
                  <select value={rl.security} onChange={(e) => saveRules(rules.map((x, j) => (j === i ? { ...x, security: e.target.value } : x)))}
                    className="text-xs rounded-lg border border-stone-300 dark:border-stone-700 bg-transparent px-1.5 py-1">
                    <option value="">защита…</option>
                    {['tls', 'reality', 'none'].map((p) => <option key={p} value={p}>{p}</option>)}
                  </select>
                  <span className="text-stone-500">→</span>
                  <select value={rl.core} onChange={(e) => saveRules(rules.map((x, j) => (j === i ? { ...x, core: e.target.value } : x)))}
                    className="text-xs rounded-lg border border-stone-300 dark:border-stone-700 bg-transparent px-1.5 py-1 font-mono">
                    {ALL_CORES.map((p) => <option key={p} value={p}>{p}</option>)}
                  </select>
                  <button onClick={() => saveRules(rules.filter((_, j) => j !== i))} className="p-1 rounded-lg hover:bg-stone-200 dark:hover:bg-stone-800" title="Удалить">
                    <Trash2 size={14} />
                  </button>
                </div>
              ))}
              <button onClick={() => saveRules([...rules, { proto: '', transport: '', security: '', core: 'sing-box' }])}
                className="text-xs px-2 py-1 rounded-lg border border-dashed border-stone-400 hover:bg-stone-100 dark:hover:bg-stone-800 w-fit">
                + правило
              </button>
            </div>
            <div className="flex items-center gap-2 text-sm md:col-span-2">
              <Toggle on={daily.enabled} onClick={() => toggleDaily(!daily.enabled)} label="Ежедневные socks5 (3к/день из hookzof-листа, живые — в results/daily/ по странам)" />
            </div>
            <div className="text-xs text-stone-500 md:col-span-4 flex items-center gap-2 flex-wrap">
              <span>
                {daily.running ? 'Прогон идёт…' : daily.lastRun ? `Посл. прогон: ${daily.lastRun}, живых ${daily.lastAlive ?? 0} из ${daily.lastTotal ?? 0}` : 'Ещё не запускалось'}
                {daily.lastError ? ` · ошибка: ${daily.lastError}` : ''}
              </span>
              <button onClick={dailyRunNow} className="px-2 py-1 rounded-lg border border-stone-300 dark:border-stone-700 hover:bg-stone-100 dark:hover:bg-stone-800">
                Прогнать 1к сейчас
              </button>
            </div>
            <div className="md:col-span-4 grid gap-1.5 rounded-xl border border-stone-200 dark:border-stone-800 p-2.5">
              <span className="text-sm">Токен 2ip.io/free {twoip.hasToken ? <span className="font-mono text-xs text-emerald-600">({twoip.twoipToken} — вставлен)</span> : <span className="text-xs text-stone-500">(нет — abuse/domains/whois недоступны)</span>}</span>
              <div className="flex gap-1.5">
                <input value={tokenInput} onChange={(e) => setTokenInput(e.target.value)} placeholder="xyz…" spellCheck={false}
                  className="flex-1 rounded-lg border border-stone-300 dark:border-stone-700 bg-transparent px-2 py-1 font-mono text-xs" />
                <button onClick={saveToken} className="text-xs px-3 py-1 rounded-lg bg-stone-900 dark:bg-stone-100 text-white dark:text-stone-900">Сохранить</button>
              </div>
              <Toggle small on={twoip.abuseAuto} onClick={() => toggleAbuseAuto(!twoip.abuseAuto)} label="Авто-abuse новых живых IP из daily (по 1 запросу, дальше кэш)" />
              <span className="text-[11px] text-stone-500">Квоты бесплатно/мес: abuse 10к · whois 100 · domains 10 · email/cms мимо. Всё только ондеманд + кэш 7 дней.</span>
            </div>
          </motion.section>
        )}

        <section className="rounded-2xl border border-stone-200 dark:border-stone-800 bg-white dark:bg-stone-900 p-4 grid gap-3">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-sm font-medium">Вставьте ссылки ({countLinks()})</span>
            <span className="text-xs text-stone-500">по одной на строку, # — комментарий</span>
            <div className="ml-auto flex gap-2">
              <button onClick={() => setText('')} className="text-xs px-2 py-1 rounded-lg hover:bg-stone-200 dark:hover:bg-stone-800 flex items-center gap-1">
                <Trash2 size={14} /> Очистить
              </button>
              {!running ? (
                <button onClick={start} className="text-sm px-4 py-1.5 rounded-xl bg-stone-900 dark:bg-stone-100 text-white dark:text-stone-900 flex items-center gap-1.5">
                  <Play size={15} /> Проверить
                </button>
              ) : (
                <button onClick={() => stop()} className="text-sm px-4 py-1.5 rounded-xl bg-red-600 text-white flex items-center gap-1.5">
                  <Square size={15} /> Стоп ({progress.done}/{progress.total})
                </button>
              )}
            </div>
          </div>
          <div className="flex items-center gap-1.5 flex-wrap">
            <span className="text-xs text-stone-500">Чем проверять:</span>
            {([
              { id: 'url', label: 'URL-тест', hint: 'полный запрос через прокси' },
              { id: 'tcp', label: 'TCP', hint: 'коннект к host:port' },
              { id: 'ping', label: 'Ping', hint: 'ICMP до хоста' },
            ] as const).map((m) => (
              <button key={m.id} onClick={() => setMode(m.id)} title={m.hint}
                className={`text-xs px-3 py-1.5 rounded-xl border ${mode === m.id ? 'bg-stone-900 dark:bg-stone-100 text-white dark:text-stone-900 border-stone-900 dark:border-stone-100' : 'border-stone-300 dark:border-stone-700 hover:bg-stone-200 dark:hover:bg-stone-800'}`}>
                {m.label}
              </button>
            ))}
            <span className="text-[11px] text-stone-500">
              {mode === 'url' ? '— гоняет test URL через прокси (нужны ядра)' : mode === 'tcp' ? '— быстрый коннект к серверу, без ядер' : '— системный ping до хоста, без ядер'}
            </span>
          </div>
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-xs text-stone-500">Ядра:</span>
            {['sing-box', 'xray', 'mihomo'].map((id) => {
              const on = selCores.includes(id)
              const info = cores.find((c) => c.id === id)
              return (
                <button key={id} onClick={() => toggleCore(id)} title={info?.installed ? `установлен${info.version ? ' ' + info.version : ''}` : 'не скачан — проверка упадёт в следующее ядро'}
                  className={`px-4 py-2 rounded-2xl border-2 font-mono text-sm transition-all ${on ? 'border-emerald-500 bg-emerald-50 dark:bg-emerald-950' : 'border-stone-300 dark:border-stone-700 opacity-60 hover:opacity-100'}`}>
                  <span className="flex items-center gap-1.5">
                    <span className={`w-2 h-2 rounded-full ${info?.installed ? 'bg-emerald-500' : 'bg-stone-400'}`} />
                    {id}
                  </span>
                </button>
              )
            })}
            <span className="text-[11px] text-stone-500">direct · mtproto · juicity · mieru — всегда включены</span>
          </div>
          <textarea value={text} onChange={(e) => setText(e.target.value)} rows={8} spellCheck={false}
            placeholder={'vless://uuid@host:443?security=tls&sni=example.com#name\ntrojan://pass@host:443\nss://method:pass@host:8388\ntg://proxy?server=1.2.3.4&port=443&secret=ee...\n— или целиком JSON-конфиг sing-box/xray (балансеры selector/urltest раскроются сами)'}
            className="w-full rounded-xl border border-stone-300 dark:border-stone-700 bg-stone-50 dark:bg-stone-950 p-3 font-mono text-xs leading-relaxed focus:outline-none focus:ring-2 focus:ring-stone-400" />
          <div className="flex gap-4 text-sm">
            <Stat label="Всего" value={stats.total} />
            <Stat label="Живые" value={stats.alive} green />
            <Stat label="Мёртвые" value={stats.dead} red />
            <Stat label={mode === 'ping' ? 'Средний ping' : mode === 'tcp' ? 'Средний коннект' : 'Средний пинг'} value={stats.avg ? stats.avg + ' мс' : '—'} />
          </div>
          {saved.length > 0 && (
            <div className="rounded-xl border border-emerald-300 dark:border-emerald-800 bg-emerald-50 dark:bg-emerald-950 px-3 py-2 text-xs grid gap-1.5">
              <span className="font-medium">Автосохранено в папку results/ — скопируйте или скачайте:</span>
              {saved.map((f) => (
                <div key={f.path} className="flex items-center gap-2 font-mono">
                  <span className="truncate flex-1">{f.path} ({Math.round(f.size / 1024)} КБ)</span>
                  <a href={`/api/results/download?file=${encodeURIComponent(f.path)}`} className="px-2 py-0.5 rounded-lg bg-emerald-600 text-white hover:bg-emerald-500 no-underline">Скачать</a>
                </div>
              ))}
              <div className="flex gap-1.5">
                <button onClick={copyAlive} className="px-2 py-1 rounded-lg border border-emerald-400 flex items-center gap-1 hover:bg-emerald-100 dark:hover:bg-emerald-900">
                  <Copy size={12} /> Скопировать живые
                </button>
                <button onClick={exportAlive} className="px-2 py-1 rounded-lg border border-emerald-400 flex items-center gap-1 hover:bg-emerald-100 dark:hover:bg-emerald-900">
                  <Download size={12} /> Скачать .txt
                </button>
              </div>
            </div>
          )}
        </section>

        <section className="rounded-2xl border border-stone-200 dark:border-stone-800 bg-white dark:bg-stone-900 p-4">
          <div className="flex items-center gap-2 mb-3 flex-wrap">
            <Cpu size={16} />
            <h2 className="text-sm font-semibold">Ядра / модули</h2>
            <button onClick={() => downloadAll()} className="ml-auto text-xs px-2.5 py-1 rounded-lg bg-stone-900 dark:bg-stone-100 text-white dark:text-stone-900 flex items-center gap-1">
              <Download size={13} /> Скачать всё недостающее
            </button>
            <button onClick={() => loadCores(true)} className="text-xs px-2 py-1 rounded-lg border border-stone-300 dark:border-stone-700 flex items-center gap-1 hover:bg-stone-100 dark:hover:bg-stone-800">
              <RefreshCw size={13} /> Проверить обновления
            </button>
          </div>
          <div className="grid gap-2 md:grid-cols-2">
            {cores.map((c) => {
              const p = dlProg[c.id]
              const busy = p && (p.state === 'downloading' || p.state === 'extracting' || p.state === 'installing')
              return (
              <div key={c.id} className="rounded-xl border border-stone-200 dark:border-stone-800 p-3 text-sm grid gap-1">
                <div className="flex items-center gap-2">
                  <span className="font-medium font-mono">{c.name}</span>
                  {c.installed
                    ? <span className="text-[11px] px-1.5 py-0.5 rounded bg-emerald-100 dark:bg-emerald-900 text-emerald-700 dark:text-emerald-200">{c.version || 'установлено'}</span>
                    : <span className="text-[11px] px-1.5 py-0.5 rounded bg-stone-200 dark:bg-stone-800 text-stone-600 dark:text-stone-300">не скачано</span>}
                  {c.updateAvailable && <span className="text-[11px] px-1.5 py-0.5 rounded bg-amber-200 dark:bg-amber-900 text-amber-800 dark:text-amber-200">→ {c.latest}</span>}
                  <span className="ml-auto text-[11px] text-stone-500 font-mono">{c.id}</span>
                </div>
                <p className="text-xs text-stone-500">{c.description}</p>
                <p className="text-[11px] font-mono text-stone-500 truncate">{c.supports.join(' · ')}</p>
                {busy ? (
                  <div className="grid gap-1">
                    <div className="h-1.5 rounded bg-stone-200 dark:bg-stone-800 overflow-hidden">
                      <div className="h-1.5 bg-emerald-500 transition-all" style={{ width: `${p.percent || 2}%` }} />
                    </div>
                    <span className="text-[11px] text-stone-500">{p.stage || p.state} {p.percent ? `${p.percent}%` : ''}</span>
                  </div>
                ) : (
                  <div className="flex items-center gap-2">
                    {(!c.installed || c.updateAvailable) && c.id !== 'direct' && (
                      <button onClick={() => downloadCore(c.id)} className="text-xs px-2.5 py-1 rounded-lg bg-emerald-600 text-white hover:bg-emerald-500">
                        {!c.installed ? `Скачать ${c.latest}` : c.id === 'mtproto-checker' ? 'Переустановить' : `Обновить до ${c.latest}`}
                      </button>
                    )}
                    {p?.state === 'error' && <span className="text-[11px] text-red-500">{p.error}</span>}
                    {p?.state === 'done' && <span className="text-[11px] text-emerald-600">готово, обновите список</span>}
                    {!c.installed && c.downloadUrl && (
                      <a href={c.downloadUrl} target="_blank" rel="noreferrer" className="text-[11px] text-stone-500 underline">
                        прямая ссылка
                      </a>
                    )}
                  </div>
                )}
              </div>
              )
            })}
            {cores.length === 0 && <p className="text-xs text-stone-500">Загрузка…</p>}
          </div>
          <p className="text-[11px] text-stone-500 mt-2">Проверка — только URL-тестом через прокси (test URL из настроек), без TCP/ICMP-пингов. Фолбэк: sing-box → mihomo → xray · tg-ссылки → mtproto-checker · http/socks → встроенный direct. Бинарники лежат в <code className="font-mono">cores/</code> рядом с бинарником.</p>
        </section>

        <section className="rounded-2xl border border-stone-200 dark:border-stone-800 bg-white dark:bg-stone-900 p-4">
          <div className="flex items-center gap-2 mb-3 flex-wrap">
            <Filter size={15} />
            <div className="flex gap-1 text-xs">
              {(['all', 'alive', 'dead'] as const).map((f) => (
                <button key={f} onClick={() => setFilter(f)}
                  className={`px-2.5 py-1 rounded-lg ${filter === f ? 'bg-stone-900 dark:bg-stone-100 text-white dark:text-stone-900' : 'hover:bg-stone-200 dark:hover:bg-stone-800'}`}>
                  {f === 'all' ? 'Все' : f === 'alive' ? 'Живые' : 'Мёртвые'}
                </button>
              ))}
            </div>
            <div className="flex gap-1 text-xs flex-wrap items-center">
              <span className="text-stone-500">Протоколы:</span>
              {protoSel.length === 0
                ? <span className="px-2 py-0.5 text-stone-500">все</span>
                : <button onClick={() => setProtoSel([])} className="px-2 py-0.5 rounded-lg border border-stone-300 dark:border-stone-700 hover:bg-stone-100 dark:hover:bg-stone-800">сбросить</button>}
              {PROTO_LIST.map((p) => {
                const on = protoSel.includes(p)
                return (
                  <button key={p} onClick={() => setProtoSel((s) => on ? s.filter((x) => x !== p) : [...s, p])}
                    className={`px-2 py-0.5 rounded-lg font-mono border ${on ? 'bg-stone-900 dark:bg-stone-100 text-white dark:text-stone-900 border-stone-900 dark:border-stone-100' : 'border-stone-300 dark:border-stone-700 hover:bg-stone-200 dark:hover:bg-stone-800'}`}>
                    {p}
                  </button>
                )
              })}
            </div>
            <div className="ml-auto flex gap-1.5">
              <Btn onClick={copyAlive} icon={<Copy size={13} />} label="Живые" />
              <Btn onClick={exportAlive} icon={<Download size={13} />} label=".txt" />
              <Btn onClick={exportJSON} icon={<Download size={13} />} label=".json" />
              <Btn onClick={exportCSV} icon={<Download size={13} />} label=".csv" />
              <Btn onClick={() => exportPNG(results)} icon={<Image size={13} />} label="PNG" />
            </div>
          </div>
          <div className="grid gap-1.5">
            <AnimatePresence initial={false}>
              {filtered.map((r) => (
                <ResultRow key={r.index} r={r} hasToken={twoip.hasToken} />
              ))}
            </AnimatePresence>
            {filtered.length === 0 && (
              <p className="text-sm text-stone-500 py-6 text-center">Пока пусто — вставьте ссылки и нажмите «Проверить»</p>
            )}
          </div>
        </section>
        </>)}
      </main>
    </div>
  )
}






function Toggle({ on, onClick, label, small }: { on: boolean; onClick: () => void; label: string; small?: boolean }) {
  return (
    <button onClick={onClick} className={`flex items-center gap-2 ${small ? 'text-xs text-stone-500' : 'text-sm'} text-left`}>
      <span className={`relative shrink-0 rounded-full transition-colors ${on ? 'bg-emerald-500' : 'bg-stone-300 dark:bg-stone-700'}`} style={{ width: 34, height: 20 }}>
        <span className="absolute top-0.5 w-[16px] h-[16px] rounded-full bg-white shadow transition-all" style={{ left: on ? 16 : 2 }} />
      </span>
      {label}
    </button>
  )
}

function Stat({ label, value, green, red }: { label: string; value: string | number; green?: boolean; red?: boolean }) {
  return (
    <div className="flex items-baseline gap-1.5">
      <span className="text-xs text-stone-500">{label}:</span>
      <span className={`font-semibold font-mono ${green ? 'text-emerald-600' : red ? 'text-red-500' : ''}`}>{value}</span>
    </div>
  )
}

function Btn({ onClick, icon, label }: { onClick: () => void; icon: React.ReactNode; label: string }) {
  return (
    <button onClick={onClick} className="text-xs px-2 py-1 rounded-lg border border-stone-300 dark:border-stone-700 flex items-center gap-1 hover:bg-stone-100 dark:hover:bg-stone-800">
      {icon} {label}
    </button>
  )
}

function trunc(s: string, n: number) {
  return s.length > n ? s.slice(0, n - 1) + '…' : s
}

// exportPNG рисует сводку по результатам на canvas и отдаёт PNG-файл.
// Без внешних библиотек: один файл, работает офлайн.
function exportPNG(results: CheckResult[]) {
  const rows = results.slice(0, 80)
  const W = 1400, rowH = 34, headH = 150
  const H = headH + rows.length * rowH + 70
  const dpr = 2
  const canvas = document.createElement('canvas')
  canvas.width = W * dpr
  canvas.height = H * dpr
  const ctx = canvas.getContext('2d')
  if (!ctx) return
  ctx.scale(dpr, dpr)

  ctx.fillStyle = '#fafaf9'
  ctx.fillRect(0, 0, W, H)

  ctx.fillStyle = '#1c1917'
  ctx.font = 'bold 28px sans-serif'
  ctx.fillText('Proxy Checker — отчёт', 40, 56)
  const alive = results.filter((r) => r.alive).length
  ctx.fillStyle = '#57534e'
  ctx.font = '14px sans-serif'
  ctx.fillText(`Всего: ${results.length} · живых: ${alive} · мёртвых: ${results.length - alive} · ${new Date().toLocaleString('ru-RU')}`, 40, 84)

  ctx.fillStyle = '#78716c'
  ctx.font = 'bold 12px monospace'
  ctx.fillText('СТАТУС', 40, 122)
  ctx.fillText('ПРОТОКОЛ', 130, 122)
  ctx.fillText('ХОСТ', 260, 122)
  ctx.fillText('МС', 940, 122)
  ctx.fillText('ЯДРО', 1010, 122)
  ctx.strokeStyle = '#e7e5e4'
  ctx.beginPath()
  ctx.moveTo(40, 132)
  ctx.lineTo(W - 40, 132)
  ctx.stroke()

  rows.forEach((r, i) => {
    const y = headH + i * rowH + 22
    if (i % 2) {
      ctx.fillStyle = '#f5f5f4'
      ctx.fillRect(40, y - 26, W - 80, rowH)
    }
    ctx.fillStyle = r.alive ? '#10b981' : '#a8a29e'
    ctx.beginPath()
    ctx.arc(52, y - 5, 5, 0, Math.PI * 2)
    ctx.fill()

    ctx.font = '13px monospace'
    ctx.fillStyle = '#292524'
    ctx.fillText(r.protocol || '?', 130, y)
    ctx.fillText(trunc(r.host || r.link, 78), 260, y)
    ctx.textAlign = 'right'
    ctx.fillText(r.alive ? String(r.latencyMs) : '—', 940, y)
    ctx.textAlign = 'left'
    ctx.fillStyle = '#78716c'
    ctx.fillText(trunc(r.core, 16), 1010, y)
  })

  if (results.length > rows.length) {
    ctx.fillStyle = '#78716c'
    ctx.font = '13px sans-serif'
    ctx.fillText(`… ещё ${results.length - rows.length} строк`, 40, headH + rows.length * rowH + 40)
  }

  canvas.toBlob((blob) => {
    if (!blob) return
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = 'proxy-checker.png'
    a.click()
    setTimeout(() => URL.revokeObjectURL(a.href), 3000)
  }, 'image/png')
}

function download(name: string, content: string) {
  const a = document.createElement('a')
  a.href = URL.createObjectURL(new Blob([content], { type: 'text/plain' }))
  a.download = name
  a.click()
  setTimeout(() => URL.revokeObjectURL(a.href), 2000)
}
function csvq(s: string) { return '"' + s.replace(/"/g, '""') + '"' }
async function resJson<T>(r: Response): Promise<T> {
  if (!r.ok) throw new Error(await r.text())
  return r.json()
}
