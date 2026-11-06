import { useEffect, useState } from 'react'
import { Play, Loader2, Gauge, Globe, Shield, Download, Upload, HelpCircle, CheckCircle2, XCircle } from 'lucide-react'
import type { SpeedResult, SpeedServer, UnlockResult, ReputationResult } from './types'

const inputCls = 'flex-1 rounded-xl border border-stone-300 dark:border-stone-700 bg-stone-50 dark:bg-stone-950 px-3 py-2 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-stone-400'
const btnCls = 'px-4 py-2 rounded-xl bg-stone-900 dark:bg-stone-100 text-white dark:text-stone-900 flex items-center gap-1.5 text-sm whitespace-nowrap disabled:opacity-50'
const cardCls = 'rounded-2xl border border-stone-200 dark:border-stone-800 bg-white dark:bg-stone-900 p-4 grid gap-3'
const noteCls = 'text-[11px] text-stone-500'

function LinkBox({ value, onChange, placeholder }: { value: string; onChange: (v: string) => void; placeholder: string }) {
  return (
    <input value={value} onChange={(e) => onChange(e.target.value)} spellCheck={false} placeholder={placeholder} className={inputCls} />
  )
}

export function SpeedPage() {
  const [link, setLink] = useState('')
  const [servers, setServers] = useState<SpeedServer[]>([])
  const [selected, setSelected] = useState('cloudflare')
  const [sizeMb, setSizeMb] = useState(20)
  const [upload, setUpload] = useState(false)
  const [busy, setBusy] = useState(false)
  const [busyAll, setBusyAll] = useState<string | null>(null)
  const [result, setResult] = useState<SpeedResult | null>(null)
  const [history, setHistory] = useState<(SpeedResult & { at: string; sizeMb: number })[]>([])

  useEffect(() => {
    fetch('/api/speed/servers').then((r) => r.json()).then((d) => {
      if (Array.isArray(d)) setServers(d)
    }).catch(() => {})
  }, [])

  async function measure(server: string): Promise<SpeedResult> {
    const r = await fetch('/api/speed', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        link: link.trim(),
        server,
        downBytes: sizeMb * 1024 * 1024,
        upBytes: upload ? 5 * 1024 * 1024 : 0,
      }),
    })
    return r.json()
  }

  async function run() {
    setBusy(true)
    try {
      const d = await measure(selected)
      setResult(d)
      setHistory((h) => [{ ...d, at: new Date().toLocaleTimeString('ru-RU'), sizeMb }, ...h].slice(0, 20))
    } catch (e) {
      setResult({ ok: false, error: e instanceof Error ? e.message : String(e) })
    } finally {
      setBusy(false)
    }
  }

  async function runAll() {
    setHistory([])
    for (const s of servers) {
      setBusyAll(s.id)
      try {
        const d = await measure(s.id)
        setResult(d)
        setHistory((h) => [...h, { ...d, at: new Date().toLocaleTimeString('ru-RU'), sizeMb }])
      } catch (e) {
        setHistory((h) => [...h, { ok: false, server: s.name, error: String(e), at: new Date().toLocaleTimeString('ru-RU'), sizeMb }])
      }
    }
    setBusyAll(null)
  }

  const anyBusy = busy || !!busyAll
  return (
    <section className={cardCls}>
      <div className="flex items-center gap-2 flex-wrap">
        <Gauge size={17} />
        <h2 className="text-sm font-semibold">Скорость до разных серверов</h2>
        <span className={noteCls}>пустая ссылка = замер с этого компьютера напрямую</span>
      </div>
      <div className="flex gap-2 flex-wrap">
        <LinkBox value={link} onChange={setLink} placeholder="vless://… / ss://… / socks5://… (или пусто — напрямую)" />
        <button onClick={run} disabled={anyBusy} className={btnCls}>
          {busy ? <Loader2 size={15} className="animate-spin" /> : <Play size={15} />} Замерить
        </button>
        <button onClick={runAll} disabled={anyBusy || servers.length === 0} className={btnCls}>
          {busyAll ? <Loader2 size={15} className="animate-spin" /> : <Play size={15} />} Все серверы
        </button>
      </div>

      <div className="flex items-center gap-2 flex-wrap">
        <span className="text-xs text-stone-500">Сервер:</span>
        {servers.map((s) => (
          <button key={s.id} onClick={() => setSelected(s.id)}
            className={`px-2.5 py-1 rounded-lg border text-xs flex items-center gap-1 ${selected === s.id ? 'border-emerald-500 bg-emerald-50 dark:bg-emerald-950 text-emerald-700 dark:text-emerald-200' : 'border-stone-300 dark:border-stone-700 hover:bg-stone-100 dark:hover:bg-stone-800'}`}>
            {s.name} <span className="text-[10px] text-stone-500">{s.region}</span>
            {s.upload && <Upload size={10} />}
            {busyAll === s.id && <Loader2 size={10} className="animate-spin" />}
          </button>
        ))}
        {servers.length === 0 && <span className="text-xs text-stone-500">загрузка списка…</span>}
      </div>

      <div className="flex items-center gap-3 flex-wrap text-xs">
        <label className="flex items-center gap-1">Размер:
          <select value={sizeMb} onChange={(e) => setSizeMb(+e.target.value)}
            className="rounded-lg border border-stone-300 dark:border-stone-700 bg-transparent px-1.5 py-1">
            {[10, 20, 50, 100].map((n) => <option key={n} value={n}>{n} МБ</option>)}
          </select>
        </label>
        <label className="flex items-center gap-1.5">
          <input type="checkbox" checked={upload} onChange={(e) => setUpload(e.target.checked)} />
          <Upload size={12} /> upload 5 МБ (только Cloudflare)
        </label>
      </div>

      {result && (
        <div className="rounded-xl border border-stone-200 dark:border-stone-800 p-3 grid gap-1">
          {result.ok ? (
            <>
              <div className="flex items-end gap-4 flex-wrap">
                <div className="text-2xl font-semibold font-mono text-emerald-600 dark:text-emerald-400">↓ {(result.downMbps ?? 0).toFixed(1)} Mbps</div>
                {(result.upMbps ?? 0) > 0 && <div className="text-xl font-semibold font-mono text-emerald-600 dark:text-emerald-400">↑ {(result.upMbps ?? 0).toFixed(1)} Mbps</div>}
              </div>
              <div className={noteCls}>
                {result.server} · {(result.downMb ?? 0).toFixed(1)} МБ за {result.latencyMs} мс · ядро {result.core}
                {result.upError ? ` · upload: ${result.upError}` : ''}
              </div>
            </>
          ) : (
            <div className="text-sm text-red-500">{result.error}</div>
          )}
        </div>
      )}

      {history.length > 0 && (
        <div className="grid gap-1">
          <div className="grid grid-cols-[1fr_auto_auto_auto] gap-2 text-[10px] font-semibold tracking-wide text-stone-500">
            <span>СЕРВЕР</span><span>DOWN</span><span>UP</span><span>КОГДА</span>
          </div>
          {history.map((h, i) => (
            <div key={i} className="grid grid-cols-[1fr_auto_auto_auto] gap-2 items-center text-xs border-t border-stone-100 dark:border-stone-800 pt-1">
              <span className="truncate">{h.server || '—'} <span className="text-[10px] text-stone-500">{h.sizeMb} МБ</span></span>
              <span className={`font-mono ${h.ok ? 'text-emerald-600 dark:text-emerald-400' : 'text-red-500'}`}>
                {h.ok ? `${(h.downMbps ?? 0).toFixed(1)}` : '—'}
              </span>
              <span className="font-mono text-stone-500">{h.ok && (h.upMbps ?? 0) > 0 ? `${(h.upMbps ?? 0).toFixed(1)}` : '—'}</span>
              <span className="text-[10px] text-stone-500">{h.at}</span>
            </div>
          ))}
        </div>
      )}
      <p className={noteCls}>
        <Download size={11} className="inline" /> Cloudflare/CacheFly/Vultr/Yandex Mirror отдают Range, поэтому качается только выбранный объём.
        Upload есть только у Cloudflare. Для 100-МБ серверов при размере 10–20 МБ запрос обрывается после лимита.
      </p>
    </section>
  )
}

export function UnlockPage() {
  const [link, setLink] = useState('')
  const [busy, setBusy] = useState(false)
  const [res, setRes] = useState<UnlockResult | null>(null)

  async function run() {
    setBusy(true)
    try {
      const r = await fetch('/api/unlock', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ link: link.trim() }),
      })
      setRes(await r.json())
    } catch (e) {
      setRes({ ok: false, error: e instanceof Error ? e.message : String(e) })
    } finally {
      setBusy(false)
    }
  }

  const color = (s: string) => s === 'yes' ? 'text-emerald-600 dark:text-emerald-400' : s === 'no' ? 'text-red-500' : s === 'unknown' ? 'text-stone-500' : 'text-amber-600'
  const label = (s: string) => s === 'yes' ? 'доступно' : s === 'no' ? 'недоступно' : s === 'unknown' ? 'неизвестно' : 'ошибка'

  return (
    <section className={cardCls}>
      <div className="flex items-center gap-2 flex-wrap">
        <Globe size={17} />
        <h2 className="text-sm font-semibold">Unlock — доступность сервисов через прокси</h2>
        <span className={noteCls}>пустая ссылка = проверка с этого компьютера</span>
      </div>
      <div className="flex gap-2 flex-wrap">
        <LinkBox value={link} onChange={setLink} placeholder="vless://… / ss://… (или пусто — локально)" />
        <button onClick={run} disabled={busy} className={btnCls}>
          {busy ? <Loader2 size={15} className="animate-spin" /> : <Play size={15} />} Проверить
        </button>
      </div>
      {res && (
        res.ok ? (
          <div className="grid gap-2 sm:grid-cols-2">
            {(res.services ?? []).map((s) => (
              <div key={s.id} className="rounded-xl border border-stone-200 dark:border-stone-800 p-3 flex items-center gap-2 text-sm">
                {s.status === 'yes' ? <CheckCircle2 size={17} className="text-emerald-500" /> : s.status === 'no' ? <XCircle size={17} className="text-red-500" /> : <HelpCircle size={17} className="text-stone-400" />}
                <span className="font-medium">{s.name}</span>
                {s.region && <span className="font-mono text-[10px] text-stone-500">{s.region}</span>}
                <span className={`ml-auto text-xs ${color(s.status)}`}>{label(s.status)}</span>
                {s.detail && <span className="text-[10px] text-stone-500 w-full truncate" title={s.detail}>{s.detail}</span>}
              </div>
            ))}
            <div className={`text-[11px] text-stone-500 sm:col-span-2`}>через {res.core}</div>
          </div>
        ) : <div className="text-sm text-red-500">{res.error}</div>
      )}
      <p className={noteCls}>YouTube Premium, Netflix, ChatGPT (регион из cdn-cgi/trace), Spotify. Проверки идут параллельно, каждая — реальным запросом через прокси.</p>
    </section>
  )
}

export function IpPage() {
  const [link, setLink] = useState('')
  const [busy, setBusy] = useState(false)
  const [res, setRes] = useState<ReputationResult | null>(null)

  async function run() {
    setBusy(true)
    try {
      const r = await fetch('/api/reputation', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ link: link.trim() }),
      })
      setRes(await r.json())
    } catch (e) {
      setRes({ ok: false, error: e instanceof Error ? e.message : String(e) })
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className={cardCls}>
      <div className="flex items-center gap-2 flex-wrap">
        <Shield size={17} />
        <h2 className="text-sm font-semibold">IP и репутация</h2>
        <span className={noteCls}>какой IP видит мир + нахождение в спам-блэклистах (DNSBL), а не РКН</span>
      </div>
      <div className="flex gap-2 flex-wrap">
        <LinkBox value={link} onChange={setLink} placeholder="vless://… / ss://… (пусто = IP этого компьютера)" />
        <button onClick={run} disabled={busy} className={btnCls}>
          {busy ? <Loader2 size={15} className="animate-spin" /> : <Play size={15} />} Проверить
        </button>
      </div>
      {res && (
        res.ok ? (
          <div className="grid gap-3">
            <div className="flex items-center gap-4 flex-wrap">
              <div className="text-2xl font-semibold font-mono">{res.exitIp}</div>
              <div className="text-sm text-stone-500">{res.country}{res.asn ? ` · ${res.asn}` : ''}</div>
              <div className={`ml-auto text-sm font-semibold ${res.listed ? 'text-red-500' : 'text-emerald-600 dark:text-emerald-400'}`}>
                {res.listed ? `в блэклистах: ${res.listed}` : 'в DNSBL чист'}
              </div>
            </div>
            <div className="grid gap-1 sm:grid-cols-2">
              {(res.lists ?? []).map((l) => (
                <div key={l.zone} className="flex items-center gap-2 text-xs rounded-lg border border-stone-200 dark:border-stone-800 px-2 py-1" title={l.detail}>
                  <span className={`w-2 h-2 rounded-full shrink-0 ${l.status === 'listed' ? 'bg-red-500' : l.status === 'clean' ? 'bg-emerald-500' : 'bg-stone-400'}`} />
                  <span className="truncate flex-1">{l.name}</span>
                  <span className="text-[10px] text-stone-500">{l.status === 'listed' ? l.detail : l.status}</span>
                </div>
              ))}
            </div>
          </div>
        ) : <div className="text-sm text-red-500">{res.error}</div>
      )}
      <p className={noteCls}>
        «В блэклистах» = exit-IP прокси числится в спам-базах (Spamhaus, SpamCop, Barracuda и др.) — с таким IP часть сайтов будет показывать капчу или отказ.
        Это <b>не</b> блокировка сайта по РКН: её смотрят в «Тестах» → «Всё сразу» (вердикт РКН) и пробах из РФ.
      </p>
    </section>
  )
}