import { useEffect, useRef, useState } from 'react'
import { Play } from 'lucide-react'
import { useFullReport, FullPanel, FilterBar, CHECK_GROUPS, type CheckKey } from './report'

function allOn(): Record<CheckKey, boolean> {
  const o = {} as Record<CheckKey, boolean>
  for (const g of CHECK_GROUPS) for (const k of g.keys) o[k] = true
  return o
}


// Отдельная страница /test: вся внешняя проверка произвольного хоста
// (не ключей) — как страница чебурчека, всё сразу и в одном месте.
export default function TestPage({ hasToken, showToast }: { hasToken: boolean; showToast: (m: string) => void }) {
  const [input, setInput] = useState('')
  const [target, setTarget] = useState('')
  const [sel, setSel] = useState<Record<CheckKey, boolean>>(allOn)
  const [ruOnly, setRuOnly] = useState(false)
  const [ccTop, setCcTop] = useState<string[]>([])
  const [ccAvailTop, setCcAvailTop] = useState<string[]>([])

  const norm = (s: string) => {
    let t = s.trim()
    // из ссылки вытащить host:port
    const m = t.match(/^[a-z0-9+.-]+:\/\/([^/?#]+)/i)
    if (m) t = m[1]
    // tg-ссылки: server/port
    const srv = t.match(/server=([^&]+)/)
    if (srv) {
      const port = (t.match(/port=([0-9]+)/) || [])[1]
      t = srv[1] + (port ? ':' + port : '')
    }
    return t.replace(/\/.*$/, '')
  }

  function run() {
    const t = norm(input)
    if (!t) {
      showToast('Введите хост, host:port или ссылку')
      return
    }
    setTarget(t)
  }

  return (
    <section className="rounded-2xl border border-stone-200 dark:border-stone-800 bg-white dark:bg-stone-900 p-4 grid gap-3">
      <div className="flex items-center gap-2 flex-wrap">
        <span className="text-sm font-medium">Хост для тестов</span>
        <span className="text-xs text-stone-500">check-host · РКН/GEO · пробы РФ · globalping · keycdn · 2ip — всё сразу</span>
      </div>
      <div className="flex gap-2">
        <input value={input} onChange={(e) => setInput(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && run()} spellCheck={false}
          placeholder="example.com / 1.2.3.4:443 / vless://…"
          className="flex-1 rounded-xl border border-stone-300 dark:border-stone-700 bg-stone-50 dark:bg-stone-950 px-3 py-2 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-stone-400" />
        <button onClick={run} className="px-4 py-2 rounded-xl bg-stone-900 dark:bg-stone-100 text-white dark:text-stone-900 flex items-center gap-1.5 text-sm">
          <Play size={15} /> Проверить
        </button>
      </div>
      <FilterBar sel={sel} toggle={(k) => setSel((s) => ({ ...s, [k]: !s[k] }))} ruOnly={ruOnly} toggleRu={() => setRuOnly((v) => !v)}
        ccSel={ccTop} ccAvail={ccAvailTop} toggleCC={(c) => setCcTop((s) => (s.includes(c) ? s.filter((x) => x !== c) : [...s, c]))} />
      {target && <TestBody key={target} target={target} link={input.trim()} hasToken={hasToken} sel={sel} ruOnly={ruOnly} ccTop={ccTop} onCc={setCcAvailTop} />}
    </section>
  )
}

function TestBody({ target, link, hasToken, sel, ruOnly, ccTop, onCc }: { target: string; link: string; hasToken: boolean; sel: Record<CheckKey, boolean>; ruOnly: boolean; ccTop: string[]; onCc: (cc: string[]) => void }) {
  const f = useFullReport(target, link, 10, sel)
  const [started, setStarted] = useState(false)
  useEffect(() => {
    if (!started) {
      if (ruOnly) f.toggleRu()
      f.runSelected()
      setStarted(true)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [started])
  // верхние тумблеры продолжают рулить запущенной панелью
  useEffect(() => {
    if (!started) return
    (Object.keys(sel) as CheckKey[]).forEach((k) => {
      if (sel[k] !== f.sel[k]) f.toggle(k)
    })
    if (ruOnly !== f.ruOnly) f.toggleRu()
    const have = new Set(f.ccSel)
    const want = new Set(ccTop)
    for (const c of [...want, ...have]) {
      if (want.has(c) !== have.has(c)) f.toggleCC(c)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sel, ruOnly, ccTop, started])
  const lastCc = useRef<string>('')
  useEffect(() => {
    const key = [...f.ccAvail].sort().join(',')
    if (key !== lastCc.current) {
      lastCc.current = key
      onCc(f.ccAvail)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [f.ccAvail])
  if (!started) return <p className="text-sm text-stone-500">Запускаю…</p>
  return <FullPanel r={{ host: target, link, protocol: '', core: '', latencyMs: 0 }} f={f} hasToken={hasToken} showFilters={false} />
}
