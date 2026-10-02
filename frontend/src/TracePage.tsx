import { useEffect, useRef, useState } from 'react'
import { Play, Square, Route } from 'lucide-react'

export default function TracePage() {
  return <TraceBlock initial="" />
}

type TraceHop = { ttl: number; probes: { ip?: string; ms?: number }[] }

function TraceBlock({ initial }: { initial: string }) {
  const [target, setTarget] = useState(initial)
  const [jobId, setJobId] = useState<string | null>(null)
  const [hops, setHops] = useState<TraceHop[]>([])
  const [done, setDone] = useState(false)
  const [verdict, setVerdict] = useState('')
  const [error, setError] = useState('')
  const [running, setRunning] = useState(false)
  const stopRef = useRef(false)

  useEffect(() => { setTarget(initial) }, [initial])

  async function stop() {
    stopRef.current = true
    if (jobId) {
      try { await fetch(`/api/trace/${jobId}`, { method: 'DELETE' }) } catch {}
    }
    setRunning(false)
    setDone(true)
  }

  async function run() {
    const t = target.trim()
    if (!t || running) return
    stopRef.current = false
    setHops([])
    setDone(false)
    setRunning(true)
    setVerdict('')
    setError('')
    try {
      const r = await fetch('/api/trace', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ target: t, maxHops: 30 }) })
      if (!r.ok) throw new Error(await r.text())
      const { id } = await r.json()
      setJobId(id)
      for (let i = 0; i < 120; i++) {
        if (stopRef.current) break
        await new Promise((res) => setTimeout(res, 2000))
        if (stopRef.current) break
        const jr = await fetch(`/api/trace/${id}`)
        if (!jr.ok) break
        const data = await jr.json()
        setHops(data.hops || [])
        setVerdict(data.verdict || '')
        if (data.error) { setError(data.error); break }
        if (data.finished) { setDone(true); break }
      }
    } catch (e) {
      if (!stopRef.current) setError(String(e))
    }
    setRunning(false)
  }

  return (
    <section className="rounded-2xl border border-stone-200 dark:border-stone-800 bg-white dark:bg-stone-900 p-4 grid gap-3">
      <div className="flex items-center gap-2 flex-wrap">
        <Route size={15} />
        <span className="text-sm font-medium">Трейс маршрута</span>
        <span className="text-xs text-stone-500">UDP с растущим TTL, с твоего инета · *** = тишина (так выглядит и ТСПУ)</span>
      </div>
      <div className="flex gap-2">
        <input value={target} onChange={(e) => setTarget(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && run()} spellCheck={false}
          placeholder="example.com / 1.2.3.4"
          className="flex-1 rounded-xl border border-stone-300 dark:border-stone-700 bg-stone-50 dark:bg-stone-950 px-3 py-2 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-stone-400" />
        <button onClick={run} disabled={running} className="px-4 py-2 rounded-xl bg-stone-900 dark:bg-stone-100 text-white dark:text-stone-900 flex items-center gap-1.5 text-sm disabled:opacity-50">
          <Play size={15} /> Трейс
        </button>
        {running && (
          <button onClick={stop} className="px-4 py-2 rounded-xl bg-red-600 text-white flex items-center gap-1.5 text-sm">
            <Square size={15} /> Стоп
          </button>
        )}
      </div>
      {verdict && (
        <div className={`rounded-xl px-3 py-2 text-sm ${verdict.startsWith('Достигнут') ? 'bg-emerald-50 dark:bg-emerald-950 text-emerald-700 dark:text-emerald-300' : 'bg-red-50 dark:bg-red-950 text-red-700 dark:text-red-300'}`}>
          {verdict}
        </div>
      )}
      {error && <div className="text-xs font-mono text-red-500">{error}</div>}
      {hops.length > 0 && (
        <div className="grid gap-px rounded-xl overflow-hidden border border-stone-200 dark:border-stone-800">
          {hops.map((h) => (
            <div key={h.ttl} className="flex items-center gap-3 px-3 py-1.5 bg-white dark:bg-stone-900 font-mono text-xs">
              <span className="w-6 shrink-0 text-stone-500">{h.ttl}</span>
              <span className="flex-1 flex gap-4 flex-wrap">
                {h.probes.map((p, i) => (
                  <span key={i} className={p.ip ? '' : 'text-stone-600'}>
                    {p.ip ? `${p.ip} ${(p.ms || 0).toFixed(1)} мс` : '* * *'}
                  </span>
                ))}
              </span>
            </div>
          ))}
        </div>
      )}
      {jobId && !done && !hops.length && <p className="text-sm text-stone-500 animate-pulse">Щупаю хопы…</p>}
    </section>
  )
}