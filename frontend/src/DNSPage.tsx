import { useEffect, useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Play, Plus, Trash2 } from 'lucide-react'

function GeoPoolNote() {
  const [t, setT] = useState('')
  useEffect(() => {
    fetch('/api/geo/pool').then((r) => r.json()).then((d) => setT(`2ip-гео: ${d.via}${d.socks ? ` (${d.socks} socks)` : ''}`)).catch(() => {})
  }, [])
  return t ? <span>{t}</span> : null
}

type Resolver = { id: string; name: string; region?: string; cc?: string; ip: string; serverName?: string; doh?: string; transports: string[]; builtin: boolean; default?: boolean }
type Row = { resolver: string; transport: string; ok: boolean; ms: number; answers?: string[]; asn?: string[]; rcode?: string; spoofSuspect?: boolean; error?: string }

const ALL_T = ['udp', 'tcp', 'dot', 'doh', 'doq']

// Страница /dns: сверка резолвинга домена через разные DNS × транспорты.
export default function DNSPage({ showToast }: { showToast: (m: string) => void }) {
  const [target, setTarget] = useState('')
  const [resolvers, setResolvers] = useState<Resolver[]>([])
  const [sel, setSel] = useState<string[]>([])
  const [running, setRunning] = useState(false)
  const [prog, setProg] = useState({ done: 0, total: 0 })
  const [res, setRes] = useState<{ baseline: string[]; rows: Row[] } | null>(null)
  const [showAdd, setShowAdd] = useState(false)
  const [form, setForm] = useState({ name: '', ip: '', serverName: '', doh: '', transports: ['udp', 'tcp'] as string[] })

  async function load() {
    try {
      const r = await fetch('/api/dnscomp/resolvers')
      const list = (await r.json()) as Resolver[]
      setResolvers(list)
      setSel((prev) => (prev.length ? prev : list.filter((x) => x.default).map((x) => x.id)))
    } catch {}
  }
  useEffect(() => { void load() }, [])

  async function run() {
    const t = target.trim().split(/[\s/:?#]+/)[0].replace(/^.*:\/\/([^/]+).*$/, '$1')
    if (!t) { showToast('Введите домен'); return }
    setRunning(true)
    setRes(null)
    setProg({ done: 0, total: 0 })
    try {
      const r = await fetch('/api/dnscomp', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ target: t, ids: sel }) })
      if (!r.ok) throw new Error(await r.text())
      const { id } = await r.json()
      for (let i = 0; i < 90; i++) {
        await new Promise((res2) => setTimeout(res2, 1000))
        const jr = await fetch(`/api/dnscomp/${id}`)
        if (!jr.ok) break
        const data = await jr.json()
        setProg({ done: data.done, total: data.total })
        setRes({ baseline: data.baseline || [], rows: data.rows || [] })
        if (data.finished) break
      }
    } catch (e) {
      showToast(String(e))
    }
    setRunning(false)
  }

  async function add() {
    try {
      const r = await fetch('/api/dnscomp/resolvers', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(form) })
      if (!r.ok) throw new Error(await r.text())
      const list = (await r.json()) as Resolver[]
      setResolvers(list)
      setShowAdd(false)
      setForm({ name: '', ip: '', serverName: '', doh: '', transports: ['udp', 'tcp'] })
    } catch (e) {
      showToast(String(e))
    }
  }

  async function del(id: string) {
    await fetch('/api/dnscomp/resolvers/del', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ id }) })
    void load()
  }

  const toggleT = (t: string) => setForm((f) => ({ ...f, transports: f.transports.includes(t) ? f.transports.filter((x) => x !== t) : [...f.transports, t] }))

  const pct = prog.total ? Math.round((prog.done / prog.total) * 100) : 0
  const C = 2 * Math.PI * 18

  return (
    <section className="rounded-2xl border border-stone-200 dark:border-stone-800 bg-white dark:bg-stone-900 p-4 grid gap-3">
      <div className="flex items-center gap-2 flex-wrap">
        <span className="text-sm font-medium">Сверка DNS</span>
        <span className="text-xs text-stone-500">один домен через разные резолверы × UDP/TCP/DoT/DoH/DoQ — расхождения подсвечиваются</span>
        {(running || prog.total > 0) && (
          <span className="ml-auto flex items-center gap-2">
            <svg width="44" height="44" viewBox="0 0 44 44" className="-rotate-90">
              <circle cx="22" cy="22" r="18" fill="none" strokeWidth="5" className="stroke-stone-200 dark:stroke-stone-800" />
              <circle cx="22" cy="22" r="18" fill="none" strokeWidth="5" strokeLinecap="round"
                className="stroke-emerald-500 transition-all duration-500"
                strokeDasharray={C} strokeDashoffset={C * (1 - pct / 100)} />
            </svg>
            <span className="text-xs font-mono rotate-0">{running && !prog.total ? '…' : `${pct}% · ${prog.done}/${prog.total}`}</span>
          </span>
        )}
      </div>
      <div className="flex gap-2">
        <input value={target} onChange={(e) => setTarget(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && run()} spellCheck={false}
          placeholder="example.com"
          className="flex-1 rounded-xl border border-stone-300 dark:border-stone-700 bg-stone-50 dark:bg-stone-950 px-3 py-2 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-stone-400" />
        <button onClick={run} disabled={running} className="px-4 py-2 rounded-xl bg-stone-900 dark:bg-stone-100 text-white dark:text-stone-900 flex items-center gap-1.5 text-sm disabled:opacity-50">
          <Play size={15} /> {running ? 'Жду…' : 'Сверить'}
        </button>
      </div>
      <div className="grid gap-2">
        {(['global', 'privacy', 'family', 'europe', 'namerica', 'asia', 'russia', ''] as const).map((rg) => {
          const items = resolvers.filter((x) => (x.region || '') === rg)
          if (!items.length) return null
          const label = { global: 'Глобальные', privacy: 'Приватность', family: 'Семейные', europe: 'Европа', namerica: 'Северная Америка', asia: 'Азия', russia: 'Россия', '': 'Без региона' }[rg]
          return (
            <div key={rg || 'none'} className="flex gap-1.5 flex-wrap items-center">
              <span className="text-[11px] text-stone-500 w-full">{label}</span>
              {items.map((r) => {
                const on = sel.includes(r.id)
                return (
                  <span key={r.id} className={`flex items-center gap-1 px-2 py-0.5 rounded-lg border text-xs ${on ? 'border-emerald-500' : 'border-stone-300 dark:border-stone-700 opacity-60'}`}>
                    <button onClick={() => setSel((s) => (on ? s.filter((x) => x !== r.id) : [...s, r.id]))} className="font-medium flex items-center gap-1">
                      {r.cc && <img src={`https://flagcdn.com/${r.cc.toLowerCase()}.svg`} alt={r.cc} width={14} height={10} className="inline rounded-[2px]" loading="lazy" />}
                      {r.name}
                    </button>
                    <span className="font-mono text-[10px] text-stone-500">{r.ip} · {r.transports.join('/')}</span>
                    {!r.builtin && <button onClick={() => del(r.id)} title="Удалить"><Trash2 size={12} /></button>}
                  </span>
                )
              })}
            </div>
          )
        })}
        <button onClick={() => setShowAdd(!showAdd)} className="flex items-center gap-1 text-xs px-2 py-0.5 rounded-lg border border-dashed border-stone-400 hover:bg-stone-100 dark:hover:bg-stone-800 w-fit">
          <Plus size={13} /> свой
        </button>
      </div>
      <AnimatePresence initial={false}>
        {showAdd && (
          <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.25 }} className="overflow-hidden">
            <div className="grid gap-2 rounded-xl border border-stone-200 dark:border-stone-800 p-3 md:grid-cols-2">
              <input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="Название" className="rounded-lg border border-stone-300 dark:border-stone-700 bg-transparent px-2 py-1 text-sm" />
              <input value={form.ip} onChange={(e) => setForm({ ...form, ip: e.target.value })} placeholder="IP или host резолвера" spellCheck={false} className="rounded-lg border border-stone-300 dark:border-stone-700 bg-transparent px-2 py-1 text-sm font-mono" />
              <input value={form.serverName} onChange={(e) => setForm({ ...form, serverName: e.target.value })} placeholder="SNI для DoT/DoQ (необязательно)" spellCheck={false} className="rounded-lg border border-stone-300 dark:border-stone-700 bg-transparent px-2 py-1 text-sm font-mono" />
              <input value={form.doh} onChange={(e) => setForm({ ...form, doh: e.target.value })} placeholder="DoH URL (необязательно)" spellCheck={false} className="rounded-lg border border-stone-300 dark:border-stone-700 bg-transparent px-2 py-1 text-sm font-mono" />
              <div className="flex gap-1.5 items-center md:col-span-2">
                {ALL_T.map((t) => (
                  <button key={t} onClick={() => toggleT(t)}
                    className={`px-2 py-0.5 rounded-lg border font-mono text-xs ${form.transports.includes(t) ? 'border-emerald-500 bg-emerald-50 dark:bg-emerald-950' : 'border-stone-300 dark:border-stone-700 opacity-60'}`}>
                    {t === 'doh' ? 'DoH' : t === 'dot' ? 'DoT' : t === 'doq' ? 'DoQ' : t.toUpperCase()}
                  </button>
                ))}
                <button onClick={add} className="ml-auto text-xs px-3 py-1 rounded-lg bg-stone-900 dark:bg-stone-100 text-white dark:text-stone-900">Добавить</button>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
      {res && (
        <div className="grid gap-2">
          <div className="text-xs text-stone-500">
            Консенсус: <span className="font-mono">{res.baseline.join(', ') || '—'}</span>
            <span className="ml-2">⚠ «отличается» — ноль пересечений с остальными при сильном консенсусе; round-robin/ECS у легитимных резолверов тоже дают разброс — смотрите глазами.</span>
          </div>
          <div className="grid gap-px rounded-xl overflow-hidden border border-stone-200 dark:border-stone-800">
            {res.rows.map((r, i) => (
              <div key={i} className={`flex items-center gap-2 px-2.5 py-1.5 text-xs ${r.spoofSuspect ? 'bg-red-50 dark:bg-red-950' : 'bg-white dark:bg-stone-900'}`}>
                <span className="w-28 shrink-0 font-medium truncate">{r.resolver}</span>
                <span className="w-10 shrink-0 font-mono text-[11px] text-stone-500">{r.transport === 'doh' ? 'DoH' : r.transport === 'dot' ? 'DoT' : r.transport === 'doq' ? 'DoQ' : r.transport.toUpperCase()}</span>
                {r.ok
                  ? <>
                    <span className="font-mono text-emerald-600 shrink-0">{r.ms} мс</span>
                    <span className="font-mono text-[11px] truncate text-stone-600 dark:text-stone-300">{(r.answers || []).join(', ')}</span>
                    {(r.asn?.length || 0) > 0 && <span className="font-mono text-[10px] px-1 rounded bg-stone-100 dark:bg-stone-800 text-stone-500 shrink-0">{r.asn!.join(' ')}</span>}
                    {r.spoofSuspect && <span className="ml-auto shrink-0 px-1.5 py-0.5 rounded bg-red-100 dark:bg-red-900 text-red-700 dark:text-red-200 font-mono text-[11px]">⚠ отличается</span>}
                  </>
                  : <span className="font-mono text-[11px] text-red-500">{r.error || '—'}</span>}
              </div>
            ))}
          </div>
        </div>
      )}
      <div className="text-[11px] text-stone-500 pt-1">
        Справочник DNS — <a href="https://dns.quic.best/" target="_blank" rel="noreferrer" className="underline">dns.quic.best</a> (90 резолверов, пресеты встроены выше)
        {' · '}<GeoPoolNote />
      </div>
    </section>
  )
}
