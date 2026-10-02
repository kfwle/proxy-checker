import { useMemo, useState } from 'react'
import { RU_REGIONS } from './russiaMap'

export type MapProbe = { probeId?: string; region: string; provider: string; verdicts: string[]; asn?: string; dpiHop?: number | null; targetHop?: number | null; evidence?: string[] }

const DROP = new Set(['республика', 'область', 'край', 'автономный', 'автономная', 'автономное', 'округ', 'народная', 'народный', 'югра', 'имени'])

// Нормализация названий регионов к множеству токенов: "Республика Саха (Якутия)" -> {саха, якутия}
function tokens(s: string): Set<string> {
  return new Set(
    s.toLowerCase().replace(/[().,-]/g, ' ').split(/\s+/).filter((t) => t && !DROP.has(t)),
  )
}

function sameSet(a: Set<string>, b: Set<string>): boolean {
  if (a.size === 0 || b.size === 0) return false
  if (a.size !== b.size) return false
  for (const t of a) if (!b.has(t)) return false
  return true
}

type RegionVerdict = { worst: 'block' | 'ok' | 'unclear' | 'none'; probes: MapProbe[]; counts: Record<string, number>; okRatio: number }

function isOkProbe(p: MapProbe): boolean {
  if (!p.verdicts.length) return true
  return p.verdicts.every((v) => v === 'ok' || v === 'clean')
}

export function rankVerdict(v: string): 'block' | 'ok' | 'unclear' {
  if (v === 'tspu_block' || v === 'sni_block' || v === 'dns_spoofing') return 'block'
  if (v === 'ok' || v === 'clean') return 'ok'
  return 'unclear'
}

const FILL: Record<RegionVerdict['worst'], string> = {
  block: '#dc2626',
  ok: '#16a34a',
  unclear: '#57534e',
  none: '#1c1917',
}

// Частичная доступность: есть ok, но не все — зелёная штриховка.
// Блок важнее: хоть один block — сплошной красный.
function fillFor(v: RegionVerdict | undefined): string {
  if (!v || v.worst === 'none') return FILL.none
  if (v.worst === 'block') return FILL.block
  if (v.okRatio >= 1) return FILL.ok
  if (v.okRatio > 0) return 'url(#hatch-ok)'
  return FILL[v.worst]
}

export function groupByGeo(probes: MapProbe[]): { verdictByGeo: Map<string, RegionVerdict>; unmatched: MapProbe[] } {
  const geoTokens = RU_REGIONS.map((g) => ({ g, t: tokens(g.n) }))
  const verdictByGeo = new Map<string, RegionVerdict>()
  const unmatched: MapProbe[] = []
  // группируем пробы по региону
  const byRegion = new Map<string, MapProbe[]>()
  for (const p of probes) {
    if (!byRegion.has(p.region)) byRegion.set(p.region, [])
    byRegion.get(p.region)!.push(p)
  }
  for (const [region, list] of byRegion) {
    const pt = tokens(region)
    let hit: string | null = null
    for (const { g, t } of geoTokens) {
      if (sameSet(pt, t)) { hit = g.n; break }
    }
    if (!hit && pt.size === 1) {
      const tok = [...pt][0]
      const cand = geoTokens.find(({ t }) => t.has(tok))
      if (cand) hit = cand.g.n
    }
    if (!hit) {
      unmatched.push(...list)
      continue
    }
    let worst: RegionVerdict['worst'] = 'none'
    const counts: Record<string, number> = {}
    let okN = 0
    for (const p of list) {
      if (isOkProbe(p)) okN++
      if (p.verdicts.length === 0) {
        counts['clean'] = (counts['clean'] || 0) + 1
        if (worst === 'none') worst = 'ok'
        continue
      }
      for (const v of p.verdicts) {
        counts[v] = (counts[v] || 0) + 1
        const r = rankVerdict(v)
        if (r === 'block') worst = 'block'
        else if (r === 'unclear' && worst !== 'block') worst = 'unclear'
        else if (r === 'ok' && worst === 'none') worst = 'ok'
      }
    }
    verdictByGeo.set(hit, { worst, probes: list, counts, okRatio: list.length ? okN / list.length : 0 })
  }
  return { verdictByGeo, unmatched }
}

export default function RussiaMap({ probes, selected, onSelect }: { probes: MapProbe[]; selected?: string | null; onSelect?: (name: string | null) => void }) {
  const [hover, setHover] = useState<{ x: number; y: number; name: string } | null>(null)

  const { verdictByGeo, unmatched } = useMemo(() => groupByGeo(probes), [probes])

  const hoverData = hover ? verdictByGeo.get(hover.name) : null

  return (
    <div className="relative">
      <svg viewBox="0 0 1000 560" className="w-full rounded-lg bg-stone-950 border border-stone-800"
        onMouseLeave={() => setHover(null)}>
        <defs>
          <pattern id="hatch-ok" width="7" height="7" patternTransform="rotate(45)" patternUnits="userSpaceOnUse">
            <rect width="7" height="7" fill="#1c1917" />
            <line x1="0" y1="0" x2="0" y2="7" stroke="#16a34a" strokeWidth="2.5" />
          </pattern>
        </defs>
        {RU_REGIONS.map((g) => {
          const v = verdictByGeo.get(g.n)
          const isSel = selected === g.n
          return (
            <path key={g.n} d={g.d}
              fill={fillFor(v)}
              fillOpacity={v ? 0.85 : 0.5}
              stroke={isSel ? '#fbbf24' : '#44403c'} strokeWidth={isSel ? 2 : 1}
              style={{ cursor: v ? 'pointer' : 'default' }}
              onMouseMove={(e) => {
                if (!v) { setHover(null); return }
                const rect = (e.currentTarget.ownerSVGElement as SVGSVGElement).getBoundingClientRect()
                setHover({ x: e.clientX - rect.left, y: e.clientY - rect.top, name: g.n })
              }}
              onClick={() => {
                if (!v || !onSelect) return
                onSelect(isSel ? null : g.n)
              }}
            />
          )
        })}
      </svg>
      {hover && hoverData && (
        <div className="absolute z-10 pointer-events-none rounded-xl border border-stone-700 bg-stone-900 px-3 py-2 text-xs shadow-xl max-w-[240px]"
          style={{ left: Math.min(hover.x + 12, 320), top: Math.max(hover.y - 10, 8) }}>
          <div className="font-semibold">{hover.name}</div>
          <div className="text-stone-400">Сканеров: {hoverData.probes.length}</div>
          <div className="flex gap-1.5 mt-1 flex-wrap font-mono text-[11px]">
            {Object.entries(hoverData.counts).map(([k, n]) => (
              <span key={k} className={`px-1.5 py-0.5 rounded ${rankVerdict(k) === 'ok' || k === 'clean' ? 'bg-emerald-900 text-emerald-200' : rankVerdict(k) === 'block' ? 'bg-red-900 text-red-200' : 'bg-stone-700 text-stone-200'}`}>
                {k}: {n}
              </span>
            ))}
          </div>
          <div className="text-stone-500 mt-1 truncate">{hoverData.probes.slice(0, 3).map((p) => p.provider).join(' · ')}</div>
        </div>
      )}
      <div className="flex gap-3 mt-1.5 text-[11px] text-stone-500 flex-wrap">
        <span><i className="inline-block w-2 h-2 rounded-full bg-red-600 mr-1" />Блокировка</span>
        <span><i className="inline-block w-2 h-2 rounded-full bg-green-600 mr-1" />Доступно</span>
        <span className="flex items-center"><i className="inline-block w-2 h-2 rounded-full mr-1" style={{ background: 'repeating-linear-gradient(45deg,#16a34a 0 1.5px,#1c1917 1.5px 3.5px)' }} />Частично</span>
        <span><i className="inline-block w-2 h-2 rounded-full bg-stone-500 mr-1" />Неясно</span>
        <span><i className="inline-block w-2 h-2 rounded-full bg-stone-900 border border-stone-700 mr-1" />Нет данных</span>
      </div>
      {unmatched.length > 0 && (
        <div className="mt-1.5 text-[11px] text-stone-500">
          Вне контуров карты ({unmatched.length}): {[...new Set(unmatched.map((p) => p.region))].join(' · ')}
        </div>
      )}
    </div>
  )
}
