import { useState } from 'react'
import { TOOL_CONFIGS } from '../config/tools'

const SEV_CONFIG = {
  critical: { color: 'text-rose-400',    bg: 'bg-rose-500/10',    border: 'border-rose-500/30',    badge: 'bg-rose-500/20 text-rose-300 border-rose-500/40',    dot: 'bg-rose-400',    glow: '#f43f5e' },
  high:     { color: 'text-amber-400',   bg: 'bg-amber-500/10',   border: 'border-amber-500/30',   badge: 'bg-amber-500/20 text-amber-300 border-amber-500/40',   dot: 'bg-amber-400',   glow: '#f59e0b' },
  medium:   { color: 'text-yellow-300',  bg: 'bg-yellow-500/10',  border: 'border-yellow-500/30',  badge: 'bg-yellow-500/20 text-yellow-300 border-yellow-500/40',  dot: 'bg-yellow-300',  glow: '#eab308' },
  low:      { color: 'text-blue-400',    bg: 'bg-blue-500/10',    border: 'border-blue-500/30',    badge: 'bg-blue-500/20 text-blue-300 border-blue-500/40',    dot: 'bg-blue-400',    glow: '#3b82f6' },
  pass:     { color: 'text-emerald-400', bg: 'bg-emerald-500/10', border: 'border-emerald-500/30', badge: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40', dot: 'bg-emerald-400', glow: '#10b981' },
  info:     { color: 'text-cyan-400',    bg: 'bg-cyan-500/10',    border: 'border-cyan-500/30',    badge: 'bg-cyan-500/20 text-cyan-300 border-cyan-500/40',    dot: 'bg-cyan-400',    glow: '#06b6d4' },
}

const ORDER = { critical: 0, high: 1, medium: 2, low: 3, pass: 4, info: 5 }

// Export helpers
function exportJSON(findings) {
  const blob = new Blob([JSON.stringify(findings, null, 2)], { type: 'application/json' })
  const url  = URL.createObjectURL(blob)
  const a    = document.createElement('a'); a.href = url
  a.download = `bb-suite-findings-${Date.now()}.json`
  a.click(); URL.revokeObjectURL(url)
}

function exportCSV(findings) {
  const headers = ['severity', 'title', 'detail', 'recommendation', 'tool']
  const rows = findings.map(f =>
    headers.map(h => `"${String(f[h] || '').replace(/"/g, '""')}"`).join(',')
  )
  const csv  = [headers.join(','), ...rows].join('\n')
  const blob = new Blob([csv], { type: 'text/csv' })
  const url  = URL.createObjectURL(blob)
  const a    = document.createElement('a'); a.href = url
  a.download = `bb-suite-findings-${Date.now()}.csv`
  a.click(); URL.revokeObjectURL(url)
}

function SeverityBar({ counts, total }) {
  if (!total) return null
  const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info', 'pass']
  const COLORS = { critical: '#f43f5e', high: '#f59e0b', medium: '#eab308', low: '#3b82f6', info: '#06b6d4', pass: '#10b981' }
  return (
    <div className="space-y-1.5">
      <div className="flex h-2.5 rounded-full overflow-hidden bg-black/30 gap-px">
        {SEV_ORDER.map(sev => {
          const pct = ((counts[sev] || 0) / total) * 100
          if (pct === 0) return null
          return (
            <div
              key={sev}
              title={`${sev}: ${counts[sev]}`}
              style={{ width: `${pct}%`, background: COLORS[sev], boxShadow: `0 0 6px ${COLORS[sev]}60` }}
              className="h-full transition-all duration-500 first:rounded-l-full last:rounded-r-full"
            />
          )
        })}
      </div>
      <div className="flex flex-wrap gap-3">
        {SEV_ORDER.filter(s => counts[s] > 0).map(sev => (
          <div key={sev} className="flex items-center gap-1.5 text-[10px] font-mono">
            <span className="w-2 h-2 rounded-full" style={{ background: COLORS[sev] }} />
            <span className="text-slate-400 capitalize">{sev}</span>
            <span className="text-white font-bold">{counts[sev]}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

function FindingItem({ finding, showTool }) {
  const [expanded, setExpanded] = useState(finding.severity === 'critical' || finding.severity === 'high')
  const [copied,   setCopied]   = useState(false)
  const cfg       = SEV_CONFIG[finding.severity] || SEV_CONFIG.info
  const toolLabel = showTool && finding._tool ? TOOL_CONFIGS[finding._tool]?.name : null

  const copy = (e) => {
    e.stopPropagation()
    const text = `[${finding.severity.toUpperCase()}] ${finding.title}\nDetail: ${finding.detail}${finding.recommendation ? `\nFix: ${finding.recommendation}` : ''}`
    navigator.clipboard.writeText(text)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <div
      onClick={() => setExpanded(p => !p)}
      className={`rounded-xl mb-2 overflow-hidden transition-all duration-200 cursor-pointer border ${cfg.border}
                  ${finding.severity === 'critical' ? 'shadow-[0_0_12px_rgba(244,63,94,0.15)]' : ''}
                  hover:bg-white/[0.03] bg-cyber-surface/40`}
    >
      <div className="flex items-center gap-3 px-4 py-3">
        {/* Severity dot */}
        <span
          className={`w-2 h-2 rounded-full flex-shrink-0 ${cfg.dot}`}
          style={finding.severity === 'critical' ? { boxShadow: `0 0 6px ${cfg.glow}` } : {}}
        />

        <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded border uppercase tracking-wider flex-shrink-0 ${cfg.badge}`}>
          {finding.severity}
        </span>

        <span className="text-xs md:text-sm font-semibold text-slate-100 flex-1 leading-snug">
          {finding.title}
        </span>

        {toolLabel && (
          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-white/[0.04] text-slate-400 border border-white/[0.08] flex-shrink-0 hidden sm:inline">
            {toolLabel}
          </span>
        )}

        <button
          onClick={copy}
          className="text-slate-500 hover:text-slate-200 text-xs px-1.5 py-0.5 rounded hover:bg-white/[0.06] transition-colors flex-shrink-0"
          title="Copy finding"
        >
          {copied ? '✓' : '📋'}
        </button>

        <span className="text-slate-500 text-xs flex-shrink-0 font-mono">
          {expanded ? '▲' : '▼'}
        </span>
      </div>

      {expanded && (
        <div className="px-4 pb-4 pt-1 border-t border-white/[0.04] space-y-2.5 text-xs">
          <p className="text-slate-300 leading-relaxed font-sans">
            {finding.detail}
          </p>

          {finding.recommendation && (
            <div className="flex items-start gap-2 p-3 rounded-lg bg-emerald-500/[0.07] border border-emerald-500/20">
              <span className="text-neon-emerald font-bold text-xs mt-0.5 flex-shrink-0">🛡 REMEDIATION:</span>
              <span className="text-slate-300 font-sans leading-relaxed">
                {finding.recommendation}
              </span>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

export default function Findings({ findings, showTool = false }) {
  const [filter,   setFilter]   = useState('all')
  const [expanded, setExpanded] = useState(true)

  const counts = Object.fromEntries(
    ['critical','high','medium','low','pass','info'].map(s => [s, findings.filter(f => f.severity === s).length])
  )

  const filtered = findings.filter(f => filter === 'all' || f.severity === filter)
  const sorted   = [...filtered].sort((a, b) => (ORDER[a.severity] ?? 9) - (ORDER[b.severity] ?? 9))

  return (
    <div className="mb-6 space-y-3">

      {/* Header Row */}
      <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-3 pb-1">
        <div className="flex items-center gap-2">
          <span className="text-neon-emerald">◈</span>
          <span className="text-xs font-bold uppercase tracking-widest font-mono text-slate-300">
            SECURITY FINDINGS ({findings.length})
          </span>
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          {/* Export buttons */}
          <button
            onClick={() => exportJSON(findings)}
            className="text-[10px] font-mono px-2.5 py-1 rounded border border-white/[0.1] bg-white/[0.03]
                       text-slate-400 hover:text-slate-200 hover:bg-white/[0.07] transition-all"
          >
            ↓ JSON
          </button>
          <button
            onClick={() => exportCSV(findings)}
            className="text-[10px] font-mono px-2.5 py-1 rounded border border-white/[0.1] bg-white/[0.03]
                       text-slate-400 hover:text-slate-200 hover:bg-white/[0.07] transition-all"
          >
            ↓ CSV
          </button>
          <button
            onClick={() => setExpanded(p => !p)}
            className="text-[10px] font-mono px-2.5 py-1 rounded border border-white/[0.1] bg-white/[0.03]
                       text-slate-400 hover:text-slate-200 hover:bg-white/[0.07] transition-all"
          >
            {expanded ? '▼ Collapse' : '▶ Expand'}
          </button>
        </div>
      </div>

      {/* Severity Distribution Bar */}
      <SeverityBar counts={counts} total={findings.length} />

      {/* Filter Chips */}
      <div className="flex items-center gap-1.5 flex-wrap">
        <button
          onClick={() => setFilter('all')}
          className={`text-[10px] font-mono px-2 py-0.5 rounded-md border transition-all ${
            filter === 'all'
              ? 'bg-white/[0.12] text-white border-white/[0.25] font-bold'
              : 'bg-white/[0.02] text-slate-400 border-white/[0.06] hover:bg-white/[0.05]'
          }`}
        >
          ALL ({findings.length})
        </button>

        {Object.entries(counts).map(([sev, n]) => {
          if (n <= 0) return null
          const cfg = SEV_CONFIG[sev] || SEV_CONFIG.info
          return (
            <button
              key={sev}
              onClick={() => setFilter(filter === sev ? 'all' : sev)}
              className={`text-[10px] font-mono px-2 py-0.5 rounded-md border uppercase transition-all ${
                filter === sev
                  ? `${cfg.badge} font-bold shadow-[0_0_8px_rgba(255,255,255,0.15)]`
                  : 'bg-white/[0.02] text-slate-400 border-white/[0.06] hover:bg-white/[0.05]'
              }`}
            >
              {sev} ({n})
            </button>
          )
        })}
      </div>

      {/* Findings List */}
      {expanded && (
        <div className="space-y-1.5">
          {sorted.map((f, i) => (
            <FindingItem key={i} finding={f} showTool={showTool} />
          ))}
        </div>
      )}

    </div>
  )
}
