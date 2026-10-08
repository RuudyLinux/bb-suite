import { useState, useRef, useEffect } from 'react'
import { useRunAll } from '../hooks/useRunAll'
import { CATEGORIES, TOOL_CONFIGS } from '../config/tools'
import Results from './Results'
import Findings from './Findings'
import CrackBanner from './CrackBanner'
import ReportPanel from './ReportPanel'

const S_COLOR = {
  pending: '#64748b',
  running: '#00f0ff',
  done:    '#00ff88',
  error:   '#f43f5e',
}

const S_ICON = {
  pending: '○',
  running: '◌',
  done:    '✓',
  error:   '✗',
}

const SEV_COLOR = {
  critical: '#f43f5e',
  high:     '#f59e0b',
  medium:   '#eab308',
  low:      '#3b82f6',
  pass:     '#10b981',
  info:     '#06b6d4',
}

function collectCrackedPages(results) {
  const pages = []
  const seen  = new Set()

  for (const p of results.vuln_map?.data?.cracked_pages || []) {
    if (seen.has(p.url)) continue
    seen.add(p.url)
    pages.push({ url: p.url, labels: p.labels, sev: p.sev, source: 'Vuln Map' })
  }

  const EXPLOIT = {
    password_cracker: 'Password Cracker',
    sqli:             'SQL Injection',
    auth_flaws:       'Auth Bypass',
    bruteforce:       'Brute Force',
    ssrf_scanner:     'SSRF Exploit',
    ssti_scanner:     'SSTI Exploit',
    poc_generator:    'PoC Synthesizer',
  }
  for (const [tool, label] of Object.entries(EXPLOIT)) {
    const res = results[tool]
    if (!res?.success) continue
    const findings = res.data?.findings || []
    if (!findings.some(f => f.severity === 'critical')) continue
    const s   = res.data?.summary || {}
    const url = s.URL || s.Target || s['Login URL'] || s['Base URL'] || ''
    if (!url || seen.has(url)) continue
    seen.add(url)
    const labels = findings
      .filter(f => f.severity === 'critical')
      .map(f => f.title)
      .slice(0, 3)
    pages.push({ url, labels, sev: 'critical', source: label })
  }

  return pages
}

function CrackedPagesBanner({ pages }) {
  if (!pages.length) return null
  return (
    <div className="cyber-card mb-6 border border-rose-500/40 bg-rose-500/[0.05] shadow-[0_0_25px_rgba(244,63,94,0.2)] overflow-hidden">
      <div className="flex items-center gap-3 px-5 py-3.5 bg-rose-500/10 border-b border-rose-500/20">
        <span className="text-2xl">💀</span>
        <div className="flex-1">
          <div className="font-extrabold text-sm md:text-base tracking-wider text-rose-400">
            {pages.length} COMPROMISED / CRACKED TARGET PAGES
          </div>
          <div className="text-xs text-rose-300/80">
            Immediate vulnerability remediation required
          </div>
        </div>
        <span className="text-[10px] font-mono font-bold px-2.5 py-1 rounded bg-rose-500/20 text-rose-300 border border-rose-500/40">
          CRITICAL
        </span>
      </div>

      <div className="divide-y divide-white/[0.04] p-2">
        {pages.map((p, i) => {
          const col = SEV_COLOR[p.sev] || '#f59e0b'
          return (
            <div key={i} className="px-4 py-3 flex items-start gap-3 hover:bg-white/[0.02] rounded-lg transition-colors">
              <span style={{ color: col, fontSize: '14px', marginTop: '1px' }}>⚡</span>
              <div className="flex-1 min-w-0">
                <a href={p.url} target="_blank" rel="noopener noreferrer"
                   className="font-mono text-sm font-bold break-all hover:underline block text-rose-300">
                  {p.url}
                </a>
                <div className="flex flex-wrap gap-1 mt-1.5">
                  {p.labels.map((lbl, j) => (
                    <span key={j} className="text-[10px] px-2 py-0.5 font-mono rounded bg-rose-500/15 text-rose-300 border border-rose-500/30">
                      {lbl}
                    </span>
                  ))}
                </div>
              </div>
              <span className="text-[10px] font-mono flex-shrink-0 px-2 py-0.5 rounded bg-white/[0.04] text-slate-400 border border-white/[0.08]">
                {p.source}
              </span>
            </div>
          )
        })}
      </div>
    </div>
  )
}

function ToolCard({ toolId, status, result, onClick, isExpanded, isManual }) {
  const cfg  = TOOL_CONFIGS[toolId]
  const col  = isManual ? '#64748b' : (S_COLOR[status] || S_COLOR.pending)
  const icon = isManual ? '⌨' : (S_ICON[status] || '○')
  const findings = result?.data?.findings || []
  const crits = findings.filter(f => f.severity === 'critical').length
  const highs = findings.filter(f => f.severity === 'high').length
  const meds  = findings.filter(f => f.severity === 'medium').length

  return (
    <button
      onClick={onClick}
      title={isManual ? `${cfg.name} — requires manual input (open from sidebar)` : cfg.name}
      className={`text-left p-2.5 rounded-xl border transition-all duration-200 ${
        isExpanded
          ? 'bg-emerald-500/15 border-neon-emerald shadow-[0_0_15px_rgba(0,255,136,0.25)]'
          : status === 'running'
          ? 'bg-cyan-500/10 border-cyan-400/50 shadow-[0_0_12px_rgba(0,240,255,0.2)]'
          : status === 'done'
          ? 'bg-white/[0.02] border-white/[0.08] hover:border-emerald-500/40 hover:bg-white/[0.04]'
          : status === 'error'
          ? 'bg-rose-500/10 border-rose-500/40'
          : 'bg-white/[0.01] border-white/[0.04] hover:bg-white/[0.03]'
      } ${isManual ? 'opacity-40 hover:opacity-80' : ''}`}
    >
      <div className="flex items-center gap-1.5 mb-1">
        <span style={{ color: col, fontSize: '11px', minWidth: '12px' }} className={status === 'running' ? 'animate-spin inline-block' : ''}>
          {icon}
        </span>
        <span className={`text-[11px] font-mono font-medium truncate flex-1 ${
          status === 'done' ? 'text-slate-200' : status === 'running' ? 'text-cyan-300 font-bold' : 'text-slate-400'
        }`}>
          {cfg?.name || toolId}
        </span>
      </div>

      {isManual && (
        <div className="text-[9px] text-slate-500 font-mono tracking-wider">MANUAL</div>
      )}

      {!isManual && (crits > 0 || highs > 0 || meds > 0) && (
        <div className="flex gap-1 mt-1">
          {crits > 0 && <span className="text-[9px] font-mono font-bold px-1 rounded bg-rose-500/20 text-rose-400 border border-rose-500/30">C:{crits}</span>}
          {highs > 0 && <span className="text-[9px] font-mono font-bold px-1 rounded bg-amber-500/20 text-amber-400 border border-amber-500/30">H:{highs}</span>}
          {meds  > 0 && <span className="text-[9px] font-mono font-bold px-1 rounded bg-yellow-500/20 text-yellow-300 border border-yellow-500/30">M:{meds}</span>}
        </div>
      )}
    </button>
  )
}

function SevBadge({ sev, count }) {
  if (!count) return null
  const col = SEV_COLOR[sev] || '#10b981'
  return (
    <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg border bg-white/[0.02]" style={{ borderColor: `${col}30` }}>
      <span className="w-2 h-2 rounded-full" style={{ background: col, boxShadow: `0 0 6px ${col}` }} />
      <span className="text-base font-bold font-mono text-white">{count}</span>
      <span className="text-[10px] uppercase tracking-wider font-mono" style={{ color: col }}>{sev}</span>
    </div>
  )
}

export default function Dashboard({ target, onSelectTool }) {
  const { statuses, results, running, progress, allFindings, sevCounts, runAll, stop, reset, manualOnly } = useRunAll()
  const [reportSaved,  setReportSaved]  = useState(0)
  const [reportMsg,    setReportMsg]    = useState('')
  const [savingReport, setSavingReport] = useState(false)
  const startTimeRef = useRef(null)

  const saveReportNow = async () => {
    setSavingReport(true)
    setReportMsg('')
    try {
      const duration = startTimeRef.current ? (Date.now() - startTimeRef.current) / 1000 : 0
      const r = await fetch('/api/save_report', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target,
          results,
          all_findings: allFindings,
          sev_counts: sevCounts,
          duration_s: duration,
        }),
      })
      const d = await r.json()
      if (d.success) {
        setReportMsg(`Report saved: ${d.data.html_file}`)
        setReportSaved(p => p + 1)
        window.open(`/api/reports/${d.data.html_file}`, '_blank')
      } else {
        setReportMsg('Save failed: ' + (d.error || 'unknown'))
      }
    } catch (e) {
      setReportMsg('Save failed: ' + e.message)
    } finally {
      setSavingReport(false)
    }
  }

  // Auto-save report when all tools finish
  const finished = Object.keys(statuses).length > 0 &&
                   progress.done + progress.failed === progress.total
  const savedRef  = useRef(false)

  useEffect(() => {
    if (finished && !running && !savedRef.current && Object.keys(results).length > 0) {
      savedRef.current = true
      const duration = startTimeRef.current ? (Date.now() - startTimeRef.current) / 1000 : 0
      fetch('/api/save_report', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target,
          results,
          all_findings: allFindings,
          sev_counts: sevCounts,
          duration_s: duration,
        }),
      })
        .then(r => r.json())
        .then(d => {
          if (d.success) {
            setReportMsg(`Report saved: ${d.data.html_file}`)
            setReportSaved(p => p + 1)
          }
        })
        .catch(() => {})
    }
    if (!finished) {
      savedRef.current = false
    }
  }, [finished, running, results, allFindings, sevCounts, target])

  const crackedFindings = allFindings.filter(fnd =>
    fnd.severity === 'critical' &&
    (fnd.title.includes('Credentials Found') || fnd.title.includes('Account Compromised') ||
     fnd.title.includes('Default Credentials') || fnd.title.includes('Password Cracked'))
  )

  const crackedPages = collectCrackedPages(results)
  const [expanded, setExpanded]     = useState(null)
  const [showFindings, setShowFindings] = useState(true)

  const domain  = target.replace(/^https?:\/\//, '').split('/')[0]
  const started = Object.keys(statuses).length > 0

  return (
    <div className="p-6 md:p-8 space-y-6 max-w-6xl mx-auto animate-fade-in">

      {/* Target Operations Header */}
      <div className="cyber-card p-6 relative overflow-hidden">
        <div className="absolute top-0 right-0 w-80 h-32 bg-emerald-500/5 rounded-full blur-3xl pointer-events-none" />

        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-5 relative z-10">
          <div className="space-y-1 min-w-0">
            <div className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-neon-emerald animate-ping" />
              <span className="text-slate-400 text-xs font-mono uppercase tracking-wider">ACTIVE TARGET DOMAIN</span>
            </div>
            <div className="text-white text-2xl md:text-3xl font-extrabold font-mono tracking-tight truncate">
              {domain}
            </div>
            <div className="text-slate-400 text-xs font-mono truncate">
              {target}
            </div>
          </div>

          <div className="flex items-center gap-2.5 flex-wrap flex-shrink-0">
            {started && !running && (
              <button
                onClick={reset}
                className="hack-btn-secondary"
              >
                ↺ Reset
              </button>
            )}

            {started && (
              <button
                onClick={saveReportNow}
                disabled={savingReport}
                className="hack-btn-secondary"
              >
                {savingReport ? 'Saving...' : '📁 Save Report'}
              </button>
            )}

            {running ? (
              <button
                onClick={stop}
                className="bg-rose-500 hover:bg-rose-600 text-white font-bold px-6 py-2.5 text-xs uppercase tracking-widest rounded-lg shadow-[0_0_20px_rgba(244,63,94,0.4)] transition-all"
              >
                ■ STOP SUITE
              </button>
            ) : (
              <button
                onClick={() => { startTimeRef.current = Date.now(); runAll(target) }}
                className="hack-btn px-7 py-2.5"
              >
                ▶▶ PERFORM ALL TOOLS
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Progress & Live Telemetry Section */}
      {started && (
        <div className="cyber-card p-5 space-y-4">
          <div className="flex items-center justify-between text-xs font-mono">
            <span className="text-slate-400 uppercase tracking-widest flex items-center gap-2">
              <span className="text-neon-cyan">◌</span>
              <span>SUITE EXECUTION PROGRESS</span>
            </span>
            <span className="text-slate-300 font-semibold">
              {progress.done + progress.failed} / {progress.total} tools completed
              {running && <span className="text-cyan-400 ml-2 animate-pulse">({progress.running} running)</span>}
              {finished && <span className="text-neon-emerald ml-2 font-bold">// COMPLETE</span>}
            </span>
          </div>

          {/* Glowing Animated Progress Bar */}
          <div className="h-2.5 bg-black/50 rounded-full overflow-hidden border border-white/[0.08] relative">
            <div
              className="h-full rounded-full transition-all duration-500 bg-gradient-to-r from-emerald-500 via-teal-400 to-cyan-400"
              style={{
                width: `${progress.pct}%`,
                boxShadow: '0 0 15px rgba(0, 255, 136, 0.5)',
              }}
            />
          </div>

          {/* Severity Badges Summary */}
          {allFindings.length > 0 && (
            <div className="flex flex-wrap items-center gap-2 pt-1 border-t border-white/[0.04]">
              <SevBadge sev="critical" count={sevCounts.critical} />
              <SevBadge sev="high"     count={sevCounts.high} />
              <SevBadge sev="medium"   count={sevCounts.medium} />
              <SevBadge sev="low"      count={sevCounts.low} />
              <SevBadge sev="info"     count={sevCounts.info} />
              <div className="ml-auto text-xs font-mono text-slate-400">
                {allFindings.length} Total Findings
              </div>
            </div>
          )}
        </div>
      )}

      {/* Tool Matrix Status Grid */}
      {started && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-xs uppercase tracking-widest font-mono text-slate-400 flex items-center gap-2">
              <span className="text-neon-emerald">▦</span>
              <span>SUITE MODULE MATRIX</span>
            </h2>
            <span className="text-[11px] font-mono text-slate-500">CLICK TO INSPECT RESULT</span>
          </div>

          <div className="space-y-4">
            {CATEGORIES.map(cat => (
              <div key={cat.id} className="cyber-card p-4 space-y-2.5">
                <div className="flex items-center justify-between text-xs font-mono">
                  <div className="flex items-center gap-2">
                    <span className="text-slate-400">{cat.icon}</span>
                    <span className="font-semibold text-slate-200 tracking-wider uppercase">{cat.label}</span>
                  </div>
                  <span className="text-slate-500 text-[11px]">
                    {cat.tools.filter(t => statuses[t] === 'done').length}/{cat.tools.length} Completed
                  </span>
                </div>

                <div className="grid grid-cols-2 sm:grid-cols-4 md:grid-cols-6 lg:grid-cols-8 gap-2">
                  {cat.tools.map(toolId => (
                    <ToolCard
                      key={toolId}
                      toolId={toolId}
                      status={statuses[toolId] || 'pending'}
                      result={results[toolId]}
                      onClick={() => onSelectTool(toolId)}
                      isExpanded={expanded === toolId}
                      isManual={manualOnly?.has(toolId)}
                    />
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Expanded Tool Result */}
      {expanded && results[expanded] && (
        <div className="cyber-card p-5 border border-emerald-500/40">
          <div className="flex items-center justify-between mb-4 pb-3 border-b border-white/[0.08]">
            <div className="flex items-center gap-3">
              <span className="text-2xl">{TOOL_CONFIGS[expanded]?.icon}</span>
              <div>
                <div className="font-bold text-base text-white">{TOOL_CONFIGS[expanded]?.name}</div>
                <div className="text-xs text-slate-400">{TOOL_CONFIGS[expanded]?.desc}</div>
              </div>
            </div>
            <div className="flex gap-2">
              <button
                onClick={() => onSelectTool(expanded)}
                className="hack-btn-sm"
              >
                ▷ Open Tool Console
              </button>
              <button
                onClick={() => setExpanded(null)}
                className="text-slate-500 hover:text-slate-200 px-2 text-sm"
              >
                ✕
              </button>
            </div>
          </div>
          <Results data={results[expanded]} toolName={TOOL_CONFIGS[expanded]?.name} target={target} />
        </div>
      )}

      {/* Cracked Pages Banner */}
      {crackedPages.length > 0 && !expanded && (
        <CrackedPagesBanner pages={crackedPages} />
      )}

      {/* Cracked Credentials Banner */}
      {crackedFindings.length > 0 && !expanded && (
        <div>
          <div className="section-title mb-3 text-rose-400">
            <span>⚡</span>
            <span>CRACKED CREDENTIALS DISCOVERED ({crackedFindings.length})</span>
          </div>
          {crackedFindings.map((fnd, i) => (
            <CrackBanner
              key={i}
              finding={fnd}
              toolName={fnd._tool || 'Tool'}
              target={target}
            />
          ))}
        </div>
      )}

      {/* Report Save Callout */}
      {reportMsg && (
        <div className="cyber-card p-4 border border-emerald-500/30 bg-emerald-500/10 flex items-center gap-3 text-xs font-mono text-emerald-300">
          <span>📁</span>
          <span>{reportMsg}</span>
          <a
            href={`/api/reports/${(reportMsg.split(': ')[1] || '').trim()}`}
            target="_blank"
            rel="noopener noreferrer"
            className="ml-auto text-emerald-400 hover:underline font-bold"
          >
            Open HTML Report ↗
          </a>
        </div>
      )}

      {/* Reports Archive */}
      {started && <ReportPanel newReportSaved={reportSaved} />}

      {/* All Aggregated Findings */}
      {allFindings.length > 0 && !expanded && (
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <div className="section-title mb-0">
              <span className="text-neon-emerald">◈</span>
              <span>AGGREGATE SECURITY FINDINGS ({allFindings.length})</span>
            </div>
            <button
              onClick={() => setShowFindings(p => !p)}
              className="hack-btn-sm"
            >
              {showFindings ? '▼ Collapse All' : '▶ Expand All'}
            </button>
          </div>
          {showFindings && (
            <Findings findings={allFindings} showTool />
          )}
        </div>
      )}

      {/* Unstarted Hero Prompt */}
      {!started && (
        <div className="cyber-card p-12 text-center space-y-4">
          <div className="w-16 h-16 mx-auto rounded-2xl bg-white/[0.04] border border-white/[0.08] flex items-center justify-center text-3xl shadow-inner">
            🎯
          </div>
          <div className="text-xs font-mono uppercase tracking-widest text-slate-400">Target Configured</div>
          <div className="text-white text-3xl font-extrabold font-mono tracking-tight">{domain}</div>
          <p className="text-slate-400 text-sm max-w-md mx-auto">
            Ready to execute full penetration testing and vulnerability mapping across all 35 modules.
          </p>
          <div className="pt-2">
            <button
              onClick={() => { startTimeRef.current = Date.now(); runAll(target) }}
              className="hack-btn px-8 py-3 text-sm font-bold"
            >
              ▶▶ PERFORM ALL 35 TOOLS
            </button>
          </div>
        </div>
      )}

    </div>
  )
}
