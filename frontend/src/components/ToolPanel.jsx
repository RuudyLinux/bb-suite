import { useState, useEffect, useRef } from 'react'
import { useToolRunner } from '../hooks/useToolRunner'
import Results from './Results'

function FormField({ field, value, onChange }) {
  if (field.type === 'select') {
    const def = field.options?.find(o => o.default)?.v || field.options?.[0]?.v || ''
    return (
      <div className="space-y-1.5">
        <label className="hack-label">{field.label}</label>
        <select
          value={value || def}
          onChange={e => onChange(e.target.value)}
          className="hack-select w-full"
        >
          {field.options?.map(o => (
            <option key={o.v} value={o.v} className="bg-cyber-surface text-slate-200">
              {o.l}
            </option>
          ))}
        </select>
      </div>
    )
  }

  if (field.type === 'textarea') {
    return (
      <div className="space-y-1.5">
        <label className="hack-label">{field.label}</label>
        <textarea
          value={value}
          onChange={e => onChange(e.target.value)}
          placeholder={field.placeholder || ''}
          rows={field.rows || 4}
          className="hack-input resize-y"
        />
      </div>
    )
  }

  return (
    <div className="space-y-1.5">
      <label className="hack-label">{field.label}</label>
      <input
        type={field.type || 'text'}
        value={value}
        onChange={e => onChange(e.target.value)}
        placeholder={field.placeholder || ''}
        className="hack-input"
        required={field.required}
      />
    </div>
  )
}

function initForm(fields, globalTarget) {
  const form = {}
  for (const field of fields) {
    if (field.autofill === 'domain' && globalTarget) {
      form[field.name] = globalTarget.replace(/^https?:\/\//, '').split('/')[0]
    } else if (field.autofill === 'url' && globalTarget) {
      form[field.name] = globalTarget.startsWith('http') ? globalTarget : `https://${globalTarget}`
    } else if (field.autofill === 'host' && globalTarget) {
      form[field.name] = globalTarget.replace(/^https?:\/\//, '').split('/')[0]
    } else if (field.defaultValue !== undefined) {
      form[field.name] = field.defaultValue
    } else if (field.type === 'select' && field.options) {
      form[field.name] = field.options.find(o => o.default)?.v || field.options[0]?.v || ''
    } else {
      form[field.name] = ''
    }
  }
  return form
}

// Calculate risk score from findings
function calcRiskScore(result) {
  if (!result?.data?.findings) return null
  const findings = result.data.findings
  const weights = { critical: 10, high: 6, medium: 3, low: 1, info: 0, pass: -2 }
  const raw = findings.reduce((acc, f) => acc + (weights[f.severity] || 0), 0)
  const score = Math.min(100, Math.round(raw * 2))
  const label = score >= 70 ? 'CRITICAL' : score >= 40 ? 'HIGH RISK' : score >= 20 ? 'MEDIUM' : score > 0 ? 'LOW RISK' : 'CLEAN'
  const color = score >= 70 ? '#f43f5e' : score >= 40 ? '#f59e0b' : score >= 20 ? '#eab308' : score > 0 ? '#3b82f6' : '#10b981'
  return { score, label, color }
}

// Animated live log during execution
const LOG_MESSAGES = [
  'Initializing security module...',
  'Establishing connection to target...',
  'Probing endpoint for response baseline...',
  'Injecting test payloads...',
  'Analyzing server response telemetry...',
  'Running secondary validation pass...',
  'Correlating findings against vulnerability database...',
  'Generating security assessment report...',
]

function LiveLog({ toolName, loading }) {
  const [logLines, setLogLines] = useState([])
  const logRef = useRef(null)

  useEffect(() => {
    if (!loading) { setLogLines([]); return }
    setLogLines([`[*] Launching ${toolName}...`])
    let i = 0
    const add = () => {
      if (!loading || i >= LOG_MESSAGES.length) return
      setLogLines(prev => [...prev, `[+] ${LOG_MESSAGES[i++]}`])
    }
    const intervals = [300, 900, 1600, 2500, 3500, 4800, 6200, 8000]
    const timers = intervals.map((ms, idx) => setTimeout(() => add(), ms))
    return () => timers.forEach(clearTimeout)
  }, [loading, toolName])

  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight
  }, [logLines])

  if (!loading && logLines.length === 0) return null

  return (
    <div className="cyber-card p-5 border border-emerald-500/30 bg-emerald-950/10">
      {/* Header row */}
      <div className="flex items-center gap-3 mb-3 pb-2.5 border-b border-white/[0.06]">
        <div className="relative w-7 h-7 flex items-center justify-center flex-shrink-0">
          <span className="absolute inset-0 rounded-full border-2 border-neon-emerald border-t-transparent animate-spin" />
          <span className="w-2.5 h-2.5 rounded-full bg-neon-emerald/80 animate-ping" />
        </div>
        <div>
          <div className="text-sm font-semibold text-white">Running {toolName}</div>
          <div className="text-[10px] font-mono text-slate-400 mt-0.5">Live execution telemetry</div>
        </div>
        <div className="ml-auto flex items-center gap-1.5">
          <span className="w-1.5 h-1.5 rounded-full bg-neon-emerald animate-ping" />
          <span className="text-[10px] font-mono text-neon-emerald font-bold">LIVE</span>
        </div>
      </div>

      {/* Log output */}
      <div
        ref={logRef}
        className="bg-black/40 rounded-lg p-3 font-mono text-[11px] space-y-1 max-h-40 overflow-y-auto"
      >
        {logLines.map((line, i) => (
          <div
            key={i}
            className={`leading-relaxed animate-fade-in ${
              line.startsWith('[*]') ? 'text-cyan-400' :
              line.startsWith('[!]') ? 'text-amber-400' :
              line.startsWith('[CRIT]') ? 'text-rose-400' :
              'text-slate-300'
            }`}
          >
            {line}
          </div>
        ))}
        {loading && (
          <div className="text-slate-500">
            <span className="animate-blink">▌</span>
          </div>
        )}
      </div>
    </div>
  )
}

function RiskMeter({ result }) {
  const risk = calcRiskScore(result)
  if (!risk) return null

  return (
    <div className="cyber-card p-4 flex items-center gap-4">
      {/* Circular risk gauge */}
      <div className="relative flex-shrink-0 w-16 h-16">
        <svg viewBox="0 0 36 36" className="w-full h-full -rotate-90">
          <circle cx="18" cy="18" r="14" fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="3" />
          <circle
            cx="18" cy="18" r="14"
            fill="none"
            stroke={risk.color}
            strokeWidth="3"
            strokeDasharray={`${risk.score * 0.88} 88`}
            strokeLinecap="round"
            style={{ filter: `drop-shadow(0 0 4px ${risk.color})` }}
          />
        </svg>
        <div className="absolute inset-0 flex items-center justify-center">
          <span className="text-xs font-extrabold font-mono" style={{ color: risk.color }}>
            {risk.score}
          </span>
        </div>
      </div>

      <div className="flex-1">
        <div className="text-[10px] font-mono text-slate-400 uppercase tracking-wider mb-1">Risk Score</div>
        <div className="text-base font-extrabold font-mono" style={{ color: risk.color }}>
          {risk.label}
        </div>
        <div className="mt-1.5 h-1.5 bg-black/40 rounded-full overflow-hidden">
          <div
            className="h-full rounded-full transition-all duration-700"
            style={{ width: `${risk.score}%`, background: risk.color, boxShadow: `0 0 8px ${risk.color}` }}
          />
        </div>
      </div>

      <div className="text-right">
        <div className="text-[10px] font-mono text-slate-400">Findings</div>
        <div className="text-sm font-bold text-white font-mono">
          {result?.data?.findings?.length || 0}
        </div>
      </div>
    </div>
  )
}

export default function ToolPanel({ toolName, config, globalTarget }) {
  const { run, loading, result, error, elapsed, reset } = useToolRunner(toolName)
  const [form, setForm] = useState(() => initForm(config.fields, globalTarget))
  const [copied, setCopied] = useState(false)

  useEffect(() => {
    reset()
    setForm(initForm(config.fields, globalTarget))
  }, [toolName, config.fields, globalTarget]) // eslint-disable-line react-hooks/exhaustive-deps

  const setField = (name, val) => setForm(p => ({ ...p, [name]: val }))

  const handleSubmit = (e) => {
    e.preventDefault()
    run(form)
  }

  const handleResetForm = () => {
    reset()
    setForm(initForm(config.fields, globalTarget))
  }

  const copyResult = () => {
    if (!result) return
    navigator.clipboard.writeText(JSON.stringify(result, null, 2))
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  const mainField   = config.fields[0]
  const otherFields = config.fields.slice(1)
  const rows = []
  for (let i = 0; i < otherFields.length; i += 2) {
    rows.push(otherFields.slice(i, i + 2))
  }

  const hasFindings = result?.data?.findings?.length > 0
  const critCount   = result?.data?.findings?.filter(f => f.severity === 'critical').length || 0
  const highCount   = result?.data?.findings?.filter(f => f.severity === 'high').length || 0

  return (
    <div className="space-y-5 animate-fade-in">

      {/* Tool Header Card */}
      <div className="cyber-card p-5 relative overflow-hidden">
        <div className="absolute top-0 right-0 w-64 h-32 bg-emerald-500/5 rounded-full blur-2xl pointer-events-none" />

        <div className="flex items-start justify-between gap-4 relative z-10">
          <div className="flex items-start gap-4">
            <div className="w-12 h-12 rounded-xl bg-white/[0.04] border border-white/[0.08] flex items-center justify-center text-2xl shadow-inner flex-shrink-0">
              {config.icon}
            </div>
            <div>
              <div className="flex items-center gap-2 flex-wrap">
                <h1 className="text-xl font-extrabold text-white tracking-wide">
                  {config.name}
                </h1>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                  READY
                </span>
                {critCount > 0 && (
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-500/20 text-rose-400 border border-rose-500/40 font-bold animate-pulse">
                    {critCount} CRITICAL
                  </span>
                )}
                {highCount > 0 && critCount === 0 && (
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-amber-500/20 text-amber-400 border border-amber-500/40 font-bold">
                    {highCount} HIGH
                  </span>
                )}
              </div>
              <p className="text-slate-400 text-xs md:text-sm mt-1 leading-relaxed max-w-2xl">
                {config.desc}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2 flex-shrink-0">
            {elapsed && (
              <span className="text-[11px] font-mono px-2.5 py-1 rounded bg-white/[0.04] text-slate-300 border border-white/[0.08]">
                ⏱ {elapsed}s
              </span>
            )}
            {result && (
              <button
                onClick={copyResult}
                className="hack-btn-sm"
                title="Copy raw JSON result"
              >
                {copied ? '✓ Copied' : '📋 Copy JSON'}
              </button>
            )}
            <button
              onClick={handleResetForm}
              className="hack-btn-sm"
              title="Reset parameters to defaults"
            >
              ↺ Reset
            </button>
          </div>
        </div>
      </div>

      {/* Risk meter (shows after scan) */}
      {result?.success && hasFindings && <RiskMeter result={result} />}

      {/* Execution Form Card */}
      <form onSubmit={handleSubmit} className="cyber-card p-6 space-y-4">
        <div className="flex items-center justify-between border-b border-white/[0.06] pb-3 mb-2">
          <span className="text-xs uppercase tracking-widest font-mono text-slate-400 flex items-center gap-2">
            <span className="text-neon-emerald">▶</span>
            <span>EXECUTION PARAMETERS</span>
          </span>
          <span className="text-[11px] font-mono text-slate-500">bb-suite // {toolName}</span>
        </div>

        {/* Primary Target Field + Execute Button */}
        <div className="flex flex-col sm:flex-row gap-3 items-stretch sm:items-end">
          <div className="flex-1">
            <FormField field={mainField} value={form[mainField.name]} onChange={v => setField(mainField.name, v)} />
          </div>
          <button
            type="submit"
            disabled={loading}
            className="hack-btn h-[42px] px-8 flex items-center justify-center flex-shrink-0"
          >
            {loading ? (
              <span className="flex items-center gap-2">
                <span className="w-3.5 h-3.5 border-2 border-slate-950 border-t-transparent rounded-full animate-spin inline-block" />
                <span>EXECUTING...</span>
              </span>
            ) : `► RUN TOOL`}
          </button>
        </div>

        {/* Secondary Parameters */}
        {rows.map((row, ri) => (
          <div key={ri} className={`grid gap-4 ${row.length === 2 ? 'grid-cols-1 md:grid-cols-2' : 'grid-cols-1'}`}>
            {row.map(field => (
              <FormField
                key={field.name}
                field={field}
                value={form[field.name]}
                onChange={v => setField(field.name, v)}
              />
            ))}
          </div>
        ))}
      </form>

      {/* Live Log */}
      <LiveLog toolName={config.name} loading={loading} />

      {/* Error Callout */}
      {error && !loading && (
        <div className="cyber-card p-5 border border-rose-500/40 bg-rose-500/10 text-rose-300 space-y-1">
          <div className="flex items-center gap-2 font-bold text-sm text-rose-400">
            <span>✗</span>
            <span>Execution Failed</span>
          </div>
          <div className="text-xs font-mono text-rose-200/90 break-all">
            {error}
          </div>
        </div>
      )}

      {/* Results Display */}
      {result && !loading && (
        <div className="animate-slide-up">
          <Results data={result} toolName={config.name} target={form.target || ''} />
        </div>
      )}

    </div>
  )
}
