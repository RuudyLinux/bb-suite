import { useState } from 'react'
import Findings from './Findings'
import DataTable from './DataTable'
import CrackBanner from './CrackBanner'

function SummaryCards({ summary }) {
  if (!summary || !Object.keys(summary).length) return null
  return (
    <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 xl:grid-cols-6 gap-3 mb-6">
      {Object.entries(summary).map(([k, v]) => (
        <div key={k} className="cyber-card p-3.5 relative overflow-hidden group hover:border-emerald-500/30 transition-all">
          <div className="text-[10px] text-slate-400 uppercase tracking-widest font-mono truncate mb-1">
            {k}
          </div>
          <div className="text-white text-base md:text-lg font-extrabold font-mono tracking-tight truncate group-hover:text-neon-emerald transition-colors">
            {String(v)}
          </div>
        </div>
      ))}
    </div>
  )
}

function DnsSection({ dns }) {
  if (!dns) return null
  return (
    <div className="mb-6">
      <div className="section-title">
        <span className="text-cyan-400">◈</span>
        <span>DNS RECORDS</span>
      </div>
      <div className="cyber-card overflow-x-auto divide-y divide-white/[0.04]">
        {Object.entries(dns).map(([type, recs]) => !recs.length ? null : (
          <div key={type} className="p-3 space-y-2">
            <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase tracking-wider bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
              {type}
            </span>
            <div className="space-y-1.5 pt-1">
              {recs.map((r, i) => (
                <div key={i} className="flex items-baseline gap-3 text-xs font-mono bg-white/[0.02] px-3 py-1.5 rounded-lg border border-white/[0.03]">
                  <span className="text-slate-400 font-semibold w-12">{type}</span>
                  <span className="text-slate-200 flex-1 break-all select-all">{r.value}</span>
                  {r.ttl && <span className="text-slate-500 text-[11px] flex-shrink-0">TTL {r.ttl}</span>}
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

function CookiesSection({ cookies }) {
  if (!cookies?.length) return null
  return (
    <div className="mb-6">
      <div className="section-title">
        <span className="text-amber-400">🍪</span>
        <span>COOKIES ({cookies.length})</span>
      </div>
      <div className="cyber-card overflow-x-auto">
        <table className="w-full text-xs font-mono">
          <thead>
            <tr className="border-b border-white/[0.08] text-slate-400 bg-white/[0.02]">
              {['Name', 'Secure', 'HttpOnly', 'SameSite', 'Domain', 'Path'].map(h => (
                <th key={h} className="text-left px-3.5 py-2.5 uppercase tracking-wider text-[11px]">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-white/[0.04]">
            {cookies.map((c, i) => (
              <tr key={i} className="hover:bg-white/[0.02] transition-colors">
                <td className="px-3.5 py-2 text-white font-semibold">{c.name}</td>
                <td className="px-3.5 py-2">
                  {c.secure ? (
                    <span className="text-neon-emerald bg-emerald-500/10 border border-emerald-500/30 px-1.5 py-0.5 rounded text-[10px]">✓ TRUE</span>
                  ) : (
                    <span className="text-rose-400 bg-rose-500/10 border border-rose-500/30 px-1.5 py-0.5 rounded text-[10px]">✗ FALSE</span>
                  )}
                </td>
                <td className="px-3.5 py-2">
                  {c.httponly ? (
                    <span className="text-neon-emerald bg-emerald-500/10 border border-emerald-500/30 px-1.5 py-0.5 rounded text-[10px]">✓ TRUE</span>
                  ) : (
                    <span className="text-rose-400 bg-rose-500/10 border border-rose-500/30 px-1.5 py-0.5 rounded text-[10px]">✗ FALSE</span>
                  )}
                </td>
                <td className="px-3.5 py-2 text-slate-300">{c.samesite || '—'}</td>
                <td className="px-3.5 py-2 text-slate-400">{c.domain || '—'}</td>
                <td className="px-3.5 py-2 text-slate-400">{c.path || '/'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function PortsSection({ ports }) {
  if (!ports?.length) return null
  const open = ports.filter(p => p.open)
  return (
    <div className="mb-6">
      <div className="section-title">
        <span className="text-neon-cyan">⬣</span>
        <span>PORT SCAN ({open.length} OPEN / {ports.length} CHECKED)</span>
      </div>
      <div className="cyber-card overflow-x-auto">
        <table className="w-full text-xs font-mono">
          <thead>
            <tr className="border-b border-white/[0.08] text-slate-400 bg-white/[0.02]">
              {['Port', 'Service', 'Status', 'Banner'].map(h => (
                <th key={h} className="text-left px-3.5 py-2.5 uppercase tracking-wider text-[11px]">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-white/[0.04]">
            {ports.filter(p => p.open).map((p, i) => (
              <tr key={i} className="bg-emerald-500/[0.03] hover:bg-emerald-500/[0.06] transition-colors">
                <td className="px-3.5 py-2.5 text-neon-emerald font-bold">{p.port}</td>
                <td className="px-3.5 py-2.5 text-white font-medium">{p.service}</td>
                <td className="px-3.5 py-2.5">
                  <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/15 text-neon-emerald border border-emerald-500/30">
                    <span className="w-1.5 h-1.5 rounded-full bg-neon-emerald animate-ping" />
                    OPEN
                  </span>
                </td>
                <td className="px-3.5 py-2.5 text-slate-400 truncate max-w-xs">{p.banner || '—'}</td>
              </tr>
            ))}
            {ports.filter(p => !p.open).slice(0, 8).map((p, i) => (
              <tr key={`c-${i}`} className="opacity-40 hover:opacity-70 transition-opacity">
                <td className="px-3.5 py-1.5 text-slate-500">{p.port}</td>
                <td className="px-3.5 py-1.5 text-slate-500">{p.service}</td>
                <td className="px-3.5 py-1.5 text-slate-600 text-[10px]">CLOSED</td>
                <td className="px-3.5 py-1.5 text-slate-600">—</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function RawOutput({ raw }) {
  const isPoc = typeof raw === 'string' && (raw.includes('PoC') || raw.includes('REPRODUCTION') || raw.includes('curl') || raw.includes('<!DOCTYPE') || raw.includes('Exploit'))
  const [show, setShow] = useState(isPoc)
  const [copied, setCopied] = useState(false)
  if (!raw) return null

  const copy = () => {
    navigator.clipboard.writeText(raw)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <div className={`mt-5 rounded-xl overflow-hidden border ${isPoc ? 'border-amber-500/30 bg-amber-500/[0.03]' : 'border-white/[0.08] bg-white/[0.01]'}`}>
      <div className="flex items-center justify-between px-4 py-2.5 bg-white/[0.03] border-b border-white/[0.06]">
        <button
          onClick={() => setShow(p => !p)}
          className="text-xs font-mono font-bold inline-flex items-center gap-2 text-slate-200 hover:text-white transition-colors"
        >
          <span className={isPoc ? 'text-amber-400' : 'text-cyan-400'}>{isPoc ? '⚡' : '▶'}</span>
          <span className="tracking-wider uppercase">{isPoc ? 'EXPLOIT PROOF-OF-CONCEPT (PoC) & CODE' : 'RAW OUTPUT / ARTIFACTS'}</span>
          <span className="text-slate-500 text-[10px]">{show ? '▼ hide' : '▶ show'}</span>
        </button>
        <button
          onClick={copy}
          className="hack-btn-sm text-[11px] font-mono py-1 px-3 inline-flex items-center gap-1.5"
        >
          {copied ? '✓ COPIED' : '📋 COPY CODE'}
        </button>
      </div>
      {show && (
        <pre className="p-4 text-xs font-mono text-emerald-300/90 overflow-x-auto max-h-96 overflow-y-auto leading-relaxed whitespace-pre-wrap break-all select-all bg-black/60">
          {raw}
        </pre>
      )}
    </div>
  )
}

function AdminPages({ pages }) {
  if (!pages?.length) return null
  return (
    <div className="mb-6 cyber-card p-4 border border-amber-500/30 bg-amber-500/[0.04]">
      <div className="flex items-center gap-2 font-bold text-amber-400 text-xs font-mono uppercase tracking-wider mb-2">
        <span>⚠</span>
        <span>ADMIN & MANAGEMENT PANELS ({pages.length})</span>
      </div>
      <div className="divide-y divide-white/[0.04]">
        {pages.map((url, i) => (
          <div key={i} className="flex items-center gap-3 py-2 text-xs font-mono">
            <span className="text-amber-400">→</span>
            <a
              href={url}
              target="_blank"
              rel="noopener noreferrer"
              className="text-amber-300 hover:text-amber-200 hover:underline break-all"
            >
              {url}
            </a>
          </div>
        ))}
      </div>
    </div>
  )
}

function CrackedPages({ pages }) {
  if (!pages?.length) return null
  return (
    <div className="mb-6 cyber-card border border-rose-500/40 bg-rose-500/[0.05] shadow-[0_0_20px_rgba(244,63,94,0.15)] overflow-hidden">
      <div className="flex items-center justify-between px-4 py-3 bg-rose-500/10 border-b border-rose-500/20">
        <div className="flex items-center gap-2 text-rose-400 font-bold text-sm">
          <span>💀</span>
          <span className="tracking-wide">{pages.length} COMPROMISED / CRACKED PAGES</span>
        </div>
        <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/40 font-bold">
          CRITICAL ALERT
        </span>
      </div>
      <div className="divide-y divide-white/[0.04] p-2">
        {pages.map((p, i) => (
          <div key={i} className="flex items-start gap-3 p-3 hover:bg-white/[0.02] transition-colors rounded-lg">
            <span className="text-rose-400 text-sm mt-0.5">⚡</span>
            <div className="flex-1 min-w-0">
              <a
                href={p.url}
                target="_blank"
                rel="noopener noreferrer"
                className="font-mono text-sm font-bold text-rose-300 hover:underline break-all block"
              >
                {p.url}
              </a>
              <div className="flex flex-wrap gap-1.5 mt-1.5">
                {p.labels?.map((lbl, j) => (
                  <span key={j} className="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-500/10 text-rose-400 border border-rose-500/30">
                    {lbl}
                  </span>
                ))}
              </div>
            </div>
            <span className="text-xs font-mono text-slate-500 flex-shrink-0">
              HTTP {p.status}
            </span>
          </div>
        ))}
      </div>
    </div>
  )
}

export default function Results({ data, toolName, target }) {
  if (!data) return null
  if (!data.success) {
    return (
      <div className="cyber-card p-5 border border-rose-500/40 bg-rose-500/10 text-rose-300 text-sm font-mono space-y-1">
        <span className="font-bold text-rose-400">✗ ERROR:</span> {data.error || 'Execution returned failure'}
      </div>
    )
  }

  const d = data.data || {}

  const crackedFindings = (d.findings || []).filter(f =>
    f.severity === 'critical' &&
    (f.title.includes('Credentials Found') || f.title.includes('Account Compromised') ||
     f.title.includes('Default Credentials') || f.title.includes('Password Cracked'))
  )

  return (
    <div className="space-y-4 animate-fade-in">
      {d.summary && <SummaryCards summary={d.summary} />}
      {d.cracked_pages?.length > 0 && <CrackedPages pages={d.cracked_pages} />}
      {d.admin_pages?.length > 0 && <AdminPages pages={d.admin_pages} />}

      {/* Show crack banner for any cracked creds */}
      {crackedFindings.map((fnd, i) => (
        <CrackBanner key={i} finding={fnd} toolName={toolName || 'Tool'} target={target || ''} />
      ))}

      {d.findings?.length > 0 && <Findings findings={d.findings} />}
      {d.ports      && <PortsSection ports={d.ports} />}
      {d.dns        && <DnsSection dns={d.dns} />}
      {d.cookies    && <CookiesSection cookies={d.cookies} />}
      {d.records?.length > 0 && (
        <DataTable records={d.records} columns={d.record_columns} />
      )}
      {d.screenshot_b64 && (
        <div className="mb-6 cyber-card p-4">
          <div className="section-title mb-3">
            <span>📷</span>
            <span>TARGET SCREENSHOT</span>
          </div>
          <div className="overflow-hidden rounded-xl border border-white/[0.08] bg-black">
            <img
              src={`data:image/png;base64,${d.screenshot_b64}`}
              alt="Screenshot"
              className="w-full object-contain"
              style={{ maxHeight: '600px' }}
            />
          </div>
          {d.screenshot_path && (
            <a
              href={d.screenshot_path}
              target="_blank"
              rel="noopener noreferrer"
              className="text-slate-400 hover:text-neon-emerald text-xs font-mono mt-2 inline-block transition-colors"
            >
              ↗ Open full resolution
            </a>
          )}
        </div>
      )}
      {d.raw && <RawOutput raw={d.raw} />}
    </div>
  )
}
