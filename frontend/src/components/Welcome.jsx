import { useState, useEffect } from 'react'

const CAPABILITIES = [
  {
    id: 'xss_scanner',
    icon: '🎯',
    title: 'XSS Scanner',
    category: 'SCANNING',
    color: 'text-orange-400',
    border: 'hover:border-orange-500/50',
    badge: 'bg-orange-500/10 text-orange-400 border-orange-500/30',
    glow: 'shadow-[0_0_20px_rgba(249,115,22,0.15)]',
    desc: 'Polyglot payload injection for Reflected, DOM-based, and Form XSS across URL params, event sinks, and POST inputs.',
  },
  {
    id: 'lfi_scanner',
    icon: '📁',
    title: 'LFI / Path Traversal',
    category: 'SCANNING',
    color: 'text-amber-400',
    border: 'hover:border-amber-500/50',
    badge: 'bg-amber-500/10 text-amber-400 border-amber-500/30',
    glow: 'shadow-[0_0_20px_rgba(245,158,11,0.15)]',
    desc: 'Unix/Windows traversal, PHP wrapper injection (php://, data://), null byte bypass, and response-size anomaly detection.',
  },
  {
    id: 'open_redirect',
    icon: '↪',
    title: 'Open Redirect',
    category: 'SCANNING',
    color: 'text-pink-400',
    border: 'hover:border-pink-500/50',
    badge: 'bg-pink-500/10 text-pink-400 border-pink-500/30',
    glow: 'shadow-[0_0_20px_rgba(236,72,153,0.15)]',
    desc: 'Detect open redirect vectors across URL params and crawled links with double-slash, URL-encoding, and null-byte bypass.',
  },
  {
    id: 'password_cracker',
    icon: '⚡',
    title: 'Password & Hash Cracker',
    category: 'EXPLOIT',
    color: 'text-amber-400',
    border: 'hover:border-amber-500/50',
    badge: 'bg-amber-500/10 text-amber-400 border-amber-500/30',
    glow: 'shadow-[0_0_20px_rgba(245,158,11,0.15)]',
    desc: 'High-speed offline hash cracking (MD5, SHA1/256/512, NTLM, MySQL, Bcrypt, APR1), rule-based mutation, and entropy analysis.',
  },
  {
    id: 'vuln_map',
    icon: '💀',
    title: 'Full Vulnerability Map',
    category: 'VULN MAP',
    color: 'text-rose-400',
    border: 'hover:border-rose-500/50',
    badge: 'bg-rose-500/10 text-rose-400 border-rose-500/30',
    glow: 'shadow-[0_0_20px_rgba(244,63,94,0.15)]',
    desc: 'Deep crawl and automated vulnerability assessment testing every discovered page for SQLi, XSS, and sensitive exposure.',
  },
  {
    id: 'sqli',
    icon: '💉',
    title: 'SQL Injection Hunter',
    category: 'EXPLOIT',
    color: 'text-rose-400',
    border: 'hover:border-rose-500/50',
    badge: 'bg-rose-500/10 text-rose-400 border-rose-500/30',
    glow: 'shadow-[0_0_20px_rgba(244,63,94,0.15)]',
    desc: 'Test URL parameters for error-based, boolean-blind, and time-delay SQL injection across MySQL, PostgreSQL, and MSSQL.',
  },
  {
    id: 'subdomain_takeover',
    icon: '⚑',
    title: 'Subdomain Takeover',
    category: 'RECON',
    color: 'text-cyan-400',
    border: 'hover:border-cyan-500/50',
    badge: 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30',
    glow: 'shadow-[0_0_20px_rgba(6,182,212,0.15)]',
    desc: 'Detect dangling DNS CNAME records pointing to unclaimed services like AWS S3, GitHub Pages, Netlify, and Heroku.',
  },
  {
    id: 'api_security',
    icon: '⇌',
    title: 'API & GraphQL Security',
    category: 'SCANNING',
    color: 'text-purple-400',
    border: 'hover:border-purple-500/50',
    badge: 'bg-purple-500/10 text-purple-400 border-purple-500/30',
    glow: 'shadow-[0_0_20px_rgba(168,85,247,0.15)]',
    desc: 'Uncover hidden OpenAPI/Swagger schemas, probe GraphQL introspection, test unauthenticated endpoints, and rate limits.',
  },
  {
    id: 'ai_analysis',
    icon: '🤖',
    title: 'AI Threat Intelligence',
    category: 'INTELLIGENCE',
    color: 'text-teal-400',
    border: 'hover:border-teal-500/50',
    badge: 'bg-teal-500/10 text-teal-400 border-teal-500/30',
    glow: 'shadow-[0_0_20px_rgba(20,184,166,0.15)]',
    desc: 'Generate automated triage, vulnerability remediation strategies, and executive threat reports using advanced AI models.',
  },
]

const STATS = [
  { label: 'Reconnaissance', count: 7,  color: 'text-cyan-400',   border: 'border-cyan-500/20',   bg: 'bg-cyan-500/5'   },
  { label: 'Analysis',       count: 8,  color: 'text-blue-400',   border: 'border-blue-500/20',   bg: 'bg-blue-500/5'   },
  { label: 'Scanning',       count: 13, color: 'text-purple-400', border: 'border-purple-500/20', bg: 'bg-purple-500/5' },
  { label: 'Exploitation',   count: 6,  color: 'text-rose-400',   border: 'border-rose-500/20',   bg: 'bg-rose-500/5'   },
  { label: 'Vuln Map',       count: 1,  color: 'text-red-400',    border: 'border-red-500/20',    bg: 'bg-red-500/5'    },
  { label: 'Intelligence',   count: 2,  color: 'text-teal-400',   border: 'border-teal-500/20',   bg: 'bg-teal-500/5'   },
  { label: 'OWASP ZAP',      count: 1,  color: 'text-amber-400',  border: 'border-amber-500/20',  bg: 'bg-amber-500/5'  },
]

const OWASP_TOP10 = [
  { rank: 'A01', name: 'Broken Access Control',      tool: 'auth_flaws',    color: 'text-rose-400'   },
  { rank: 'A02', name: 'Cryptographic Failures',     tool: 'tls',           color: 'text-orange-400' },
  { rank: 'A03', name: 'Injection (SQL/XSS/SSTI)',   tool: 'sqli',          color: 'text-rose-500'   },
  { rank: 'A04', name: 'Insecure Design',            tool: 'vuln_detection',color: 'text-amber-400'  },
  { rank: 'A05', name: 'Security Misconfiguration',  tool: 'headers',       color: 'text-yellow-400' },
  { rank: 'A06', name: 'Vulnerable Components',      tool: 'http_security', color: 'text-orange-400' },
  { rank: 'A07', name: 'Auth & Session Failures',    tool: 'cookies',       color: 'text-red-400'    },
  { rank: 'A08', name: 'Software & Data Integrity',  tool: 'js_intel',      color: 'text-purple-400' },
  { rank: 'A09', name: 'Security Logging Failures',  tool: 'cors',          color: 'text-blue-400'   },
  { rank: 'A10', name: 'SSRF (Server-Side Forgery)', tool: 'ssrf_scanner',  color: 'text-cyan-400'   },
]

// Animated terminal log lines to simulate activity
const LOG_LINES = [
  { delay: 0,    text: '$ bb-suite --version',                  color: 'text-neon-emerald' },
  { delay: 400,  text: '  BB-Suite v4.0 — 38 Strix-grade modules loaded', color: 'text-slate-300'   },
  { delay: 900,  text: '$ scan --target example.com --all',     color: 'text-neon-emerald' },
  { delay: 1400, text: '  [*] IP resolved: 93.184.216.34',      color: 'text-slate-300'   },
  { delay: 1900, text: '  [+] Ports: 80/open, 443/open',        color: 'text-cyan-400'    },
  { delay: 2400, text: '  [!] Missing CSP header detected',     color: 'text-amber-400'   },
  { delay: 2900, text: '  [!] CORS: wildcard (*) origin allowed',color: 'text-amber-400'  },
  { delay: 3400, text: '  [CRIT] XSS in param ?q= (reflected)', color: 'text-rose-400'    },
  { delay: 3900, text: '  [CRIT] SQLi: time-based (param: id)', color: 'text-rose-400'    },
  { delay: 4400, text: '  [+] Report saved → report_2026.html', color: 'text-neon-emerald'},
  { delay: 4900, text: '$ _',                                    color: 'text-neon-emerald', blink: true },
]

function AnimatedTerminal() {
  const [visibleLines, setVisibleLines] = useState(0)

  useEffect(() => {
    LOG_LINES.forEach((line, idx) => {
      setTimeout(() => setVisibleLines(idx + 1), line.delay)
    })
  }, [])

  return (
    <div className="bg-black/60 rounded-xl border border-white/[0.08] p-4 font-mono text-xs overflow-hidden">
      {/* Terminal title bar */}
      <div className="flex items-center gap-2 mb-3 pb-2 border-b border-white/[0.06]">
        <span className="w-3 h-3 rounded-full bg-rose-500/70" />
        <span className="w-3 h-3 rounded-full bg-amber-500/70" />
        <span className="w-3 h-3 rounded-full bg-emerald-500/70" />
        <span className="ml-2 text-slate-500 text-[10px] tracking-wider">bb-suite terminal</span>
      </div>
      <div className="space-y-1 min-h-[180px]">
        {LOG_LINES.slice(0, visibleLines).map((line, i) => (
          <div key={i} className={`${line.color} transition-all duration-200`}>
            {line.text}
            {line.blink && <span className="animate-blink">▌</span>}
          </div>
        ))}
      </div>
    </div>
  )
}

function StatCard({ stat, index }) {
  const [count, setCount] = useState(0)

  useEffect(() => {
    const delay = index * 80
    const timer = setTimeout(() => {
      let current = 0
      const step = () => {
        current += 1
        setCount(current)
        if (current < stat.count) requestAnimationFrame(step)
      }
      requestAnimationFrame(step)
    }, delay)
    return () => clearTimeout(timer)
  }, [stat.count, index])

  return (
    <div className={`cyber-card p-3.5 text-center border ${stat.border} ${stat.bg} group hover:scale-105 transition-all duration-200`}>
      <div className={`text-2xl font-extrabold font-mono ${stat.color} group-hover:drop-shadow-lg transition-all`}>
        {count}
      </div>
      <div className="text-[10px] text-slate-400 uppercase tracking-wider font-mono mt-1">
        {stat.label}
      </div>
    </div>
  )
}

export default function Welcome({ onSelectTool }) {
  return (
    <div className="p-6 md:p-10 max-w-7xl mx-auto space-y-10 animate-fade-in">

      {/* ── Hero Section ─────────────────────────────────────── */}
      <div className="relative overflow-hidden rounded-2xl bg-gradient-to-br from-cyber-surface/90 via-cyber-surface/60 to-cyber-bg/90
                      border border-white/[0.08] p-8 md:p-12 shadow-2xl backdrop-blur-2xl">
        <div className="absolute -top-24 -right-24 w-96 h-96 bg-emerald-500/8 rounded-full blur-3xl pointer-events-none" />
        <div className="absolute -bottom-24 -left-24 w-80 h-80 bg-cyan-500/8 rounded-full blur-3xl pointer-events-none" />
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[200px] bg-purple-500/3 rounded-full blur-3xl pointer-events-none" />

        <div className="relative z-10 grid grid-cols-1 lg:grid-cols-2 gap-10 items-center">
          {/* Left: Text */}
          <div className="space-y-5">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs font-mono">
              <span className="w-2 h-2 rounded-full bg-neon-emerald animate-ping" />
              <span>SECURITY OPS CENTER // v4.0 — 38 MODULES</span>
            </div>

            <h1 className="text-3xl md:text-5xl font-extrabold tracking-tight text-white leading-tight">
              Advanced Penetration
              <br />
              <span className="bg-gradient-to-r from-emerald-400 via-teal-300 to-cyan-400 bg-clip-text text-transparent">
                Testing Suite
              </span>
            </h1>

            <p className="text-slate-400 text-sm md:text-base leading-relaxed max-w-lg">
              Multi-vector security assessment powered by{' '}
              <span className="text-neon-emerald font-semibold">38 offensive modules</span> —
              XSS, SQLi, LFI, open redirects, brute force, JWT analysis,
              subdomain takeover, and AI-powered threat intelligence.
            </p>

            {/* CTA */}
            <div className="pt-2 flex flex-col sm:flex-row items-stretch sm:items-center gap-3">
              <div className="flex items-center gap-2 px-4 py-3 rounded-xl bg-white/[0.03] border border-white/[0.08] text-slate-300 text-xs font-mono">
                <span className="text-neon-emerald text-base">↑</span>
                <span>Enter target URL above and click <strong className="text-neon-emerald">SET TARGET</strong></span>
              </div>
              <button
                onClick={() => onSelectTool('vuln_map')}
                className="hack-btn text-xs py-3 px-5 flex-shrink-0"
              >
                LAUNCH VULN MAP 💀
              </button>
            </div>

            {/* New tools badge row */}
            <div className="flex flex-wrap gap-2 pt-1">
              {['XSS Scanner', 'LFI Scanner', 'Open Redirect'].map(t => (
                <span key={t} className="text-[10px] font-mono px-2.5 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
                  NEW: {t}
                </span>
              ))}
            </div>
          </div>

          {/* Right: Animated Terminal */}
          <div className="hidden lg:block">
            <AnimatedTerminal />
          </div>
        </div>
      </div>

      {/* ── Animated Stats Ribbon ─────────────────────────────── */}
      <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-3">
        {STATS.map((s, i) => (
          <StatCard key={s.label} stat={s} index={i} />
        ))}
      </div>

      {/* ── Capabilities Grid ────────────────────────────────── */}
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-xs uppercase tracking-widest font-mono text-slate-400 flex items-center gap-2">
            <span className="text-neon-emerald">◈</span>
            <span>CORE OFFENSIVE CAPABILITIES</span>
          </h2>
          <span className="text-[11px] font-mono text-slate-500">SELECT TO EXECUTE</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {CAPABILITIES.map(cap => (
            <div
              key={cap.id}
              onClick={() => onSelectTool(cap.id)}
              className={`cyber-card p-5 cursor-pointer group hover:bg-white/[0.04] transition-all duration-200 border ${cap.border} ${cap.glow} hover:scale-[1.02]`}
            >
              <div className="flex items-start justify-between mb-3">
                <div className={`w-10 h-10 rounded-xl bg-white/[0.04] border border-white/[0.08] flex items-center justify-center text-xl
                                group-hover:scale-110 group-hover:border-white/20 transition-all`}>
                  {cap.icon}
                </div>
                <span className={`text-[10px] font-mono px-2 py-0.5 rounded border uppercase tracking-wider ${cap.badge}`}>
                  {cap.category}
                </span>
              </div>

              <h3 className={`text-sm font-bold text-white group-hover:${cap.color} transition-colors mb-1.5`}>
                {cap.title}
              </h3>

              <p className="text-xs text-slate-400 leading-relaxed mb-4">
                {cap.desc}
              </p>

              <div className={`flex items-center gap-1.5 text-xs font-mono text-slate-500 group-hover:${cap.color} transition-colors`}>
                <span>LAUNCH TOOL</span>
                <span className="group-hover:translate-x-1 transition-transform">→</span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* ── OWASP Top 10 Quick Reference ─────────────────────── */}
      <div className="space-y-3">
        <div className="flex items-center gap-2">
          <span className="text-neon-emerald text-xs font-mono">▦</span>
          <span className="text-xs uppercase tracking-widest font-mono text-slate-400">OWASP TOP 10 — MAPPED TO TOOLS</span>
        </div>

        <div className="cyber-card overflow-hidden">
          <div className="grid grid-cols-1 sm:grid-cols-2 divide-y sm:divide-y-0 sm:divide-x divide-white/[0.06]">
            {[OWASP_TOP10.slice(0, 5), OWASP_TOP10.slice(5)].map((col, ci) => (
              <div key={ci} className="divide-y divide-white/[0.04]">
                {col.map(item => (
                  <button
                    key={item.rank}
                    onClick={() => onSelectTool(item.tool)}
                    className="w-full flex items-center gap-3 px-4 py-2.5 hover:bg-white/[0.03] transition-colors text-left group"
                  >
                    <span className={`text-[10px] font-mono font-bold w-10 flex-shrink-0 ${item.color}`}>{item.rank}</span>
                    <span className="text-xs text-slate-300 group-hover:text-white transition-colors flex-1">{item.name}</span>
                    <span className="text-[10px] font-mono text-slate-600 group-hover:text-slate-400 transition-colors flex-shrink-0">→ TEST</span>
                  </button>
                ))}
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* ── Footer ───────────────────────────────────────────── */}
      <div className="flex items-center justify-between text-[11px] font-mono text-slate-500 border-t border-white/[0.08] pt-6">
        <div className="flex items-center gap-2">
          <span className="text-amber-400">⚡</span>
          <span>BB-SUITE v4.0 // Python FastAPI + React Vite // 38 Security Modules</span>
        </div>
        <div className="text-rose-400/80">Authorized Security Audits Only</div>
      </div>

    </div>
  )
}
