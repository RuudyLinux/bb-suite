import { useState, useEffect, useRef } from 'react'

const MAX_HISTORY = 8

export default function Header({ target, onTargetChange, onHome }) {
  const [val,          setVal]          = useState(target)
  const [showHistory,  setShowHistory]  = useState(false)
  const [history,      setHistory]      = useState(() => {
    try { return JSON.parse(localStorage.getItem('bb_target_history') || '[]') }
    catch { return [] }
  })
  const dropRef = useRef(null)

  useEffect(() => setVal(target), [target])

  // Close dropdown on outside click
  useEffect(() => {
    const handler = (e) => {
      if (dropRef.current && !dropRef.current.contains(e.target)) {
        setShowHistory(false)
      }
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [])

  const commit = (overrideVal) => {
    const v = (overrideVal !== undefined ? overrideVal : val).trim()
    if (!v) return
    onTargetChange(v)
    setShowHistory(false)
    // Save to history
    setHistory(prev => {
      const next = [v, ...prev.filter(h => h !== v)].slice(0, MAX_HISTORY)
      try { localStorage.setItem('bb_target_history', JSON.stringify(next)) } catch {}
      return next
    })
  }

  const clearHistory = () => {
    setHistory([])
    try { localStorage.removeItem('bb_target_history') } catch {}
    setShowHistory(false)
  }

  const removeHistoryItem = (item, e) => {
    e.stopPropagation()
    setHistory(prev => {
      const next = prev.filter(h => h !== item)
      try { localStorage.setItem('bb_target_history', JSON.stringify(next)) } catch {}
      return next
    })
  }

  const cleanDomain = target ? target.replace(/^https?:\/\//, '').split('/')[0] : ''

  const PRESETS = [
    { label: 'HTTPBin',   url: 'https://httpbin.org'       },
    { label: 'Example',   url: 'https://example.com'       },
    { label: 'Localhost', url: 'http://localhost:8000'      },
  ]

  return (
    <header className="fixed top-0 left-0 right-0 h-14 z-50 flex items-center px-4 gap-4
                       bg-cyber-surface/90 backdrop-blur-xl border-b border-white/[0.08] shadow-lg">

      {/* Brand / Home Button */}
      <button
        onClick={onHome}
        className="flex items-center gap-2.5 flex-shrink-0 group hover:opacity-95 transition-all text-left"
        title="Return to Security Operations Deck"
      >
        <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-emerald-400/20 to-cyan-500/10 border border-emerald-500/40
                        flex items-center justify-center shadow-[0_0_12px_rgba(0,255,136,0.25)] group-hover:border-neon-emerald transition-colors">
          <span className="text-neon-emerald text-base font-bold">⚡</span>
        </div>
        <div>
          <div className="flex items-center gap-1.5">
            <span className="font-extrabold text-sm tracking-wider bg-gradient-to-r from-emerald-400 via-teal-300 to-cyan-400 bg-clip-text text-transparent">
              BB-SUITE
            </span>
            <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
              v4.0
            </span>
          </div>
          <div className="flex items-center gap-1.5 text-[9px] font-mono text-slate-400">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-ping inline-block" />
            <span className="text-emerald-400/90 font-medium tracking-wider">SYSTEM ARMED</span>
          </div>
        </div>
      </button>

      <div className="h-6 w-px bg-white/[0.08] hidden sm:block" />

      {/* Target Command Input with History */}
      <div className="flex items-center gap-2 flex-1 max-w-2xl relative" ref={dropRef}>
        <div className="flex items-center gap-2 w-full bg-cyber-bg/70 border border-white/[0.08] rounded-xl px-2.5 py-1.5
                        focus-within:border-emerald-500/50 focus-within:ring-2 focus-within:ring-emerald-500/10 transition-all">
          <span className="text-slate-400 text-xs font-mono pl-1 hidden sm:inline select-none">TARGET://</span>
          <input
            value={val}
            onChange={e => { setVal(e.target.value); setShowHistory(false) }}
            onKeyDown={e => { if (e.key === 'Enter') commit(); if (e.key === 'Escape') setShowHistory(false) }}
            onFocus={() => history.length > 0 && setShowHistory(true)}
            placeholder="https://example.com or domain.com"
            className="flex-1 bg-transparent text-slate-100 text-xs sm:text-sm font-mono placeholder-slate-600 focus:outline-none min-w-0"
            autoComplete="off"
            spellCheck={false}
          />

          {val && (
            <button
              onClick={() => { setVal(''); onTargetChange('') }}
              className="text-slate-500 hover:text-slate-300 text-xs px-1.5 transition-colors"
              title="Clear target"
            >
              ✕
            </button>
          )}

          {/* History toggle */}
          {history.length > 0 && (
            <button
              onClick={() => setShowHistory(p => !p)}
              className="text-slate-500 hover:text-slate-300 text-xs px-1.5 transition-colors border-l border-white/[0.08] pl-2"
              title="Recent targets"
            >
              {showHistory ? '▲' : '▼'}
            </button>
          )}

          <button
            onClick={() => commit()}
            className="hack-btn py-1.5 px-3.5 text-[11px] font-bold tracking-wider flex-shrink-0"
          >
            SET TARGET ▶
          </button>
        </div>

        {/* History Dropdown */}
        {showHistory && history.length > 0 && (
          <div className="absolute top-full left-0 right-0 mt-1.5 bg-cyber-surface/95 backdrop-blur-xl border border-white/[0.12]
                          rounded-xl shadow-[0_16px_48px_rgba(0,0,0,0.6)] overflow-hidden z-50 animate-fade-in">
            <div className="flex items-center justify-between px-3 py-2 border-b border-white/[0.06]">
              <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider">Recent Targets</span>
              <button
                onClick={clearHistory}
                className="text-[10px] font-mono text-slate-500 hover:text-rose-400 transition-colors"
              >
                Clear all
              </button>
            </div>
            {history.map((h, i) => (
              <div
                key={i}
                onClick={() => { setVal(h); commit(h) }}
                className="flex items-center gap-3 px-3 py-2 hover:bg-white/[0.05] cursor-pointer group transition-colors border-b border-white/[0.04] last:border-0"
              >
                <span className="text-slate-500 text-xs">⏱</span>
                <span className="font-mono text-xs text-slate-200 flex-1 truncate">{h}</span>
                <button
                  onClick={(e) => removeHistoryItem(h, e)}
                  className="text-slate-600 hover:text-slate-300 text-xs opacity-0 group-hover:opacity-100 transition-all"
                >
                  ✕
                </button>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Quick Presets */}
      <div className="hidden xl:flex items-center gap-1.5">
        <span className="text-[10px] text-slate-500 uppercase tracking-widest font-mono mr-1">Presets:</span>
        {PRESETS.map(p => (
          <button
            key={p.label}
            onClick={() => { setVal(p.url); commit(p.url) }}
            className={`text-[10px] font-mono px-2 py-1 rounded border transition-all ${
              val === p.url
                ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40 shadow-[0_0_8px_rgba(0,255,136,0.2)]'
                : 'bg-white/[0.03] text-slate-400 border-white/[0.06] hover:bg-white/[0.08] hover:text-slate-200'
            }`}
          >
            {p.label}
          </button>
        ))}
      </div>

      {/* Right side: target display + auth warning */}
      <div className="ml-auto flex items-center gap-3 flex-shrink-0">
        {cleanDomain && (
          <div className="hidden md:flex items-center gap-2 bg-emerald-500/10 border border-emerald-500/20 px-2.5 py-1 rounded-lg">
            <span className="w-2 h-2 rounded-full bg-emerald-400 shadow-[0_0_6px_#00ff88]" />
            <span className="text-xs font-mono text-emerald-300 font-medium truncate max-w-[160px]">
              {cleanDomain}
            </span>
          </div>
        )}

        <div className="border border-rose-500/30 bg-rose-500/10 text-rose-400 text-[10px] font-mono px-2.5 py-1 rounded-lg tracking-wider flex items-center gap-1.5">
          <span className="text-rose-400 text-xs">⚠</span>
          <span className="hidden sm:inline">AUTH TEST ONLY</span>
        </div>
      </div>

    </header>
  )
}
