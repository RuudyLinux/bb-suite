import { useState, useMemo } from 'react'
import { CATEGORIES, TOOL_CONFIGS } from '../config/tools'

const CAT_THEMES = {
  recon:        { color: 'text-cyan-400',    bg: 'bg-cyan-500/10',    border: 'border-cyan-500/30',    indicator: '#06b6d4' },
  analysis:     { color: 'text-blue-400',    bg: 'bg-blue-500/10',    border: 'border-blue-500/30',    indicator: '#3b82f6' },
  scanning:     { color: 'text-purple-400',  bg: 'bg-purple-500/10',  border: 'border-purple-500/30',  indicator: '#a855f7' },
  exploit:      { color: 'text-rose-400',    bg: 'bg-rose-500/10',    border: 'border-rose-500/30',    indicator: '#f43f5e' },
  vuln_map:     { color: 'text-red-400',     bg: 'bg-red-500/10',     border: 'border-red-500/30',     indicator: '#ef4444' },
  intelligence: { color: 'text-teal-400',    bg: 'bg-teal-500/10',    border: 'border-teal-500/30',    indicator: '#14b8a6' },
  zap:          { color: 'text-amber-400',   bg: 'bg-amber-500/10',   border: 'border-amber-500/30',   indicator: '#f59e0b' },
}

export default function Sidebar({ activeTool, onSelectTool, onHome }) {
  const [collapsed, setCollapsed] = useState({})
  const [search, setSearch] = useState('')

  const toggle = (id) => setCollapsed(p => ({ ...p, [id]: !p[id] }))

  // Filter tools dynamically based on search
  const filteredCategories = useMemo(() => {
    if (!search.trim()) return CATEGORIES
    const query = search.toLowerCase()
    return CATEGORIES.map(cat => {
      const matchingTools = cat.tools.filter(toolId => {
        const cfg = TOOL_CONFIGS[toolId]
        if (!cfg) return false
        return cfg.name.toLowerCase().includes(query) ||
               (cfg.desc && cfg.desc.toLowerCase().includes(query)) ||
               toolId.toLowerCase().includes(query)
      })
      return { ...cat, tools: matchingTools }
    }).filter(cat => cat.tools.length > 0)
  }, [search])

  const totalToolsCount = Object.keys(TOOL_CONFIGS).length

  return (
    <aside className="w-64 flex-shrink-0 overflow-y-auto flex flex-col bg-cyber-surface/90 backdrop-blur-xl border-r border-white/[0.08] select-none z-40">
      
      {/* Home / Dashboard Link */}
      <div className="p-3 pb-2">
        <button
          onClick={onHome}
          className={`w-full px-3 py-2.5 rounded-xl text-left flex items-center gap-3 transition-all ${
            !activeTool
              ? 'bg-gradient-to-r from-emerald-500/20 to-teal-500/10 border border-emerald-500/40 text-neon-emerald font-semibold shadow-[0_0_15px_rgba(0,255,136,0.15)]'
              : 'bg-white/[0.02] border border-white/[0.05] text-slate-400 hover:text-slate-200 hover:bg-white/[0.05]'
          }`}
        >
          <span className="text-base">⌂</span>
          <div className="flex-1 min-w-0">
            <div className="text-xs uppercase tracking-wider font-bold">Command Center</div>
            <div className="text-[10px] text-slate-500 font-mono">Overview & Telemetry</div>
          </div>
          {!activeTool && (
            <span className="w-2 h-2 rounded-full bg-neon-emerald animate-pulse shadow-[0_0_8px_#00ff88]" />
          )}
        </button>
      </div>

      {/* Live Tool Search */}
      <div className="px-3 pb-3">
        <div className="relative">
          <input
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder={`Filter ${totalToolsCount} tools...`}
            className="w-full bg-cyber-bg/90 border border-white/[0.08] text-slate-200 text-xs px-3 py-1.5 pl-8 rounded-lg font-mono
                       placeholder-slate-600 focus:outline-none focus:border-emerald-500/50 focus:ring-1 focus:ring-emerald-500/20 transition-all"
          />
          <span className="absolute left-2.5 top-2 text-slate-500 text-xs">⌕</span>
          {search && (
            <button
              onClick={() => setSearch('')}
              className="absolute right-2.5 top-1.5 text-slate-500 hover:text-slate-300 text-xs"
            >
              ✕
            </button>
          )}
        </div>
      </div>

      {/* Categorized Tool Navigation */}
      <nav className="flex-1 px-2 space-y-1.5 pb-4">
        {filteredCategories.length === 0 ? (
          <div className="text-center py-8 px-4 text-slate-500 text-xs font-mono">
            No tools matching "{search}"
          </div>
        ) : (
          filteredCategories.map(cat => {
            const theme = CAT_THEMES[cat.id] || { color: 'text-slate-400', bg: 'bg-white/5', border: 'border-white/10' }
            const isCollapsed = collapsed[cat.id] && !search

            return (
              <div key={cat.id} className="rounded-xl overflow-hidden bg-white/[0.015] border border-white/[0.04]">
                {/* Category Header */}
                <button
                  onClick={() => toggle(cat.id)}
                  className="w-full flex items-center gap-2.5 px-3 py-2 text-xs font-medium text-slate-400
                             hover:text-slate-200 hover:bg-white/[0.03] transition-colors uppercase tracking-wider"
                >
                  <span className={`text-sm ${theme.color}`}>{cat.icon}</span>
                  <span className="text-[11px] font-semibold">{cat.label}</span>
                  
                  <span className={`ml-auto text-[10px] font-mono px-1.5 py-0.2 rounded-full ${theme.bg} ${theme.color} border ${theme.border}`}>
                    {cat.tools.length}
                  </span>

                  <span className="text-slate-600 text-[10px] ml-1">
                    {isCollapsed ? '▶' : '▼'}
                  </span>
                </button>

                {/* Tool Items in Category */}
                {!isCollapsed && (
                  <div className="px-1.5 pb-1.5 space-y-0.5">
                    {cat.tools.map(toolId => {
                      const cfg = TOOL_CONFIGS[toolId]
                      if (!cfg) return null
                      const isActive = activeTool === toolId

                      return (
                        <button
                          key={toolId}
                          onClick={() => onSelectTool(toolId)}
                          className={`w-full text-left px-2.5 py-1.5 rounded-lg text-xs font-mono flex items-center gap-2 transition-all ${
                            isActive
                              ? 'bg-emerald-500/15 text-neon-emerald font-semibold border-l-2 border-neon-emerald shadow-[inset_4px_0_10px_-2px_rgba(0,255,136,0.3)]'
                              : 'text-slate-400 hover:text-slate-200 hover:bg-white/[0.04]'
                          }`}
                        >
                          <span className={`text-xs ${isActive ? 'text-neon-emerald' : 'text-slate-500'}`}>
                            {cfg.icon || '▪'}
                          </span>
                          <span className="truncate flex-1">{cfg.name}</span>
                          {isActive && (
                            <span className="w-1.5 h-1.5 rounded-full bg-neon-emerald shadow-[0_0_6px_#00ff88]" />
                          )}
                        </button>
                      )
                    })}
                  </div>
                )}
              </div>
            )
          })
        )}
      </nav>

      {/* Bottom Telemetry Footer */}
      <div className="p-3 border-t border-white/[0.08] bg-cyber-bg/50 text-[10px] font-mono text-slate-500 flex items-center justify-between">
        <span className="flex items-center gap-1.5">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
          <span>{totalToolsCount} ACTIVE TOOLS</span>
        </span>
        <span className="text-slate-600">v4.0 SEC</span>
      </div>

    </aside>
  )
}
