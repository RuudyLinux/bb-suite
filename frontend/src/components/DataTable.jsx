import { useState } from 'react'

const STATUS_BADGES = {
  200: 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30',
  201: 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30',
  204: 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30',
  301: 'bg-yellow-500/15 text-yellow-300 border border-yellow-500/30',
  302: 'bg-yellow-500/15 text-yellow-300 border border-yellow-500/30',
  307: 'bg-yellow-500/15 text-yellow-300 border border-yellow-500/30',
  401: 'bg-amber-500/15 text-amber-400 border border-amber-500/30',
  403: 'bg-amber-500/15 text-amber-400 border border-amber-500/30',
  404: 'bg-slate-500/15 text-slate-400 border border-slate-500/30',
  429: 'bg-rose-500/15 text-rose-400 border border-rose-500/30 font-bold',
  500: 'bg-rose-500/20 text-rose-400 border border-rose-500/40 font-bold',
  502: 'bg-rose-500/20 text-rose-400 border border-rose-500/40 font-bold',
  503: 'bg-rose-500/20 text-rose-400 border border-rose-500/40 font-bold',
}

function renderCellContent(val, col) {
  const strVal = String(val)

  // Status code column
  if ((col === 'Status' || col === 'Code') && STATUS_BADGES[Number(val)]) {
    return (
      <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${STATUS_BADGES[Number(val)]}`}>
        {val}
      </span>
    )
  }

  // Result / Success / Cracked
  if (strVal.includes('SUCCESS') || strVal.includes('CRACKED') || (col === 'Exposed' && strVal === 'YES')) {
    return (
      <span className="text-neon-emerald font-bold bg-emerald-500/10 border border-emerald-500/30 px-2 py-0.5 rounded text-[10px]">
        {strVal}
      </span>
    )
  }

  if (strVal === 'Failed' || strVal === '✗ Exhausted' || (col === 'Vulnerable' && strVal === 'NO')) {
    return (
      <span className="text-slate-500 text-[11px]">
        {strVal}
      </span>
    )
  }

  if (strVal === '✓ Present') {
    return (
      <span className="text-neon-emerald font-semibold">
        {strVal}
      </span>
    )
  }

  if (strVal.includes('Missing') || strVal.includes('✗')) {
    return (
      <span className="text-rose-400 font-medium">
        {strVal}
      </span>
    )
  }

  return <span className="text-slate-200">{strVal}</span>
}

export default function DataTable({ records, columns }) {
  const [page, setPage] = useState(0)
  const [search, setSearch] = useState('')
  const PER_PAGE = 25

  if (!records?.length) {
    return (
      <div className="cyber-card p-6 text-center text-slate-500 text-xs font-mono">
        No records available
      </div>
    )
  }

  const cols = columns || Object.keys(records[0])
  const filtered = search
    ? records.filter(r => Object.values(r).some(v => String(v).toLowerCase().includes(search.toLowerCase())))
    : records
  const pages = Math.ceil(filtered.length / PER_PAGE)
  const visible = filtered.slice(page * PER_PAGE, (page + 1) * PER_PAGE)

  return (
    <div className="mb-6 space-y-3">
      {/* Table Title & Quick Filter */}
      <div className="flex items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <span className="text-cyan-400">▦</span>
          <span className="text-xs font-bold uppercase tracking-widest font-mono text-slate-300">
            DATA RECORDS ({filtered.length}{search ? ` of ${records.length}` : ''})
          </span>
        </div>

        {records.length > 5 && (
          <div className="relative">
            <input
              value={search}
              onChange={e => { setSearch(e.target.value); setPage(0) }}
              placeholder="Filter records..."
              className="text-xs bg-cyber-bg/90 border border-white/[0.08] text-slate-200 px-2.5 py-1 pl-7 rounded-lg font-mono w-44 focus:outline-none focus:border-emerald-500/50 transition-all"
            />
            <span className="absolute left-2.5 top-1.5 text-slate-500 text-xs">⌕</span>
            {search && (
              <button
                onClick={() => setSearch('')}
                className="absolute right-2 top-1 text-slate-500 hover:text-slate-300 text-xs"
              >
                ✕
              </button>
            )}
          </div>
        )}
      </div>

      {/* Glass Table */}
      <div className="cyber-card overflow-x-auto">
        <table className="w-full text-xs font-mono">
          <thead>
            <tr className="border-b border-white/[0.08] text-slate-400 bg-white/[0.02]">
              {cols.map(c => (
                <th key={c} className="text-left px-3.5 py-2.5 uppercase tracking-wider text-[11px] whitespace-nowrap">
                  {c}
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-white/[0.04]">
            {visible.map((row, i) => (
              <tr key={i} className="hover:bg-white/[0.02] transition-colors">
                {cols.map(col => {
                  const val = row[col] ?? '—'
                  return (
                    <td key={col} className="px-3.5 py-2.5 break-all max-w-xs">
                      {renderCellContent(val, col)}
                    </td>
                  )
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Pagination Controls */}
      {pages > 1 && (
        <div className="flex items-center justify-between text-xs font-mono text-slate-400 px-1 pt-1">
          <span>
            Showing {page * PER_PAGE + 1}–{Math.min(filtered.length, (page + 1) * PER_PAGE)} of {filtered.length}
          </span>
          <div className="flex items-center gap-1.5">
            <button
              onClick={() => setPage(p => Math.max(0, p - 1))}
              disabled={page === 0}
              className="hack-btn-sm disabled:opacity-30 disabled:cursor-not-allowed"
            >
              ◀ Prev
            </button>
            <span className="px-2 py-1 text-slate-300 font-semibold bg-white/[0.04] rounded">
              {page + 1} / {pages}
            </span>
            <button
              onClick={() => setPage(p => Math.min(pages - 1, p + 1))}
              disabled={page >= pages - 1}
              className="hack-btn-sm disabled:opacity-30 disabled:cursor-not-allowed"
            >
              Next ▶
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
