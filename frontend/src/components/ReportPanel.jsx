import { useState, useEffect } from 'react'

function ReportRow({ report }) {
  const ts = report.timestamp ? new Date(report.timestamp).toLocaleString() : '—'
  return (
    <div className="flex items-center gap-3 px-3 py-2 border-b border-matrix-950 hover:bg-matrix-950/40 transition-colors">
      <div className="flex-1 min-w-0">
        <div className="text-matrix-400 text-xs font-bold truncate">{report.target}</div>
        <div className="text-matrix-800 text-xs">{ts} &nbsp;·&nbsp; {report.size_kb}KB</div>
      </div>
      <div className="flex gap-2 items-center flex-shrink-0">
        {report.critical > 0 && (
          <span className="text-xs px-1.5 py-0.5" style={{ color: '#ff0000', background: '#ff000015' }}>
            C{report.critical}
          </span>
        )}
        {report.high > 0 && (
          <span className="text-xs px-1.5 py-0.5" style={{ color: '#ff6600', background: '#ff660015' }}>
            H{report.high}
          </span>
        )}
        <span className="text-matrix-800 text-xs">{report.total_findings} findings</span>
        <a
          href={`/api/reports/${report.html_file}`}
          target="_blank"
          rel="noopener noreferrer"
          className="hack-btn-sm text-xs"
        >
          ↗ HTML
        </a>
      </div>
    </div>
  )
}

export default function ReportPanel({ newReportSaved }) {
  const [reports, setReports]   = useState([])
  const [loading, setLoading]   = useState(false)
  const [open, setOpen]         = useState(false)

  const fetchReports = async () => {
    setLoading(true)
    try {
      const r = await fetch('/api/reports')
      const d = await r.json()
      setReports(d.data?.reports || [])
    } catch (e) {
      console.error('fetchReports:', e)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    if (open) fetchReports()
  }, [open, newReportSaved])

  return (
    <div className="border border-matrix-900 bg-hack-card">
      {/* Header toggle */}
      <button
        onClick={() => setOpen(p => !p)}
        className="w-full flex items-center gap-3 px-4 py-3 hover:bg-matrix-950/50 transition-colors"
      >
        <span className="text-matrix-400 text-sm">📁</span>
        <span className="text-matrix-600 text-xs uppercase tracking-widest">Reports Folder</span>
        {reports.length > 0 && (
          <span className="text-matrix-800 text-xs">({reports.length} saved)</span>
        )}
        <button
          onClick={e => { e.stopPropagation(); fetchReports() }}
          className="ml-auto text-matrix-800 text-xs hover:text-matrix-400"
        >
          ↺
        </button>
        <span className="text-matrix-800 text-xs">{open ? '▼' : '▶'}</span>
      </button>

      {open && (
        <div style={{ borderTop: '1px solid #001a00' }}>
          {loading && (
            <div className="px-4 py-3 text-matrix-800 text-xs flex items-center gap-2">
              <span className="animate-spin">◌</span> Loading reports...
            </div>
          )}
          {!loading && reports.length === 0 && (
            <div className="px-4 py-3 text-matrix-900 text-xs">
              No reports yet — run "Perform All Tools" to generate one.
            </div>
          )}
          {reports.map((r, i) => (
            <ReportRow key={i} report={r} />
          ))}
        </div>
      )}
    </div>
  )
}
