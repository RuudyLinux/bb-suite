import { useState } from 'react'

function Section({ title, color = '#00ff41', children }) {
  const [open, setOpen] = useState(true)
  return (
    <div className="mb-3" style={{ borderLeft: `2px solid ${color}30` }}>
      <button
        onClick={() => setOpen(p => !p)}
        className="w-full flex items-center gap-2 px-3 py-1.5 text-left"
        style={{ background: `${color}08` }}
      >
        <span style={{ color, fontSize: '10px' }}>{open ? '▼' : '▶'}</span>
        <span className="text-xs font-bold uppercase tracking-widest" style={{ color }}>{title}</span>
      </button>
      {open && <div className="px-3 py-2">{children}</div>}
    </div>
  )
}

function DataTable({ rows, columns, color = '#00cc33' }) {
  if (!rows?.length) return <div style={{ color: '#333', fontSize: '11px' }}>No data</div>
  const cols = columns || Object.keys(rows[0] || {})
  return (
    <div className="overflow-x-auto">
      <table style={{ fontSize: '10px', borderCollapse: 'collapse', width: '100%' }}>
        <thead>
          <tr>
            {cols.map(c => (
              <th key={c} style={{ padding: '3px 8px', borderBottom: `1px solid ${color}30`,
                                   textAlign: 'left', color: `${color}88`, textTransform: 'uppercase',
                                   letterSpacing: '1px', fontFamily: 'monospace' }}>
                {c}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.slice(0, 30).map((row, i) => (
            <tr key={i} style={{ borderBottom: '1px solid #0a0a0a' }}>
              {cols.map(c => (
                <td key={c} style={{ padding: '3px 8px', color, fontFamily: 'monospace',
                                     maxWidth: '300px', overflow: 'hidden', textOverflow: 'ellipsis',
                                     whiteSpace: 'nowrap' }}>
                  {String(row[c] ?? '—')}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
      {rows.length > 30 && (
        <div style={{ color: '#333', fontSize: '10px', padding: '4px 8px' }}>
          +{rows.length - 30} more rows
        </div>
      )}
    </div>
  )
}

function SensitiveFields({ fields }) {
  if (!fields?.length) return null
  return (
    <div>
      {fields.map((f, i) => (
        <div key={i} className="flex items-baseline gap-2 py-0.5" style={{ fontFamily: 'monospace', fontSize: '11px' }}>
          <span style={{ color: '#ff6600', minWidth: '200px' }}>{f.field}</span>
          <span style={{ color: '#ff3333' }}>=</span>
          <span style={{ color: '#ffcc00', wordBreak: 'break-all' }}>{f.value}</span>
        </div>
      ))}
    </div>
  )
}

export default function CrackBanner({ finding, toolName, target }) {
  const [loading,     setLoading]     = useState(false)
  const [report,      setReport]      = useState(null)
  const [error,       setError]       = useState(null)
  const [openingPage, setOpeningPage] = useState(false)

  const titleMatch = finding.title.match(/:\s+([^:]+):(.+)$/)
  const username   = titleMatch?.[1]?.trim() || 'admin'
  const password   = titleMatch?.[2]?.trim() || ''

  const runExtraction = async () => {
    setLoading(true)
    setError(null)
    try {
      const res = await fetch('/api/post_exploit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target:         target || '',
          username,
          password,
          crack_method:   toolName,
          username_field: 'username',
          password_field: 'password',
        }),
      })
      const d = await res.json()
      if (d.success) setReport(d.data)
      else setError(d.error || 'Extraction failed')
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }

  const openCrackedPage = async () => {
    setOpeningPage(true)
    try {
      const res = await fetch('/api/auto_login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: target || '', username, password,
                               username_field: 'username', password_field: 'password' }),
      })
      const d = await res.json()
      if (d.success && d.data?.url) window.open(d.data.url, '_blank')
      else alert('Auto-login failed: ' + (d.error || 'unknown'))
    } catch (e) {
      alert('Error: ' + e.message)
    } finally {
      setOpeningPage(false)
    }
  }

  const r = report?.report || {}
  const stats = r.summary_stats || {}

  return (
    <div className="mb-4" style={{
      border: '2px solid #ff0000',
      background: 'rgba(255,0,0,0.04)',
      boxShadow: '0 0 20px rgba(255,0,0,0.2)',
    }}>
      {/* Header */}
      <div className="flex items-center gap-3 px-4 py-3"
           style={{ background: 'rgba(255,0,0,0.12)', borderBottom: '1px solid #3a0000' }}>
        <span className="text-2xl">⚡</span>
        <div className="flex-1">
          <div className="font-bold text-base tracking-widest animate-glitch"
               style={{ color: '#ff0000', textShadow: '0 0 10px #ff0000' }}>
            ██ LOGIN CRACKED ██
          </div>
          <div className="text-xs" style={{ color: '#ff4444' }}>via {toolName} · {target}</div>
        </div>
        <span className="text-xs border border-red-900 px-2 py-1" style={{ color: '#ff4444' }}>CRITICAL</span>
      </div>

      {/* Credentials */}
      <div className="px-4 py-3" style={{ borderBottom: '1px solid #1a0000' }}>
        <div className="grid grid-cols-2 gap-3 mb-3">
          {[['Username', username, '#ff6600'], ['Password', password, '#ff3333']].map(([label, val, col]) => (
            <div key={label} style={{ background: '#0a0000', border: `1px solid ${col}33`, padding: '10px 14px' }}>
              <div className="text-xs uppercase tracking-widest mb-1" style={{ color: `${col}66` }}>{label}</div>
              <div className="font-bold text-lg font-mono" style={{ color: col }}>{val}</div>
            </div>
          ))}
        </div>

        {/* Action buttons */}
        <div className="flex gap-2 flex-wrap">
          {!report && (
            <button onClick={runExtraction} disabled={loading || !target}
              className="border-2 font-mono font-bold text-sm px-5 py-2 transition-all"
              style={{ borderColor: '#ff0000', color: '#ff4444',
                       boxShadow: loading ? 'none' : '0 0 8px #ff000050' }}
            >
              {loading
                ? <span className="flex items-center gap-2"><span className="animate-spin">◌</span> EXTRACTING ALL DATA...</span>
                : '▶ EXTRACT ALL WEBSITE DATA'}
            </button>
          )}
          {report && (
            <button onClick={runExtraction} disabled={loading}
              className="border font-mono text-xs px-4 py-2 transition-all"
              style={{ borderColor: '#ff4444', color: '#ff6666' }}
            >↺ RE-EXTRACT</button>
          )}
          <button onClick={openCrackedPage} disabled={openingPage || !target}
            className="border-2 font-mono font-bold text-sm px-5 py-2 transition-all"
            style={{ borderColor: '#ff6600', color: '#ff9933',
                     boxShadow: '0 0 6px #ff660030' }}
          >
            {openingPage ? '◌' : '🌐'} OPEN IN BROWSER
          </button>
        </div>
        {error && <div className="text-xs mt-2" style={{ color: '#ff4444' }}>✗ {error}</div>}
      </div>

      {/* Extraction Report */}
      {report && (
        <div className="px-2 py-2">

          {/* Stats bar */}
          <div className="flex flex-wrap gap-2 mb-3 px-2">
            {[
              ['Users Extracted',    stats.users_extracted,      '#ff0000'],
              ['DB Rows Dumped',     stats.db_rows_dumped,       '#ff6600'],
              ['Sensitive APIs',     stats.sensitive_endpoints,  '#ffff00'],
              ['Config Files',       stats.configs_exposed,      '#ff6600'],
              ['Credential Files',   stats.credential_files,     '#ff0000'],
              ['Admin Panels',       stats.admin_panels,         '#ff3333'],
            ].map(([label, val, col]) => val > 0 && (
              <div key={label} style={{ background: `${col}15`, border: `1px solid ${col}40`,
                                        padding: '6px 12px', textAlign: 'center' }}>
                <div className="font-bold text-lg" style={{ color: col, textShadow: `0 0 8px ${col}` }}>{val}</div>
                <div className="text-xs uppercase" style={{ color: `${col}88`, letterSpacing: '1px' }}>{label}</div>
              </div>
            ))}
          </div>

          {/* Session cookies */}
          {r.session?.cookies && Object.keys(r.session.cookies).length > 0 && (
            <Section title={`Session Cookies (${Object.keys(r.session.cookies).length})`} color="#ff6600">
              {Object.entries(r.session.cookies).map(([k, v]) => (
                <div key={k} className="flex gap-2 py-0.5" style={{ fontFamily: 'monospace', fontSize: '11px' }}>
                  <span style={{ color: '#ff9933', minWidth: '200px' }}>{k}</span>
                  <span style={{ color: '#ffcc00', wordBreak: 'break-all' }}>{v}</span>
                </div>
              ))}
            </Section>
          )}

          {/* Extracted users */}
          {r.users_extracted?.length > 0 && (
            <Section title={`Users Extracted (${r.users_extracted.length})`} color="#ff0000">
              <DataTable
                rows={r.users_extracted}
                columns={r.users_extracted[0] ? Object.keys(r.users_extracted[0]) : []}
                color="#ff6666"
              />
            </Section>
          )}

          {/* Sensitive API endpoints */}
          {r.sensitive_data?.length > 0 && (
            <Section title={`Sensitive API Endpoints (${r.sensitive_data.length})`} color="#ffff00">
              {r.sensitive_data.map((ep, i) => (
                <div key={i} className="mb-3 pb-3" style={{ borderBottom: '1px solid #111' }}>
                  <div className="text-xs mb-1" style={{ color: '#ffcc00', fontFamily: 'monospace' }}>
                    GET {ep.url} → HTTP {ep.status}
                  </div>
                  <SensitiveFields fields={ep.sensitive_fields} />
                  {ep.raw_sample && (
                    <details className="mt-1">
                      <summary className="text-xs cursor-pointer" style={{ color: '#444' }}>Raw response</summary>
                      <pre style={{ fontSize: '9px', color: '#555', whiteSpace: 'pre-wrap',
                                    maxHeight: '150px', overflow: 'auto', background: '#050505',
                                    padding: '6px', marginTop: '4px' }}>
                        {ep.raw_sample}
                      </pre>
                    </details>
                  )}
                </div>
              ))}
            </Section>
          )}

          {/* HTML tables from admin panels */}
          {r.tables_found?.length > 0 && (
            <Section title={`Admin Panel Tables (${r.tables_found.length})`} color="#ff6600">
              {r.tables_found.map((t, i) => (
                <div key={i} className="mb-3">
                  <div className="text-xs mb-1" style={{ color: '#ff9933', fontFamily: 'monospace' }}>{t.url}</div>
                  <DataTable
                    rows={t.table.slice(1).map(row => Object.fromEntries(
                      (t.table[0] || []).map((h, j) => [h || `col${j}`, row[j] || ''])
                    ))}
                    columns={t.table[0]}
                    color="#ff9933"
                  />
                </div>
              ))}
            </Section>
          )}

          {/* Config files */}
          {r.configs_found?.length > 0 && (
            <Section title={`Config Files (${r.configs_found.length})`} color="#ff6600">
              {r.configs_found.map((cfg, i) => (
                <div key={i} className="mb-2">
                  <div className="text-xs mb-1" style={{ color: '#ff9933', fontFamily: 'monospace' }}>{cfg.url}</div>
                  <pre style={{ fontSize: '9px', color: '#cc8800', background: '#050505',
                                 padding: '6px', maxHeight: '150px', overflow: 'auto',
                                 whiteSpace: 'pre-wrap' }}>
                    {JSON.stringify(cfg.data, null, 2).slice(0, 2000)}
                  </pre>
                </div>
              ))}
            </Section>
          )}

          {/* Credential files (.env etc) */}
          {r.credentials_found?.length > 0 && (
            <Section title={`Credential Files (${r.credentials_found.length})`} color="#ff0000">
              {r.credentials_found.map((cred, i) => (
                <div key={i} className="mb-2">
                  <div className="text-xs mb-1" style={{ color: '#ff6666', fontFamily: 'monospace' }}>{cred.file}</div>
                  <div className="mb-1">
                    {cred.values?.map((v, j) => (
                      <div key={j} style={{ color: '#ffcc00', fontFamily: 'monospace', fontSize: '11px' }}>{v}</div>
                    ))}
                  </div>
                  <pre style={{ fontSize: '9px', color: '#884444', background: '#050505',
                                 padding: '6px', maxHeight: '120px', overflow: 'auto',
                                 whiteSpace: 'pre-wrap' }}>
                    {cred.raw?.slice(0, 1000)}
                  </pre>
                </div>
              ))}
            </Section>
          )}

          {/* Database dump */}
          {Object.entries(r.db_dump || {}).map(([dbType, res]) => res?.connected && (
            <Section key={dbType} title={`${dbType} Database Dump`} color="#ff0000">
              {Object.entries(res.databases || {}).map(([db, tables]) => (
                <div key={db} className="mb-4">
                  <div className="text-xs font-bold mb-2" style={{ color: '#ff6600', fontFamily: 'monospace' }}>
                    DATABASE: {db}
                  </div>
                  {Object.entries(tables).map(([tbl, tdata]) => (
                    <div key={tbl} className="mb-3 ml-2">
                      <div className="text-xs mb-1" style={{ color: '#ff9933', fontFamily: 'monospace' }}>
                        TABLE: {tbl} ({tdata.rows?.length || 0} rows)
                      </div>
                      <DataTable rows={tdata.rows} columns={tdata.columns} color="#ff6666" />
                    </div>
                  ))}
                </div>
              ))}
            </Section>
          ))}

          {/* Admin panels */}
          {r.admin_panels?.length > 0 && (
            <Section title={`Admin Panels Found (${r.admin_panels.length})`} color="#ff6600">
              {r.admin_panels.map((url, i) => (
                <div key={i} className="flex items-center gap-2 py-1">
                  <span style={{ color: '#ff6600', fontSize: '10px' }}>▶</span>
                  <a href={url} target="_blank" rel="noopener noreferrer"
                     className="text-xs hover:underline" style={{ color: '#ff9933', fontFamily: 'monospace' }}>
                    {url}
                  </a>
                </div>
              ))}
            </Section>
          )}

        </div>
      )}
    </div>
  )
}
