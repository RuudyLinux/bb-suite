const BASE = '/api'

function coerce(data) {
  const out = {}
  for (const [k, v] of Object.entries(data)) {
    if (v === 'true')  out[k] = true
    else if (v === 'false') out[k] = false
    else if (k === 'findings') {
      // Parse JSON findings if user pasted them
      try { out[k] = typeof v === 'string' ? JSON.parse(v) : v }
      catch { out[k] = [] }
    }
    else out[k] = v
  }
  return out
}

export async function runTool(toolName, formData) {
  const res = await fetch(`${BASE}/${toolName}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(coerce(formData)),
  })
  if (!res.ok) {
    const text = await res.text()
    throw new Error(`HTTP ${res.status}: ${text}`)
  }
  return res.json()
}

export async function zapStatus(zapHost = 'http://localhost:8080') {
  const res = await fetch(`${BASE}/zap`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action: 'status', zap_host: zapHost, target: '' }),
  })
  return res.json()
}
