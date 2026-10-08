import { useState, useCallback, useRef } from 'react'
import { runTool as apiRun } from '../lib/api'
import { TOOL_CONFIGS } from '../config/tools'

// Tools that require specific user input (tokens, hashes) — skip during automated target crawl
const MANUAL_ONLY = new Set(['jwt_analyzer', 'password_cracker'])

// Main tool list (screenshots + ai_analysis included — handled specially)
const ALL_TOOLS = Object.keys(TOOL_CONFIGS).filter(t => !MANUAL_ONLY.has(t) && t !== 'ai_analysis')

const ORDER = { critical: 0, high: 1, medium: 2, low: 3, pass: 4, info: 5 }

function buildData(toolName, target, overrides = {}) {
  const cfg  = TOOL_CONFIGS[toolName]
  if (!cfg) return overrides
  const url    = /^https?:\/\//i.test(target) ? target : `https://${target}`
  const domain = url.replace(/^https?:\/\//, '').split('/')[0]
  const host   = domain.split(':')[0]
  const data   = {}
  for (const field of cfg.fields) {
    if      (field.autofill === 'domain') data[field.name] = domain
    else if (field.autofill === 'url')    data[field.name] = url
    else if (field.autofill === 'host')   data[field.name] = host
    else if (field.defaultValue != null)  data[field.name] = field.defaultValue
    else if (field.type === 'select')     data[field.name] = field.options?.find(o => o.default)?.v || field.options?.[0]?.v || ''
    else                                  data[field.name] = ''
  }
  return { ...data, ...overrides }
}

export function useRunAll() {
  const [statuses, setStatuses] = useState({})
  const [results,  setResults]  = useState({})
  const [running,  setRunning]  = useState(false)
  const aborted    = useRef(false)
  const resultsRef = useRef({})  // mirror of results for access inside async callbacks

  const setSt = (tool, s) => setStatuses(p => ({ ...p, [tool]: s }))
  const setRe = (tool, r) => {
    resultsRef.current = { ...resultsRef.current, [tool]: r }
    setResults(p => ({ ...p, [tool]: r }))
  }

  const runAll = useCallback(async (target) => {
    aborted.current  = false
    resultsRef.current = {}
    setRunning(true)

    // Init statuses for all tools (including ai_analysis + screenshots)
    const allToolsWithSpecial = [...ALL_TOOLS, 'screenshots', 'ai_analysis']
    setStatuses(Object.fromEntries(allToolsWithSpecial.map(t => [t, 'pending'])))
    setResults({})

    const runOne = async (toolName) => {
      if (aborted.current) return
      setSt(toolName, 'running')
      try {
        const res = await apiRun(toolName, buildData(toolName, target))
        setSt(toolName, 'done')
        setRe(toolName, res)
      } catch (e) {
        setSt(toolName, 'error')
        setRe(toolName, { success: false, error: e.message, data: { findings: [] } })
      }
    }

    // 1. Run main tools in batches of 5
    const BATCH = 5
    for (let i = 0; i < ALL_TOOLS.length; i += BATCH) {
      if (aborted.current) break
      await Promise.all(ALL_TOOLS.slice(i, i + BATCH).map(runOne))
    }

    // 2. Run screenshots (just needs URL — works automatically)
    if (!aborted.current) {
      await runOne('screenshots')
    }

    // 3. Run AI Analysis LAST — collect all findings from completed tools
    if (!aborted.current) {
      const collected = []
      for (const [tool, res] of Object.entries(resultsRef.current)) {
        if (res?.success && res?.data?.findings) {
          for (const fnd of res.data.findings) {
            if (fnd.severity !== 'pass') {
              collected.push({ ...fnd, _tool: tool })
            }
          }
        }
      }

      if (collected.length > 0) {
        setSt('ai_analysis', 'running')
        try {
          const res = await apiRun('ai_analysis', buildData('ai_analysis', target, {
            findings: collected,
            api_key: '',   // backend loads from key.env
          }))
          setSt('ai_analysis', 'done')
          setRe('ai_analysis', res)
        } catch (e) {
          setSt('ai_analysis', 'error')
          setRe('ai_analysis', { success: false, error: e.message, data: { findings: [] } })
        }
      } else {
        setSt('ai_analysis', 'stopped')
        setRe('ai_analysis', { success: false, error: 'No findings to analyze', data: {} })
      }
    }

    setRunning(false)
  }, [])

  const stop = useCallback(() => {
    aborted.current = true
    setRunning(false)
    setStatuses(p =>
      Object.fromEntries(Object.entries(p).map(([k, v]) =>
        [k, v === 'pending' || v === 'running' ? 'stopped' : v]))
    )
  }, [])

  const reset = useCallback(() => {
    aborted.current  = true
    resultsRef.current = {}
    setRunning(false)
    setStatuses({})
    setResults({})
  }, [])

  // Progress — count ALL tools including special ones
  const allToolsTotal = ALL_TOOLS.length + 2  // +screenshots +ai_analysis
  const completed = Object.values(statuses).filter(s => ['done','error','stopped'].includes(s)).length
  const progress = {
    total:   allToolsTotal,
    done:    Object.values(statuses).filter(s => s === 'done').length,
    failed:  Object.values(statuses).filter(s => s === 'error').length,
    running: Object.values(statuses).filter(s => s === 'running').length,
    pct:     allToolsTotal ? Math.round((completed / allToolsTotal) * 100) : 0,
  }

  // Aggregate non-pass findings from all tools
  const allFindings = []
  for (const [tool, res] of Object.entries(results)) {
    if (res?.success && res?.data?.findings) {
      for (const fnd of res.data.findings) {
        if (fnd.severity !== 'pass') {
          allFindings.push({ ...fnd, _tool: tool })
        }
      }
    }
  }
  allFindings.sort((a, b) => (ORDER[a.severity] ?? 9) - (ORDER[b.severity] ?? 9))

  const sevCounts = allFindings.reduce((acc, f) => {
    acc[f.severity] = (acc[f.severity] || 0) + 1
    return acc
  }, {})

  return { statuses, results, running, progress, allFindings, sevCounts, runAll, stop, reset,
           manualOnly: MANUAL_ONLY }
}
