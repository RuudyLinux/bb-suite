import { useState, useCallback } from 'react'
import { runTool } from '../lib/api'

export function useToolRunner(toolName) {
  const [loading, setLoading]   = useState(false)
  const [result,  setResult]    = useState(null)
  const [error,   setError]     = useState(null)
  const [elapsed, setElapsed]   = useState(null)

  const run = useCallback(async (data) => {
    setLoading(true)
    setError(null)
    setResult(null)
    setElapsed(null)
    const t0 = Date.now()
    try {
      const res = await runTool(toolName, data)
      setResult(res)
      setElapsed(((Date.now() - t0) / 1000).toFixed(2))
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }, [toolName])

  const reset = useCallback(() => {
    setResult(null)
    setError(null)
    setElapsed(null)
  }, [])

  return { run, loading, result, error, elapsed, reset }
}
