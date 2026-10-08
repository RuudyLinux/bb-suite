import { useState, useCallback } from 'react'
import Header from './components/Header'
import Sidebar from './components/Sidebar'
import Welcome from './components/Welcome'
import Dashboard from './components/Dashboard'
import ToolPanel from './components/ToolPanel'
import { TOOL_CONFIGS } from './config/tools'

export default function App() {
  const [activeTool,   setActiveTool]   = useState(null)   // null = show home/dashboard
  const [globalTarget, setGlobalTarget] = useState('')

  const selectTool = useCallback((name) => setActiveTool(name), [])
  const goHome     = useCallback(() => setActiveTool(null), [])

  const handleTargetChange = useCallback((val) => {
    setGlobalTarget(val)
    setActiveTool(null) // go to dashboard when target changes
  }, [])

  return (
    <div className="flex flex-col h-screen bg-cyber-bg text-slate-100 font-sans overflow-hidden select-none">
      <Header target={globalTarget} onTargetChange={handleTargetChange} onHome={goHome} />

      <div className="flex flex-1 overflow-hidden" style={{ marginTop: '56px' }}>
        <Sidebar activeTool={activeTool} onSelectTool={selectTool} onHome={goHome} />

        <main className="flex-1 overflow-y-auto relative bg-cyber-bg">
          <div className="fixed top-14 right-0 w-px h-full bg-gradient-to-b from-white/[0.08] to-transparent pointer-events-none" />

          {activeTool && TOOL_CONFIGS[activeTool] ? (
            // Individual tool view
            <div className="p-6 md:p-8 max-w-5xl mx-auto">
              <ToolPanel
                key={activeTool}
                toolName={activeTool}
                config={TOOL_CONFIGS[activeTool]}
                globalTarget={globalTarget}
              />
            </div>
          ) : globalTarget ? (
            // Dashboard — target is set, show "perform all" home
            <Dashboard
              key={globalTarget}
              target={globalTarget}
              onSelectTool={selectTool}
            />
          ) : (
            // No target — welcome screen
            <Welcome onSelectTool={selectTool} />
          )}
        </main>
      </div>
    </div>
  )
}
