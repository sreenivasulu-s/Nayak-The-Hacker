import { useEffect, useState } from 'react'
import './App.css'

const API_BASE = (import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000').replace(/\/$/, '')
const STORAGE_KEY = 'nayak-npt-scan-id'
const TOOL_LIST = ['nmap', 'gobuster', 'nikto', 'nuclei']

async function apiFetch(url, options = {}) { return fetch(url, options) }

function App() {
  const [target, setTarget] = useState('')
  const [scope, setScope] = useState('')
  const [tools, setTools] = useState([...TOOL_LIST])
  const [authorized, setAuthorized] = useState(false)
  const [scan, setScan] = useState(null)
  const [findings, setFindings] = useState([])
  const [severity, setSeverity] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [history, setHistory] = useState([])

  async function loadHistory() {
    try {
      const response = await apiFetch(`${API_BASE}/scans`)
      if (!response.ok) throw new Error('Failed to load scan history')
      setHistory(await response.json())
    } catch (err) { setError(err.message || 'Failed to load scan history') }
  }

  async function loadScan(scanId) {
    const response = await apiFetch(`${API_BASE}/scan/${scanId}`)
    if (!response.ok) throw new Error('Failed to load scan')
    const data = await response.json()
    setScan(data)
    setFindings(data.findings || [])
    return data
  }

  useEffect(() => {
    loadHistory()
    const saved = localStorage.getItem(STORAGE_KEY)
    if (!saved) return
    let cancelled = false
    let timer
    async function poll() {
      try {
        const data = await loadScan(saved)
        if (cancelled) return
        if (data.status === 'queued' || data.status === 'running') timer = setTimeout(poll, 1000)
        else loadHistory()
      } catch (err) { if (!cancelled) setError(err.message || 'Failed to restore scan') }
    }
    poll()
    return () => { cancelled = true; clearTimeout(timer) }
  }, [])

  function toggleTool(tool) {
    setTools((current) => current.includes(tool) ? current.filter((item) => item !== tool) : [...current, tool])
  }

  async function startScan(event) {
    event.preventDefault()
    setLoading(true)
    setError('')
    setScan(null)
    setFindings([])
    try {
      const response = await apiFetch(`${API_BASE}/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: target.trim(), scope: scope.trim(), tools, authorized }),
      })
      const data = await response.json().catch(() => ({}))
      if (!response.ok) throw new Error(data.detail?.[0]?.msg || data.detail || 'Scan request failed')
      localStorage.setItem(STORAGE_KEY, data.scan_id)
      setScan(data)
      let current = data
      while (current.status === 'queued' || current.status === 'running') {
        await new Promise((resolve) => setTimeout(resolve, 1000))
        current = await loadScan(data.scan_id)
      }
      await loadHistory()
    } catch (err) { setError(err.message || 'Scan failed') }
    finally { setLoading(false) }
  }

  async function filterFindings(value) {
    setSeverity(value)
    if (!scan) return
    const endpoint = value ? `${API_BASE}/scan/${scan.scan_id}/findings?severity=${encodeURIComponent(value)}` : `${API_BASE}/scan/${scan.scan_id}/findings`
    const response = await apiFetch(endpoint)
    if (response.ok) setFindings((await response.json()).findings || [])
  }

  const counts = findings.reduce((out, item) => { const level = item.severity || 'info'; out[level] = (out[level] || 0) + 1; return out }, { critical: 0, high: 0, medium: 0, low: 0, info: 0 })
  const total = Object.values(counts).reduce((a, b) => a + b, 0)
  const highRisk = counts.critical + counts.high

  return (
    <main className="app">
      <header className="header">
        <div><p className="eyebrow">Nayak Enterprise Penetration Testing Platform</p><h1>NPT v7.0</h1><p className="subtitle">Authorized target → scope verification → real tools → evidence → findings → dashboard.</p></div>
        <span className="status-badge">Real Execution</span>
      </header>

      <section className="dashboard-grid">
        <article className="metric-card"><span className="metric-label">Total Scans</span><strong>{history.length}</strong><small>Saved in database</small></article>
        <article className="metric-card"><span className="metric-label">Findings</span><strong>{total}</strong><small>Current scan</small></article>
        <article className="metric-card risk"><span className="metric-label">High Risk</span><strong>{highRisk}</strong><small>{counts.critical} critical · {counts.high} high</small></article>
        <article className="metric-card"><span className="metric-label">Scan Status</span><strong>{scan?.status || 'Ready'}</strong><small>Live execution state</small></article>
      </section>

      <section className="card">
        <h2>Target & Authorization</h2>
        <form onSubmit={startScan} className="scan-form">
          <input value={target} onChange={(e) => setTarget(e.target.value)} placeholder="Target IP, domain, or URL" required />
          <input value={scope} onChange={(e) => setScope(e.target.value)} placeholder="Authorized scope (same host/domain)" required />
          <div className="tool-picker"><strong>Tools</strong>{TOOL_LIST.map((tool) => <label key={tool}><input type="checkbox" checked={tools.includes(tool)} onChange={() => toggleTool(tool)} /> {tool}</label>)}</div>
          <label className="authorization"><input type="checkbox" checked={authorized} onChange={(e) => setAuthorized(e.target.checked)} /> I confirm I have authorization to test this target and the target is within the stated scope.</label>
          <button type="submit" disabled={loading || !authorized || tools.length === 0}>{loading ? 'Running...' : 'Start Authorized Scan'}</button>
        </form>
        {error && <p className="error">{error}</p>}
      </section>

      <section className="severity-overview">
        <div className="severity-overview-header"><div><h2>Security Overview</h2><p>Parsed findings from real tool output.</p></div></div>
        <div className="severity-grid">{['critical', 'high', 'medium', 'low', 'info'].map((level) => <button type="button" className={`severity-summary ${level}`} key={level} onClick={() => filterFindings(level)} disabled={!scan}><span>{level}</span><strong>{counts[level]}</strong></button>)}</div>
      </section>

      <section className="card">
        <div className="section-header"><div><h2>Scan History</h2><p className="target">Authorized scans and selected tools.</p></div><button type="button" className="history-refresh" onClick={loadHistory}>Refresh</button></div>
        {history.length === 0 ? <p className="empty">No scans yet.</p> : <div className="history-list">{history.map((item) => <button type="button" className={`history-item ${scan?.scan_id === item.scan_id ? 'selected' : ''}`} key={item.scan_id} onClick={() => loadScan(item.scan_id)}><span className="history-target">{item.target}<small className="history-type">{(item.tools || []).join(', ')}</small></span><span className="history-details"><span className={`scan-status ${item.status}`}>{item.status}</span><span className="history-count">{item.findings_count} findings</span></span></button>)}</div>}
      </section>

      {scan && <section className="card">
        <div className="section-header"><div><h2>Evidence & Findings</h2><p className="target">{scan.target} · Scope: {scan.scope}</p></div><span className={`scan-status ${scan.status}`}>{scan.status}</span></div>
        <div className="scan-meta"><div><strong>Scan ID</strong><span>{scan.scan_id}</span></div><div><strong>Authorization</strong><span>{scan.authorized ? 'Verified' : 'Rejected'}</span></div><div><strong>Tools</strong><span>{(scan.tools || []).join(', ')}</span></div></div>
        {scan.error && <p className="error">{scan.error}</p>}
        <div className="findings-header"><h2>Findings</h2><button type="button" className="history-refresh" onClick={() => window.open(`${API_BASE}/scan/${scan.scan_id}/report`, '_blank')} disabled={scan.status !== 'completed'}>Download Report</button><select value={severity} onChange={(e) => filterFindings(e.target.value)}><option value="">All severities</option><option value="info">Info</option><option value="low">Low</option><option value="medium">Medium</option><option value="high">High</option><option value="critical">Critical</option></select></div>
        {findings.length === 0 ? <p className="empty">No parsed findings returned yet.</p> : <div className="findings">{findings.map((finding, index) => <article className="finding" key={`${finding.title}-${index}`}><div className="finding-header"><h3>{finding.title}</h3><span className={`severity ${finding.severity}`}>{finding.severity}</span></div><p>{finding.description}</p><p><strong>Evidence:</strong> {finding.evidence}</p><p><strong>Tool:</strong> {finding.tool}</p></article>)}</div>}
      </section>}
    </main>
  )
}

export default App
