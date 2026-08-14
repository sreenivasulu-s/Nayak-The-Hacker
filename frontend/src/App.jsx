import { useEffect, useState } from 'react'
import './App.css'

const API_BASE = (import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000').replace(/\/$/, '')
const STORAGE_KEY = 'vapt-scan-id'

async function api(url, options = {}) {
  const response = await fetch(url, options)
  const data = await response.json().catch(() => ({}))
  if (!response.ok) throw new Error(data.detail?.[0]?.msg || data.detail || 'Request failed')
  return data
}

function App() {
  const [url, setUrl] = useState('')
  const [targetType, setTargetType] = useState('web')
  const [authorized, setAuthorized] = useState(false)
  const [activeApproved, setActiveApproved] = useState(false)
  const [scan, setScan] = useState(null)
  const [findings, setFindings] = useState([])
  const [history, setHistory] = useState([])
  const [severity, setSeverity] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  async function loadHistory() {
    try { setHistory(await api(`${API_BASE}/scans`)) } catch (err) { setError(err.message) }
  }

  async function loadScan(id) {
    const data = await api(`${API_BASE}/scan/${id}`)
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
    const poll = async () => {
      try {
        const data = await loadScan(saved)
        if (!cancelled && (data.status === 'queued' || data.status === 'running')) timer = setTimeout(poll, 1200)
      } catch (err) { if (!cancelled) setError(err.message) }
    }
    poll()
    return () => { cancelled = true; clearTimeout(timer) }
  }, [])

  async function startScan(event) {
    event.preventDefault()
    setLoading(true); setError(''); setScan(null); setFindings([])
    try {
      const data = await api(`${API_BASE}/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: url.trim(), target_type: targetType, authorized, active_approved: activeApproved }),
      })
      localStorage.setItem(STORAGE_KEY, data.scan_id)
      setScan(data)
      let current = data
      while (current.status === 'queued' || current.status === 'running') {
        await new Promise((resolve) => setTimeout(resolve, 1200))
        current = await loadScan(data.scan_id)
      }
      await loadHistory()
    } catch (err) { setError(err.message) }
    finally { setLoading(false) }
  }

  async function filterFindings(value) {
    setSeverity(value)
    if (!scan) return
    try {
      const query = value ? `?severity=${encodeURIComponent(value)}` : ''
      const data = await api(`${API_BASE}/scan/${scan.scan_id}/findings${query}`)
      setFindings(data.findings || [])
    } catch (err) { setError(err.message) }
  }

  const counts = findings.reduce((acc, item) => { acc[item.severity || 'info'] = (acc[item.severity || 'info'] || 0) + 1; return acc }, { critical: 0, high: 0, medium: 0, low: 0, info: 0 })
  const risk = counts.critical + counts.high

  return (
    <main className="app">
      <header className="header">
        <div><p className="eyebrow">Nayak The Hacker</p><h1>VAPT Automation Console</h1><p className="subtitle">Kali tools + MCP + AI correlation for authorized assessments.</p></div>
        <span className="status-badge">API Connected</span>
      </header>

      <section className="dashboard-grid">
        <article className="metric-card"><span className="metric-label">Total Scans</span><strong>{history.length}</strong><small>Saved scans</small></article>
        <article className="metric-card"><span className="metric-label">Findings</span><strong>{findings.length}</strong><small>Current scan</small></article>
        <article className="metric-card risk"><span className="metric-label">High Risk</span><strong>{risk}</strong><small>{counts.critical} critical · {counts.high} high</small></article>
        <article className="metric-card"><span className="metric-label">Status</span><strong>{scan?.status || 'Ready'}</strong><small>MCP/Kali pipeline</small></article>
      </section>

      <section className="card">
        <h2>Start Authorized VAPT</h2>
        <form onSubmit={startScan} className="scan-form">
          <select value={targetType} onChange={(e) => setTargetType(e.target.value)} aria-label="Target type">
            <option value="web">Web Application</option><option value="api">API</option><option value="network">Network</option>
          </select>
          <input type="url" value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://authorized-target.example" required />
          <button type="submit" disabled={loading || !authorized}>{loading ? 'Scanning...' : 'Start Scan'}</button>
        </form>
        <label className="approval-row"><input type="checkbox" checked={authorized} onChange={(e) => setAuthorized(e.target.checked)} /> I confirm I am authorized to assess this target and its related assets.</label>
        <label className="approval-row"><input type="checkbox" checked={activeApproved} onChange={(e) => setActiveApproved(e.target.checked)} disabled={!authorized} /> Enable active discovery checks (ffuf/Gobuster/Nuclei/Nikto) for this authorized scope.</label>
        {error && <p className="error">{error}</p>}
      </section>

      <section className="severity-overview">
        <div className="severity-overview-header"><div><h2>Security Overview</h2><p>Current finding distribution.</p></div></div>
        <div className="severity-grid">{['critical', 'high', 'medium', 'low', 'info'].map((level) => <button type="button" className={`severity-summary ${level}`} key={level} onClick={() => filterFindings(level)} disabled={!scan}><span>{level}</span><strong>{counts[level]}</strong></button>)}</div>
      </section>

      <section className="card">
        <div className="section-header"><div><h2>Scan History</h2><p className="target">Previous assessments.</p></div><button type="button" className="history-refresh" onClick={loadHistory}>Refresh</button></div>
        {history.length === 0 ? <p className="empty">No scans yet.</p> : <div className="history-list">{history.map((item) => <button type="button" className={`history-item ${scan?.scan_id === item.scan_id ? 'selected' : ''}`} key={item.scan_id} onClick={() => loadScan(item.scan_id)}><span className="history-target">{item.target}<small className="history-type">{item.target_type}</small></span><span className="history-details"><span className={`scan-status ${item.status}`}>{item.status}</span><span className="history-count">{item.findings_count} findings</span></span></button>)}</div>}
      </section>

      {scan && <section className="card">
        <div className="section-header"><div><h2>Findings</h2><p className="target">{scan.target}</p></div><span className={`scan-status ${scan.status}`}>{scan.status}</span></div>
        <div className="findings-header"><h2>Results</h2><select value={severity} onChange={(e) => filterFindings(e.target.value)}><option value="">All severities</option><option value="info">Info</option><option value="low">Low</option><option value="medium">Medium</option><option value="high">High</option><option value="critical">Critical</option></select><button type="button" className="history-refresh" onClick={() => window.open(`${API_BASE}/scan/${scan.scan_id}/report`, '_blank')}>JSON Report</button></div>
        {findings.length === 0 ? <p className="empty">No findings returned.</p> : <div className="findings">{findings.map((finding, index) => <article className="finding" key={`${finding.title}-${index}`}><div className="finding-header"><h3>{finding.title}</h3><span className={`severity ${finding.severity}`}>{finding.severity}</span></div><p>{finding.description}</p><p><strong>Evidence:</strong> {finding.evidence}</p><p><strong>Tool:</strong> {finding.tool}</p></article>)}</div>}
        {scan.ai_analysis && <article className="finding"><div className="finding-header"><h3>ChatGPT Analysis</h3><span className="severity info">{scan.ai_analysis.provider}</span></div><p>{scan.ai_analysis.summary}</p></article>}
      </section>}
    </main>
  )
}

export default App
