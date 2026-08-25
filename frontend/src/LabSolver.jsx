import { useEffect, useState } from 'react'

const API_BASE = (import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000').replace(/\/$/, '')

export default function LabSolver() {
  const [url, setUrl] = useState('')
  const [job, setJob] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  async function start(event) {
    event.preventDefault()
    setLoading(true); setError(''); setJob(null)
    try {
      const response = await fetch(`${API_BASE}/lab`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url, authorized: true, user_confirmation: true }),
      })
      const data = await response.json().catch(() => ({}))
      if (!response.ok) throw new Error(data.detail || 'Lab request failed')
      setJob(data)
    } catch (err) { setError(err.message || 'Lab request failed') }
    finally { setLoading(false) }
  }

  return <section className="card">
    <div className="section-header"><div><h2>PortSwigger Lab Solver</h2><p className="target">Paste an authorized Web Security Academy lab URL.</p></div><span className="status-badge">LAB MODE</span></div>
    <form className="scan-form" onSubmit={start}>
      <input value={url} onChange={e => setUrl(e.target.value)} placeholder="https://....web-security-academy.net" required />
      <button type="submit" disabled={loading || !url}>{loading ? 'Starting lab...' : 'Start Lab Solver'}</button>
    </form>
    {error && <p className="error">{error}</p>}
    {job && <div className="scan-meta">
      <div><strong>Job</strong><span>{job.job_id}</span></div>
      <div><strong>State</strong><span>{job.state}</span></div>
      <div><strong>Host</strong><span>{job.lab_host}</span></div>
      <div><strong>Report</strong><a href={`${API_BASE}/lab/${job.job_id}/report`} target="_blank" rel="noreferrer">JSON evidence report</a></div>
    </div>}
  </section>
}
