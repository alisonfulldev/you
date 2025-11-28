import React, { useEffect, useMemo, useState } from 'react'
import { createRoot } from 'react-dom/client'

async function fetchJSON(url, opts) {
  const res = await fetch(url, opts)
  if (!res.ok) throw new Error(await res.text())
  return res.json()
}

function formatWorkload(mins) {
  if (!mins) return 'Carga não informada'
  const h = Math.floor(mins / 60), m = mins % 60
  return `${h}h ${m}min`
}

function Card({ course, enrolled, onEnroll }) {
  const isFree = (course.priceCents || 0) === 0
  const actionLabel = isFree ? (enrolled ? 'Continuar curso' : 'Matricular grátis') : 'Acessar curso'
  const onAction = () => {
    if (isFree) return onEnroll(course)
    window.location.href = `/course/${course.id}`
  }
  return (
    <div className="card" style={{ transform: 'translateZ(0)', transition: '.2s', willChange: 'transform' }}
      onMouseEnter={(e) => e.currentTarget.style.transform = 'translateY(-2px)'}
      onMouseLeave={(e) => e.currentTarget.style.transform = 'translateY(0)'}>
      <div className="thumb"><div className="thumb-img" /></div>
      <div className="card-body">
        <div className="row center" style={{ gap: 10 }}>
          <div style={{ width: 36, height: 36, borderRadius: 999, background: '#ddd' }} />
          <div>
            <h3 className="card-title" style={{ margin: 0 }}>{course.title}</h3>
            <div className="muted" style={{ fontSize: 12 }}>{course.slug} • {isFree ? 'Gratuito' : 'Pago'} • {formatWorkload(course.workloadMinutes)}</div>
          </div>
        </div>
        <div className="card-actions" style={{ marginTop: 10 }}>
          <button className="btn primary" onClick={onAction}>{actionLabel}</button>
          <a className="btn ghost" href={`/c/${course.slug}`}>Link público</a>
          {enrolled ? <span className="badge success">Inscrito</span> : null}
        </div>
      </div>
    </div>
  )
}

function Feed() {
  const [q, setQ] = useState(new URLSearchParams(window.location.search).get('q') || '')
  const [courses, setCourses] = useState([])
  const [enrolledIds, setEnrolledIds] = useState([])
  const [loading, setLoading] = useState(true)
  const [student, setStudent] = useState(null)

  const load = async () => {
    setLoading(true)
    try {
      const [list, me, enrolls] = await Promise.all([
        fetchJSON(`/api/courses${q ? `?q=${encodeURIComponent(q)}` : ''}`),
        fetchJSON('/api/me').catch(() => null),
        fetchJSON('/api/me/enrollments').catch(() => ({ courseIds: [] })),
      ])
      setCourses(list)
      setStudent(me)
      setEnrolledIds(enrolls.courseIds || [])
    } catch (e) {
      console.error(e)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [q])

  useEffect(() => {
    const onPop = () => setQ(new URLSearchParams(window.location.search).get('q') || '')
    window.addEventListener('popstate', onPop)
    return () => window.removeEventListener('popstate', onPop)
  }, [])

  useEffect(() => {
    const form = document.querySelector('.yt-search')
    if (!form) return
    form.addEventListener('submit', (ev) => {
      ev.preventDefault()
      const input = form.querySelector('input[name="q"]')
      const nq = input ? input.value : ''
      const url = new URL(window.location.href)
      if (nq) url.searchParams.set('q', nq); else url.searchParams.delete('q')
      window.history.pushState({}, '', url.toString())
      setQ(nq)
    })
  }, [])

  const onEnroll = async (course) => {
    if (!student) {
      window.location.href = `/student/login?next=${encodeURIComponent(`/course/${course.id}/enroll`)}`
      return
    }
    try {
      await fetchJSON(`/api/course/${course.id}/enroll`, { method: 'POST', headers: { 'Content-Type': 'application/json' } })
      window.location.href = `/course/${course.id}`
    } catch (e) {
      alert('Não foi possível matricular: ' + e.message)
    }
  }

  if (loading) {
    const skeletons = Array.from({ length: 6 }).map((_, i) => (
      <div key={i} className="card">
        <div className="thumb"><div className="thumb-img" style={{ background: 'linear-gradient(90deg,#eee,#f5f5f5,#eee)', animation: 'shimmer 1.4s infinite' }} /></div>
        <div className="card-body">
          <div className="row center" style={{ gap: 10 }}>
            <div style={{ width: 36, height: 36, borderRadius: 999, background: '#eee' }} />
            <div>
              <div style={{ width: 220, height: 16, background: '#eee', borderRadius: 6, marginBottom: 6 }} />
              <div style={{ width: 160, height: 12, background: '#f0f0f0', borderRadius: 6 }} />
            </div>
          </div>
        </div>
      </div>
    ))
    return <section className="grid">{skeletons}</section>
  }

  if (courses.length === 0) {
    return <p className="muted" style={{ margin: '16px 0' }}>Nenhum curso encontrado para "{q}".</p>
  }

  return (
    <section className="grid">
      {courses.map((c) => (
        <Card key={c.id} course={c} enrolled={enrolledIds.includes(c.id)} onEnroll={onEnroll} />
      ))}
    </section>
  )
}

export function mount(selector = '#react-root') {
  const el = document.querySelector(selector)
  if (!el) return
  const root = createRoot(el)
  root.render(<Feed />)
}

const style = document.createElement('style')
style.innerHTML = `@keyframes shimmer {0%{background-position:-200px 0}100%{background-position:200px 0}}`
document.head.appendChild(style)

// -------- Watch Page (Course) ---------
function getCookie(name) {
  return document.cookie.split(';').map(s => s.trim()).find(s => s.startsWith(name + '='))?.split('=')[1] || ''
}

function WatchApp({ courseId }) {
  const [meta, setMeta] = useState(null)
  const [items, setItems] = useState([])
  const [current, setCurrent] = useState(0)
  const [summary, setSummary] = useState({ total: 0, completed: 0 })
  const [loading, setLoading] = useState(true)
  const STORAGE_KEY = `certipay:course:${courseId}:completed`
  const loadProgress = () => { try { return JSON.parse(localStorage.getItem(STORAGE_KEY) || '{}') } catch { return {} } }
  const saveProgress = (map) => { try { localStorage.setItem(STORAGE_KEY, JSON.stringify(map)) } catch {} }

  const load = async () => {
    setLoading(true)
    try {
      const [m, pl] = await Promise.all([
        fetchJSON(`/api/course/${courseId}`),
        fetchJSON(`/api/course/${courseId}/playlist`)
      ])
      setMeta(m)
      const arr = (pl.items || []).sort((a, b) => (a.position || 0) - (b.position || 0))
      setItems(arr)
      await updateSummary()
    } catch (e) {
      console.error(e)
    } finally {
      setLoading(false)
    }
  }

  const updateSummary = async () => {
    try {
      const map = loadProgress()
      const total = items.length || 0
      const completed = items.filter(it => !!map[it.videoId]).length
      setSummary({ total, completed })
      const certBtn = document.getElementById('certBtn')
      if (certBtn) {
        const can = total > 0 && completed >= total
        if (can) { certBtn.classList.add('gradient') } else { certBtn.classList.remove('gradient') }
      }
    } catch (e) { console.error(e) }
  }

  const markCompleted = async () => {
    try {
      const vid = items[current]?.videoId
      if (!vid) return
      const m = loadProgress(); m[vid] = true; saveProgress(m)
      await updateSummary()
    } catch (e) { console.error(e) }
  }

  useEffect(() => { load() }, [])

  if (loading) return <p className="muted">Carregando curso…</p>
  if (!meta) return <p className="muted">Curso não encontrado.</p>

  const vid = items[current]?.videoId
  return (
    <div className="card">
      <h3>Aulas</h3>
      <div className="watch-row" style={{ gap: 16 }}>
        <div style={{ flex: 3 }}>
          <div style={{ width: '100%', aspectRatio: '16 / 9', background: '#000', borderRadius: 8, overflow: 'hidden' }}>
            {vid ? (
              <iframe title={meta.title} width="100%" height="100%" style={{ border: 0 }}
                src={`https://www.youtube.com/embed/${vid}?rel=0&controls=1&modestbranding=1`}></iframe>
            ) : (
              <div className="row center" style={{ color: '#999', height: '100%', alignItems: 'center', justifyContent: 'center' }}>
                Nenhuma aula disponível
              </div>
            )}
          </div>
          <div className="row" style={{ marginTop: 8, gap: 8 }}>
            <button className="btn" onClick={() => setCurrent(c => Math.max(0, c - 1))} disabled={current === 0}>Anterior</button>
            <button className="btn" onClick={() => setCurrent(c => Math.min(items.length - 1, c + 1))} disabled={current >= items.length - 1}>Próxima</button>
            <button className="btn primary" onClick={markCompleted} disabled={!vid}>Marcar concluída</button>
            <span className="muted" style={{ marginLeft: 'auto' }}>Progresso: {summary.completed} de {summary.total}</span>
          </div>
        </div>
        <div style={{ flex: 2 }}>
          <ul style={{ listStyle: 'none', padding: 0, margin: 0 }}>
            {items.map((it, i) => (
              <li key={it.videoId} className="card" style={{ padding: 8, marginBottom: 8, cursor: 'pointer', border: i === current ? '1px solid var(--accent)' : '1px solid var(--border)' }} onClick={() => setCurrent(i)}>
                <div className="row between center" style={{ gap: 8 }}>
                  <span className="btn ghost" style={{ cursor: 'pointer' }}>Aula {i + 1}</span>
                  <label className="option" style={{ margin: 0 }} onClick={(e) => e.stopPropagation()}>
                    <input type="checkbox"
                      checked={!!loadProgress()[it.videoId]}
                      onClick={(e) => e.stopPropagation()}
                      onChange={(e) => {
                        const m = loadProgress(); m[it.videoId] = e.target.checked; saveProgress(m); updateSummary()
                      }}
                    />
                    <span>Concluída</span>
                  </label>
                </div>
              </li>
            ))}
          </ul>
        </div>
      </div>
    </div>
  )
}

export function mountWatch(opts) {
  const el = document.querySelector('#react-watch')
  if (!el) return
  const root = createRoot(el)
  const { courseId } = opts || {}
  root.render(<WatchApp courseId={courseId} />)
}
