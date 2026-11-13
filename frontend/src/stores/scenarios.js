import { defineStore } from 'pinia'
import { computed, ref } from 'vue'
import { api } from '../api'
import { levelByScore } from '../levels'

// Сценарії ризику, їхні заходи захисту, історія оцінювань і дерева атак
export const useScenarioStore = defineStore('scenarios', () => {
  const scenarios = ref([])
  const loading = ref(false)
  const error = ref('')
  const method = ref('combined') // метод, за яким будуються дашборди

  async function fetchScenarios() {
    loading.value = true
    error.value = ''
    try {
      scenarios.value = await api.get('/scenarios')
    } catch (e) {
      error.value = 'Не вдалося завантажити сценарії. Перевірте, чи запущено сервер.'
    } finally {
      loading.value = false
    }
  }

  const replace = (s) => {
    const i = scenarios.value.findIndex((x) => x.id === s.id)
    if (i >= 0) scenarios.value[i] = s
    else scenarios.value.push(s)
    return s
  }

  const refresh = async (id) => replace(await api.get(`/scenarios/${id}`))
  const create = async (payload) => replace(await api.post('/scenarios', payload))
  async function remove(id) {
    await api.delete(`/scenarios/${id}`)
    scenarios.value = scenarios.value.filter((s) => s.id !== id)
  }
  async function setMeasures(id, measures) {
    return replace(await api.put(`/scenarios/${id}/measures`, measures))
  }
  async function assess(id, payload) {
    const a = await api.post(`/scenarios/${id}/assessments`, payload)
    await refresh(id)
    return a
  }
  // Переоцінка всіх сценаріїв комбінованим методом (після зміни заходів чи дерев)
  async function assessAll(m = 'combined') {
    for (const s of scenarios.value) {
      const last = latest(s, 'matrix')
      const body = m === 'matrix'
        ? { method: 'matrix', probability: last?.probability ?? 3, impact: last?.impact ?? 3 }
        : { method: 'combined' }
      await api.post(`/scenarios/${s.id}/assessments`, body)
    }
    await fetchScenarios()
  }

  const getTree = (id) => api.get(`/scenarios/${id}/attack-tree`)
  const saveTree = (id, tree) => api.put(`/scenarios/${id}/attack-tree`, tree)
  const resetTree = (id) => api.delete(`/scenarios/${id}/attack-tree`)

  // --- похідні дані ---
  function latest(s, m) {
    const list = s.assessments.filter((a) => a.method === m)
    return list.length ? list[list.length - 1] : null
  }

  // Плоский реєстр: сценарій + останні оцінки обома методами
  const register = computed(() => scenarios.value.map((s) => {
    const matrix = latest(s, 'matrix')
    const combined = latest(s, 'combined')
    const current = method.value === 'matrix' ? matrix : combined
    return {
      id: s.id,
      asset: s.asset.name,
      threat: s.threat.name,
      vulnerability: s.vulnerability.name,
      matrix,
      combined,
      current,
      score: current ? Number(current.score) : null,
      residual: current?.residual_score != null ? Number(current.residual_score) : null,
      level: current?.level.name ?? null,
      measuresImplemented: s.measure_links.filter((l) => l.status === 'implemented').length,
      measuresPlanned: s.measure_links.filter((l) => l.status === 'planned').length,
    }
  }).sort((a, b) => (b.score ?? -1) - (a.score ?? -1) || a.id - b.id))

  const assessed = computed(() => register.value.filter((r) => r.current))

  const stats = computed(() => {
    const rows = assessed.value
    const avg = (xs) => (xs.length ? xs.reduce((s, x) => s + x, 0) / xs.length : 0)
    return {
      total: scenarios.value.length,
      critical: rows.filter((r) => r.level === 'Критичний').length,
      average: avg(rows.map((r) => r.score)),
      averageResidual: avg(rows.map((r) => r.residual ?? r.score)),
      assets: new Set(rows.map((r) => r.asset)).size,
    }
  })

  // matrix[p - 1][i - 1] — рядки реєстру з імовірністю p та впливом i (для комбінованого
  // методу p — рівень NIST імовірності з дерева атак)
  const matrix = computed(() => {
    const cells = Array.from({ length: 5 }, () => Array.from({ length: 5 }, () => []))
    for (const r of assessed.value) cells[r.current.probability - 1][r.current.impact - 1].push(r)
    return cells
  })

  // Загрози: найбільший поточний і залишковий бал серед сценаріїв загрози
  const threats = computed(() => {
    const best = new Map()
    for (const r of assessed.value) {
      const prev = best.get(r.threat)
      if (!prev || prev.score < r.score) best.set(r.threat, r)
    }
    return [...best.values()].sort((a, b) => b.score - a.score)
  })

  const levelDistribution = computed(() => {
    const counts = {}
    for (const r of assessed.value) counts[r.level] = (counts[r.level] ?? 0) + 1
    const residual = {}
    for (const r of assessed.value) {
      const name = levelByScore(r.residual ?? r.score).name
      residual[name] = (residual[name] ?? 0) + 1
    }
    return { inherent: counts, residual }
  })

  // Динаміка: для кожної дати оцінювання — стан реєстру (останні оцінки на цю дату)
  const history = computed(() => {
    const out = {}
    for (const m of ['matrix', 'combined']) {
      const events = scenarios.value.flatMap((s) => s.assessments
        .filter((a) => a.method === m).map((a) => ({ ...a, scenario: s.id })))
        .sort((a, b) => a.assessed_at.localeCompare(b.assessed_at))
      const state = new Map()
      const byDay = new Map()
      for (const e of events) {
        state.set(e.scenario, e)
        const day = e.assessed_at.slice(0, 10)
        const vals = [...state.values()]
        byDay.set(day, {
          day,
          average: vals.reduce((s, a) => s + Number(a.score), 0) / vals.length,
          residual: vals.reduce((s, a) => s + Number(a.residual_score ?? a.score), 0) / vals.length,
          // критичні з урахуванням впроваджених заходів (залишковий ризик >= 15)
          critical: vals.filter((a) => Number(a.residual_score ?? a.score) >= 15).length,
          criticalInherent: vals.filter((a) => a.level.name === 'Критичний').length,
          total: vals.reduce((s, a) => s + Number(a.score), 0),
        })
      }
      out[m] = [...byDay.values()]
    }
    return out
  })

  return {
    scenarios, loading, error, method,
    fetchScenarios, refresh, create, remove, setMeasures, assess, assessAll,
    getTree, saveTree, resetTree, latest,
    register, stats, matrix, threats, levelDistribution, history,
  }
})
