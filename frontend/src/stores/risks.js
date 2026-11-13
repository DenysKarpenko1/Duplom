import { defineStore } from 'pinia'
import { computed, ref } from 'vue'
import { api } from '../api'

// Сховище ризиків: єдине джерело даних для дашборду та сторінки введення
export const useRiskStore = defineStore('risks', () => {
  const risks = ref([])
  const loading = ref(false)
  const error = ref('')

  // --- похідні дані (перераховуються автоматично після зміни risks) ---
  const total = computed(() => risks.value.length)
  const criticalCount = computed(() => risks.value.filter((r) => r.level === 'Критичний').length)
  const assetCount = computed(() => new Set(risks.value.map((r) => r.asset)).size)
  const averageScore = computed(() =>
    total.value ? risks.value.reduce((sum, r) => sum + r.score, 0) / total.value : 0,
  )

  // matrix[p - 1][i - 1] — перелік ризиків з імовірністю p та впливом i
  const matrix = computed(() => {
    const cells = Array.from({ length: 5 }, () => Array.from({ length: 5 }, () => []))
    for (const r of risks.value) cells[r.probability - 1][r.impact - 1].push(r)
    return cells
  })

  // Топ-5 загроз за найбільшим балом ризику серед пов’язаних сценаріїв
  const topThreats = computed(() => {
    const best = new Map()
    for (const r of risks.value) {
      if (!best.has(r.threat) || best.get(r.threat).score < r.score) best.set(r.threat, r)
    }
    return [...best.values()].sort((a, b) => b.score - a.score).slice(0, 5)
  })

  // --- дії ---
  async function fetchRisks() {
    loading.value = true
    error.value = ''
    try {
      risks.value = await api.get('/risks')
    } catch (e) {
      error.value = 'Не вдалося завантажити дані. Перевірте, чи запущено сервер.'
    } finally {
      loading.value = false
    }
  }

  async function addRisk(payload) {
    const created = await api.post('/risks', payload)
    // Зберігаємо впорядкованість за спаданням балу, як у відповіді сервера
    risks.value = [...risks.value, created].sort((a, b) => b.score - a.score || a.id - b.id)
    return created
  }

  async function removeRisk(id) {
    await api.delete(`/risks/${id}`)
    risks.value = risks.value.filter((r) => r.id !== id)
  }

  return {
    risks, loading, error,
    total, criticalCount, assetCount, averageScore, matrix, topThreats,
    fetchRisks, addRisk, removeRisk,
  }
})
