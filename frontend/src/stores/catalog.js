import { defineStore } from 'pinia'
import { reactive, ref } from 'vue'
import { api } from '../api'

// Довідники системи: один і той самий набір дій для кожного ресурсу API
export const RESOURCES = {
  assets: '/assets',
  threats: '/threats',
  vulnerabilities: '/vulnerabilities',
  measures: '/measures',
  assetCategories: '/asset-categories',
  threatCategories: '/threat-categories',
}

export const useCatalogStore = defineStore('catalog', () => {
  const items = reactive(Object.fromEntries(Object.keys(RESOURCES).map((k) => [k, []])))
  const riskLevels = ref([])
  const loaded = ref(false)
  const error = ref('')

  async function fetchOne(kind) {
    items[kind] = await api.get(RESOURCES[kind])
  }

  async function fetchAll(force = false) {
    if (loaded.value && !force) return
    error.value = ''
    try {
      await Promise.all([...Object.keys(RESOURCES).map(fetchOne),
        api.get('/risk-levels').then((r) => { riskLevels.value = r })])
      loaded.value = true
    } catch (e) {
      error.value = 'Не вдалося завантажити довідники. Перевірте, чи запущено сервер.'
    }
  }

  // Створення (без id) або оновлення (з id) запису
  async function save(kind, payload, id = null) {
    const saved = id ? await api.put(`${RESOURCES[kind]}/${id}`, payload) : await api.post(RESOURCES[kind], payload)
    // Зв'язки M:N видно з обох боків, тож оновлюємо пов'язані довідники
    await Promise.all(['assets', 'threats', 'vulnerabilities', 'measures'].map(fetchOne))
    return saved
  }

  async function remove(kind, id) {
    await api.delete(`${RESOURCES[kind]}/${id}`)
    await Promise.all(['assets', 'threats', 'vulnerabilities', 'measures'].map(fetchOne))
  }

  const byId = (kind, id) => items[kind].find((x) => x.id === id)

  return { items, riskLevels, loaded, error, fetchAll, fetchOne, save, remove, byId }
})
