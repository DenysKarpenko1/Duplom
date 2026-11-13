<script setup>
import { onMounted, reactive, ref } from 'vue'
import { useCatalogStore } from '../stores/catalog'
import { useScenarioStore } from '../stores/scenarios'
import Panel from '../components/Panel.vue'
import RiskRegister from '../components/RiskRegister.vue'
import MethodSwitch from '../components/MethodSwitch.vue'

// Сценарії ризику: створення з довідників та масова переоцінка
const catalog = useCatalogStore()
const store = useScenarioStore()
onMounted(() => { catalog.fetchAll(); store.fetchScenarios() })

const form = reactive({ asset_id: null, threat_id: null, vulnerability_id: null })
const message = ref('')
const failed = ref(false)
const busy = ref(false)

// Вразливості, пов'язані з обраною загрозою, показуються першими
const vulnOptions = () => {
  const threat = catalog.byId('threats', form.threat_id)
  const linked = new Set(threat?.vulnerabilities.map((v) => v.id) ?? [])
  return [...catalog.items.vulnerabilities].sort((a, b) => linked.has(b.id) - linked.has(a.id))
    .map((v) => ({ ...v, linked: linked.has(v.id) }))
}

async function create() {
  busy.value = true
  try {
    const s = await store.create({ ...form })
    await store.assess(s.id, { method: 'combined' })
    failed.value = false
    message.value = 'Сценарій створено й оцінено комбінованим методом.'
  } catch (e) {
    failed.value = true
    message.value = e.message
  } finally {
    busy.value = false
  }
}

async function reassess(method) {
  busy.value = true
  try {
    await store.assessAll(method)
    failed.value = false
    message.value = 'Усі сценарії переоцінено.'
  } catch (e) {
    failed.value = true
    message.value = e.message
  } finally {
    busy.value = false
  }
}

const input = 'mt-1 w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm outline-none focus:border-slate-500'
</script>

<template>
  <div class="space-y-6">
    <header class="flex flex-wrap items-end justify-between gap-4">
      <div>
        <h1 class="text-2xl font-semibold text-slate-900">Сценарії ризику</h1>
        <p class="text-sm text-slate-500">Актив + загроза + вразливість; дерево атак і заходи задаються в картці сценарію</p>
      </div>
      <div class="flex flex-wrap items-center gap-2">
        <button :disabled="busy" class="rounded-lg bg-white px-3 py-2 text-sm ring-1 ring-slate-200 hover:bg-slate-50 disabled:opacity-50" @click="reassess('combined')">
          Переоцінити всі (комбінований)
        </button>
        <button :disabled="busy" class="rounded-lg bg-white px-3 py-2 text-sm ring-1 ring-slate-200 hover:bg-slate-50 disabled:opacity-50" @click="reassess('matrix')">
          Переоцінити всі (матриця)
        </button>
      </div>
    </header>

    <Panel title="Новий сценарій">
      <form class="grid gap-4 lg:grid-cols-4" @submit.prevent="create">
        <label class="text-sm"><span class="font-medium text-slate-700">ІТ-актив</span>
          <select v-model="form.asset_id" required :class="input">
            <option v-for="a in catalog.items.assets" :key="a.id" :value="a.id">{{ a.name }}</option>
          </select>
        </label>
        <label class="text-sm"><span class="font-medium text-slate-700">Загроза</span>
          <select v-model="form.threat_id" required :class="input">
            <option v-for="t in catalog.items.threats" :key="t.id" :value="t.id">{{ t.name }}</option>
          </select>
        </label>
        <label class="text-sm"><span class="font-medium text-slate-700">Вразливість</span>
          <select v-model="form.vulnerability_id" required :class="input">
            <option v-for="v in vulnOptions()" :key="v.id" :value="v.id">{{ v.linked ? '★ ' : '' }}{{ v.name }}</option>
          </select>
        </label>
        <div class="flex items-end">
          <button type="submit" :disabled="busy" class="w-full rounded-lg bg-slate-900 px-5 py-2 text-sm font-medium text-white hover:bg-slate-700 disabled:opacity-50">
            Створити й оцінити
          </button>
        </div>
      </form>
      <p class="mt-2 text-xs text-slate-400">★ — вразливість, яку обрана загроза експлуатує за довідником</p>
      <p v-if="message" class="mt-2 text-sm" :class="failed ? 'text-red-600' : 'text-green-700'">{{ message }}</p>
    </Panel>

    <Panel title="Реєстр сценаріїв">
      <template #actions><MethodSwitch v-model="store.method" /></template>
      <RiskRegister :rows="store.register" />
    </Panel>
  </div>
</template>
