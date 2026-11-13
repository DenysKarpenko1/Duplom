<script setup>
import { computed, onMounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useCatalogStore } from '../stores/catalog'
import { useScenarioStore } from '../stores/scenarios'
import { IMPACT_LABELS, METHODS, NIST_UK, PROBABILITY_LABELS, fmt, pct } from '../levels'
import Panel from '../components/Panel.vue'
import LevelBadge from '../components/LevelBadge.vue'
import AttackTreeChart from '../components/AttackTreeChart.vue'

// Картка сценарію: дерево атак, заходи захисту, оцінювання та історія
const route = useRoute()
const router = useRouter()
const catalog = useCatalogStore()
const store = useScenarioStore()
const id = computed(() => Number(route.params.id))
const scenario = computed(() => store.scenarios.find((s) => s.id === id.value))
const tree = ref(null)
const error = ref('')
const message = ref('')
const showResidual = ref(true)

async function loadTree() {
  try {
    tree.value = await store.getTree(id.value)
    editorText.value = JSON.stringify(strip(tree.value.root), null, 2)
  } catch (e) {
    error.value = e.message
  }
}

onMounted(async () => {
  catalog.fetchAll()
  if (!scenario.value) await store.refresh(id.value).catch((e) => { error.value = e.message })
  await loadTree()
})
watch(id, loadTree)

// --- заходи захисту ---
const links = computed(() => scenario.value?.measure_links ?? [])
const statusOf = (mid) => links.value.find((l) => l.measure.id === mid)?.status ?? 'none'
const relevant = (m) => m.vulnerabilities.some((v) => treeVulns.value.has(v.id))
const treeVulns = computed(() => {
  const ids = new Set()
  const walk = (n) => { if (n.vulnerability_id) ids.add(n.vulnerability_id); n.children?.forEach(walk) }
  if (tree.value) walk(tree.value.root)
  return ids
})

async function setStatus(measureId, status) {
  const rest = links.value.filter((l) => l.measure.id !== measureId)
    .map((l) => ({ measure_id: l.measure.id, status: l.status }))
  if (status !== 'none') rest.push({ measure_id: measureId, status })
  await store.setMeasures(id.value, rest)
  await loadTree()
}

// --- оцінювання ---
const matrixForm = ref({ probability: 3, impact: 3 })
async function assess(method) {
  message.value = ''
  try {
    const body = method === 'matrix' ? { method, ...matrixForm.value } : { method }
    const a = await store.assess(id.value, body)
    message.value = `${METHODS[method].label}: бал ${fmt(a.score)}, рівень «${a.level.name}», залишковий ${fmt(a.residual_score)}.`
  } catch (e) {
    error.value = e.message
  }
}
const history = computed(() => [...(scenario.value?.assessments ?? [])].reverse())

// --- редактор дерева атак (JSON) ---
const editorOpen = ref(false)
const editorText = ref('')
const editorError = ref('')
function strip(n) {
  const out = { name: n.name, gate: n.gate }
  if (n.gate === 'LEAF') out.probability = n.probability
  if (n.vulnerability_id) out.vulnerability_id = n.vulnerability_id
  if (n.children?.length) out.children = n.children.map(strip)
  return out
}
async function saveTree() {
  editorError.value = ''
  try {
    tree.value = await store.saveTree(id.value, JSON.parse(editorText.value))
    editorOpen.value = false
  } catch (e) {
    editorError.value = e instanceof SyntaxError ? `Помилка JSON: ${e.message}` : e.message
  }
}
async function resetTree() {
  tree.value = await store.resetTree(id.value)
  editorText.value = JSON.stringify(strip(tree.value.root), null, 2)
}

async function removeScenario() {
  await store.remove(id.value)
  router.push('/scenarios')
}
</script>

<template>
  <div v-if="scenario" class="space-y-6">
    <header class="flex flex-wrap items-end justify-between gap-4">
      <div>
        <RouterLink to="/scenarios" class="text-xs text-slate-500 hover:text-slate-900">← Усі сценарії</RouterLink>
        <h1 class="text-2xl font-semibold text-slate-900">{{ scenario.threat.name }}</h1>
        <p class="text-sm text-slate-500">
          Актив: <b>{{ scenario.asset.name }}</b> · Вразливість: <b>{{ scenario.vulnerability.name }}</b>
        </p>
      </div>
      <button class="text-sm text-slate-400 hover:text-red-600" @click="removeScenario">Видалити сценарій</button>
    </header>

    <p v-if="error" class="rounded-lg bg-red-50 px-4 py-3 text-sm text-red-700">{{ error }}</p>

    <section v-if="tree" class="grid grid-cols-2 gap-4 xl:grid-cols-5">
      <div class="rounded-xl bg-white p-4 shadow-sm ring-1 ring-slate-200">
        <p class="text-xs text-slate-500">Ймовірність реалізації (дерево атак)</p>
        <p class="mt-1 text-2xl font-semibold">{{ pct(tree.likelihood) }}</p>
        <p class="text-xs text-slate-400">NIST: {{ NIST_UK[tree.likelihood_level] }}</p>
      </div>
      <div class="rounded-xl bg-white p-4 shadow-sm ring-1 ring-slate-200">
        <p class="text-xs text-slate-500">Вплив (max C/I/A активу)</p>
        <p class="mt-1 text-2xl font-semibold">{{ fmt(tree.impact) }}</p>
        <p class="text-xs text-slate-400">{{ IMPACT_LABELS[Math.round(tree.impact) - 1] }}</p>
      </div>
      <div class="rounded-xl bg-white p-4 shadow-sm ring-1 ring-slate-200">
        <p class="text-xs text-slate-500">Ризик (нечіткий висновок)</p>
        <p class="mt-1 text-2xl font-semibold">{{ fmt(tree.inherent.score) }}</p>
        <p class="text-xs text-slate-400">NIST: {{ NIST_UK[tree.inherent.nist_level] }}</p>
      </div>
      <div class="rounded-xl bg-white p-4 shadow-sm ring-1 ring-slate-200">
        <p class="text-xs text-slate-500">Залишковий ризик</p>
        <p class="mt-1 text-2xl font-semibold text-green-700">{{ fmt(tree.residual.score) }}</p>
        <p class="text-xs text-slate-400">P = {{ pct(tree.residual_likelihood) }} · NIST: {{ NIST_UK[tree.residual.nist_level] }}</p>
      </div>
      <div class="rounded-xl bg-white p-4 shadow-sm ring-1 ring-slate-200">
        <p class="text-xs text-slate-500">Зниження ризику</p>
        <p class="mt-1 text-2xl font-semibold">{{ pct(tree.risk_reduction) }}</p>
        <p class="text-xs text-slate-400">завдяки впровадженим заходам</p>
      </div>
    </section>

    <Panel
      v-if="tree" title="Дерево атак"
      :subtitle="tree.custom ? 'Власне дерево сценарію' : 'Типове дерево: ініціювання загрози AND експлуатація вразливості'"
    >
      <template #actions>
        <div class="flex flex-wrap items-center gap-3 text-xs">
          <label class="flex items-center gap-1.5 text-slate-600">
            <input v-model="showResidual" type="checkbox" class="accent-green-600" /> показувати вплив заходів
          </label>
          <button class="rounded-md bg-slate-100 px-2.5 py-1 hover:bg-slate-200" @click="editorOpen = !editorOpen">
            {{ editorOpen ? 'Закрити редактор' : 'Редагувати дерево' }}
          </button>
          <button v-if="tree.custom" class="text-slate-500 hover:text-slate-900" @click="resetTree">Скинути до типового</button>
        </div>
      </template>
      <AttackTreeChart :root="tree.root" :show-residual="showResidual" />
      <div class="mt-2 flex flex-wrap gap-4 text-xs text-slate-500">
        <span><span class="inline-block h-3 w-5 rounded-sm bg-violet-600 align-middle"></span> AND — потрібні всі дії</span>
        <span><span class="inline-block h-3 w-5 rounded-sm bg-cyan-600 align-middle"></span> OR — достатньо однієї</span>
        <span><span class="inline-block h-3 w-3 rounded-full bg-slate-600 align-middle"></span> елементарна дія</span>
        <span class="text-red-600">● найімовірніший шлях атаки</span>
        <span class="text-green-700">→ ймовірність з урахуванням заходів</span>
      </div>
      <div class="mt-3 text-sm">
        <p><b>Найімовірніший сценарій атаки:</b> {{ tree.most_likely_path.join(' + ') }}</p>
        <p class="mt-1 text-slate-500">Мінімальних наборів атак: {{ tree.minimal_cut_sets.length }}</p>
      </div>
      <div v-if="editorOpen" class="mt-4 grid gap-4 lg:grid-cols-3">
        <div class="lg:col-span-2">
          <textarea v-model="editorText" rows="16" class="w-full rounded-lg border border-slate-300 p-3 font-mono text-xs outline-none focus:border-slate-500" />
          <p v-if="editorError" class="mt-1 text-sm text-red-600">{{ editorError }}</p>
          <button class="mt-2 rounded-lg bg-slate-900 px-4 py-2 text-sm text-white hover:bg-slate-700" @click="saveTree">Зберегти дерево</button>
        </div>
        <div class="text-xs text-slate-500">
          <p class="font-medium text-slate-700">Формат вузла</p>
          <pre class="mt-1 rounded-lg bg-slate-50 p-2">{ "name": "…",
  "gate": "AND" | "OR" | "LEAF",
  "probability": 0.5,      // лише LEAF
  "vulnerability_id": 3,   // необов'язково
  "children": [ … ] }</pre>
          <p class="mt-2 font-medium text-slate-700">Вразливості (id)</p>
          <ul class="mt-1 space-y-0.5">
            <li v-for="v in catalog.items.vulnerabilities" :key="v.id"><b>{{ v.id }}</b> — {{ v.name }}</li>
          </ul>
        </div>
      </div>
    </Panel>

    <section class="grid gap-6 xl:grid-cols-2">
      <Panel title="Заходи захисту" subtitle="Впроваджені заходи знижують імовірність листків, що експлуатують закриті ними вразливості">
        <table class="w-full text-left text-sm">
          <tbody>
            <tr v-for="m in catalog.items.measures" :key="m.id" class="border-b border-slate-100 last:border-0">
              <td class="py-2 pr-2">
                <p class="font-medium" :class="!relevant(m) && 'text-slate-400'">{{ m.name }}</p>
                <p class="text-xs text-slate-400">
                  ефективність {{ pct(m.effectiveness, 0) }} · {{ m.vulnerabilities.map((v) => v.name).join('; ') || 'не закриває вразливостей' }}
                  <span v-if="!relevant(m)"> · не впливає на дерево</span>
                </p>
              </td>
              <td class="py-2 text-right">
                <select
                  :value="statusOf(m.id)" class="rounded-md border border-slate-300 px-2 py-1 text-xs"
                  @change="setStatus(m.id, $event.target.value)"
                >
                  <option value="none">не застосовано</option>
                  <option value="planned">заплановано</option>
                  <option value="implemented">впроваджено</option>
                </select>
              </td>
            </tr>
          </tbody>
        </table>
      </Panel>

      <Panel title="Оцінювання" subtitle="Кожне оцінювання зберігається в історії">
        <div class="space-y-3">
          <div class="flex flex-wrap items-end gap-3 rounded-lg bg-slate-50 p-3">
            <label class="text-xs">Імовірність
              <select v-model.number="matrixForm.probability" class="mt-1 block rounded-md border border-slate-300 px-2 py-1">
                <option v-for="n in 5" :key="n" :value="n">{{ n }} – {{ PROBABILITY_LABELS[n - 1] }}</option>
              </select>
            </label>
            <label class="text-xs">Вплив
              <select v-model.number="matrixForm.impact" class="mt-1 block rounded-md border border-slate-300 px-2 py-1">
                <option v-for="n in 5" :key="n" :value="n">{{ n }} – {{ IMPACT_LABELS[n - 1] }}</option>
              </select>
            </label>
            <button class="rounded-lg bg-slate-600 px-3 py-1.5 text-sm text-white hover:bg-slate-500" @click="assess('matrix')">Оцінити матрицею</button>
          </div>
          <button class="w-full rounded-lg bg-blue-600 px-3 py-2 text-sm font-medium text-white hover:bg-blue-500" @click="assess('combined')">
            Оцінити комбінованим методом (дерево атак + нечітка логіка)
          </button>
          <p v-if="message" class="text-sm text-green-700">{{ message }}</p>
          <div class="max-h-80 overflow-y-auto">
            <table class="w-full text-left text-xs">
              <thead class="sticky top-0 bg-white text-slate-500">
                <tr><th class="py-1">Дата</th><th>Метод</th><th class="text-center">P</th><th class="text-center">I</th><th class="text-center">Бал</th><th class="text-center">Залишк.</th><th>Рівень</th></tr>
              </thead>
              <tbody>
                <tr v-for="a in history" :key="a.id" class="border-t border-slate-100">
                  <td class="py-1.5">{{ new Date(a.assessed_at).toLocaleString('uk-UA', { dateStyle: 'short', timeStyle: 'short' }) }}</td>
                  <td>{{ METHODS[a.method].label }}</td>
                  <td class="text-center">{{ a.likelihood != null ? pct(a.likelihood) : a.probability }}</td>
                  <td class="text-center">{{ a.impact }}</td>
                  <td class="text-center font-semibold">{{ fmt(a.score) }}</td>
                  <td class="text-center">{{ fmt(a.residual_score) }}</td>
                  <td><LevelBadge :level="a.level.name" /></td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </Panel>
    </section>
  </div>
  <p v-else-if="error" class="rounded-lg bg-red-50 px-4 py-3 text-sm text-red-700">{{ error }}</p>
</template>
