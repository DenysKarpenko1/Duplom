<script setup>
import { computed, onMounted, ref } from 'vue'
import { api } from '../api'
import { useChart, saveAsImage } from '../composables/useChart'
import { useScenarioStore } from '../stores/scenarios'
import { LEVELS, METHODS, fmt, levelByName, pct } from '../levels'
import Panel from '../components/Panel.vue'
import LevelBadge from '../components/LevelBadge.vue'

// Експериментальне порівняння: базова матрична модель vs комбінований метод
const data = ref(null)
const error = ref('')
const loading = ref(false)
const topN = ref(10)
const scenarios = useScenarioStore()

async function load() {
  loading.value = true
  error.value = ''
  try {
    data.value = await api.get(`/experiments/comparison?top_n=${topN.value}`)
    await scenarios.fetchScenarios()
  } catch (e) {
    error.value = 'Не вдалося отримати результати. Перевірте, чи запущено сервер і чи завантажено дані (python -m app.seed_enterprise).'
  } finally {
    loading.value = false
  }
}
onMounted(load)

const M = METHODS.matrix.color
const C = METHODS.combined.color
const S = computed(() => data.value?.summary)
const A = computed(() => data.value?.agreement)

// --- таблиця підсумкових метрик ---
const METRICS = [
  ['Середній бал ризику', (s) => fmt(s.score.mean)],
  ['Медіана', (s) => fmt(s.score.median)],
  ['Стандартне відхилення', (s) => fmt(s.score.std)],
  ['Діапазон балів', (s) => `${fmt(s.score.min)} – ${fmt(s.score.max)}`],
  ['Кількість різних значень балу', (s) => s.distinct_scores],
  ['Частка нерозрізнюваних пар (ties)', (s) => pct(s.tie_ratio)],
  ['Нормована ентропія розподілу рівнів', (s) => fmt(s.entropy, 3)],
  ['Частка критичних ризиків', (s) => pct(s.critical_share)],
  ['Середній залишковий бал', (s) => fmt(s.residual.mean)],
  ['Середнє зниження ризику заходами', (s) => pct(s.mean_reduction)],
]

// --- 1. розподіл за рівнями ---
const levelsEl = useChart(() => {
  if (!S.value) return {}
  const names = LEVELS.map((l) => l.name)
  const bar = (name, src, color, opacity = 1) => ({
    name, type: 'bar', data: names.map((n) => src[n]), itemStyle: { color, opacity }, barGap: '8%',
    label: { show: true, position: 'top', fontSize: 10 },
  })
  return {
    toolbox: saveAsImage, tooltip: { trigger: 'axis' }, legend: { top: 0 },
    grid: { left: 40, right: 16, top: 48, bottom: 28 },
    xAxis: { type: 'category', data: names }, yAxis: { type: 'value', name: 'Сценаріїв', minInterval: 1 },
    series: [
      bar('Матриця: поточний', S.value.matrix.levels, M),
      bar('Комбінований: поточний', S.value.combined.levels, C),
      bar('Матриця: залишковий', S.value.matrix.residual_levels, M, 0.4),
      bar('Комбінований: залишковий', S.value.combined.residual_levels, C, 0.4),
    ],
  }
}, () => data.value)

// --- 2. діаграма розсіювання балів ---
const scatterEl = useChart(() => {
  if (!data.value) return {}
  const rows = data.value.scenarios
  return {
    toolbox: saveAsImage,
    tooltip: { formatter: ({ data: d }) => `${d.row.asset}<br/>${d.row.threat}<br/>Матриця: ${d.value[0]} · Комбінований: ${d.value[1]}` },
    grid: { left: 56, right: 24, top: 24, bottom: 48 },
    xAxis: { type: 'value', name: 'Бал за матричною моделлю', nameLocation: 'middle', nameGap: 28, min: 0, max: 25 },
    yAxis: { type: 'value', name: 'Бал за комбінованим методом', nameLocation: 'middle', nameGap: 36, min: 0, max: 25 },
    series: [{
      type: 'scatter', symbolSize: 11,
      data: rows.map((r) => ({ value: [r.matrix.score, r.combined.score], row: r, itemStyle: { color: levelByName(r.combined.level).color, borderColor: '#fff' } })),
      markLine: { silent: true, symbol: 'none', lineStyle: { type: 'dashed', color: '#94a3b8' }, label: { formatter: 'y = x' }, data: [[{ coord: [0, 0] }, { coord: [25, 25] }]] },
      markArea: {
        silent: true,
        data: LEVELS.map((l, i) => [{ yAxis: i ? LEVELS[i - 1].max : 0, itemStyle: { color: l.color, opacity: 0.06 } }, { yAxis: l.max }]),
      },
    }],
  }
}, () => data.value)

// --- 3. матриця відповідності рівнів ---
const confusionEl = useChart(() => {
  if (!A.value) return {}
  const names = data.value.levels
  const cells = []
  A.value.confusion.forEach((row, i) => row.forEach((v, j) => cells.push([j, i, v])))
  const max = Math.max(1, ...cells.map((c) => c[2]))
  return {
    toolbox: saveAsImage,
    tooltip: { formatter: ({ value }) => `Матриця: ${names[value[1]]}<br/>Комбінований: ${names[value[0]]}<br/>Сценаріїв: ${value[2]}` },
    grid: { left: 96, right: 16, top: 16, bottom: 56 },
    xAxis: { type: 'category', data: names, name: 'Комбінований метод', nameLocation: 'middle', nameGap: 32 },
    yAxis: { type: 'category', data: names, name: 'Матрична модель', nameLocation: 'middle', nameGap: 80 },
    visualMap: { show: false, min: 0, max, inRange: { color: ['#f8fafc', '#1d4ed8'] } },
    series: [{
      type: 'heatmap', data: cells,
      label: { show: true, fontSize: 16, fontWeight: 'bold', color: '#0f172a', formatter: ({ value }) => value[2] || '' },
      itemStyle: { borderColor: '#fff', borderWidth: 2 },
    }],
  }
}, () => data.value)

// --- 4. бали за сценаріями ---
const perScenarioEl = useChart(() => {
  if (!data.value) return {}
  const rows = [...data.value.scenarios].sort((a, b) => b.combined.score - a.combined.score)
  const label = (r) => `${r.asset}: ${r.threat}`
  return {
    toolbox: saveAsImage,
    tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
    legend: { top: 0 },
    grid: { left: 48, right: 16, top: 40, bottom: 150 },
    dataZoom: [{ type: 'inside' }],
    xAxis: { type: 'category', data: rows.map(label), axisLabel: { rotate: 60, fontSize: 9, width: 160, overflow: 'truncate' } },
    yAxis: { type: 'value', name: 'Бал ризику', min: 0, max: 25 },
    series: [
      { name: 'Матриця', type: 'bar', data: rows.map((r) => r.matrix.score), itemStyle: { color: M } },
      { name: 'Комбінований', type: 'bar', data: rows.map((r) => r.combined.score), itemStyle: { color: C } },
      { name: 'Комбінований: залишковий', type: 'line', data: rows.map((r) => r.combined.residual), itemStyle: { color: '#16a34a' }, symbolSize: 5 },
      { name: 'Матриця: залишковий', type: 'line', data: rows.map((r) => r.matrix.residual), itemStyle: { color: '#94a3b8' }, lineStyle: { type: 'dashed' }, symbolSize: 4 },
    ],
  }
}, () => data.value)

// --- 5. ефект заходів захисту (частка в сумарному зниженні) ---
const measuresEl = useChart(() => {
  if (!data.value) return {}
  const ms = [...data.value.measures]
  const total = (k) => ms.reduce((s, m) => s + m[k], 0) || 1
  const tm = total('matrix_reduction')
  const tc = total('combined_reduction')
  ms.sort((a, b) => a.combined_reduction / tc - b.combined_reduction / tc)
  return {
    toolbox: saveAsImage,
    tooltip: {
      trigger: 'axis', axisPointer: { type: 'shadow' },
      formatter: (ps) => `${ps[0].name}<br/>${ps.map((p) => `${p.seriesName}: ${p.value}%`).join('<br/>')}`,
    },
    legend: { top: 0 },
    grid: { left: 230, right: 40, top: 36, bottom: 24 },
    xAxis: { type: 'value', name: '% сумарного зниження', axisLabel: { formatter: '{value}%' } },
    yAxis: { type: 'category', data: ms.map((m) => m.name), axisLabel: { width: 220, overflow: 'truncate', fontSize: 11 } },
    series: [
      { name: 'Матриця', type: 'bar', data: ms.map((m) => +(m.matrix_reduction / tm * 100).toFixed(1)), itemStyle: { color: M } },
      { name: 'Комбінований', type: 'bar', data: ms.map((m) => +(m.combined_reduction / tc * 100).toFixed(1)), itemStyle: { color: C } },
    ],
  }
}, () => data.value)

// --- 6. динаміка за раундами оцінювання ---
const dynamicsEl = useChart(() => {
  const h = scenarios.history
  const days = [...new Set([...h.matrix, ...h.combined].map((x) => x.day))].sort()
  const pick = (m, key) => days.map((d) => { const x = h[m].find((e) => e.day === d); return x ? +x[key].toFixed(2) : null })
  return {
    toolbox: saveAsImage, tooltip: { trigger: 'axis' }, legend: { top: 0 },
    grid: { left: 48, right: 48, top: 84, bottom: 32 },
    xAxis: { type: 'category', data: days, axisLabel: { interval: 0 } },
    yAxis: [{ type: 'value', name: 'Середній бал', min: 0, max: 20 }, { type: 'value', name: 'Критичних', minInterval: 1, splitLine: { show: false } }],
    series: [
      { name: 'Матриця: залишковий', type: 'line', data: pick('matrix', 'residual'), itemStyle: { color: M }, symbolSize: 7 },
      { name: 'Комбінований: залишковий', type: 'line', data: pick('combined', 'residual'), itemStyle: { color: C }, symbolSize: 7 },
      { name: 'Матриця: критичних', type: 'bar', yAxisIndex: 1, data: pick('matrix', 'critical'), itemStyle: { color: M, opacity: 0.3 }, barMaxWidth: 18 },
      { name: 'Комбінований: критичних', type: 'bar', yAxisIndex: 1, data: pick('combined', 'critical'), itemStyle: { color: C, opacity: 0.3 }, barMaxWidth: 18 },
    ],
  }
}, () => scenarios.history)

const corr = (c) => (c?.coef == null ? '—' : `${fmt(c.coef, 3)} (p ${c.p_value < 0.001 ? '< 0,001' : `= ${fmt(c.p_value, 3)}`})`)
</script>

<template>
  <div class="space-y-6">
    <header class="flex flex-wrap items-end justify-between gap-4">
      <div>
        <h1 class="text-2xl font-semibold text-slate-900">Порівняння моделей</h1>
        <p class="text-sm text-slate-500">
          Базова матрична модель (P×I) та комбінований метод (дерево атак + нечіткий висновок NIST SP 800-30) на одному наборі сценаріїв
        </p>
      </div>
      <div class="flex items-center gap-2 text-sm">
        <label class="text-slate-500">Топ-N <input v-model.number="topN" type="number" min="1" max="50" class="ml-1 w-16 rounded-md border border-slate-300 px-2 py-1" /></label>
        <button :disabled="loading" class="rounded-lg bg-slate-900 px-4 py-2 text-white hover:bg-slate-700 disabled:opacity-50" @click="load">
          {{ loading ? 'Обчислення…' : 'Перерахувати' }}
        </button>
      </div>
    </header>

    <p v-if="error" class="rounded-lg bg-red-50 px-4 py-3 text-sm text-red-700">{{ error }}</p>

    <template v-if="data">
      <section class="grid grid-cols-2 gap-4 xl:grid-cols-6">
        <div v-for="[label, value, hint] in [
          ['Сценаріїв', data.scenarios.length, 'у вибірці'],
          ['Спірмен ρ', corr(A.spearman), 'рангова кореляція балів'],
          ['Кендалл τ', corr(A.kendall), 'рангова кореляція балів'],
          ['Збіг рівнів', pct(A.exact), `з точністю до 1 рівня: ${pct(A.within_one)}`],
          ['Каппа Коена', fmt(A.kappa_linear, 3), 'лінійно зважена'],
          [`Перетин топ-${A.top_n}`, pct(A.top_overlap), 'найризикованіших сценаріїв'],
        ]" :key="label" class="rounded-xl bg-white p-4 shadow-sm ring-1 ring-slate-200">
          <p class="text-xs text-slate-500">{{ label }}</p>
          <p class="mt-1 text-lg font-semibold">{{ value }}</p>
          <p class="text-xs text-slate-400">{{ hint }}</p>
        </div>
      </section>

      <section class="grid gap-6 xl:grid-cols-5">
        <Panel title="Підсумкові показники моделей" class="xl:col-span-2">
          <table class="w-full text-sm">
            <thead class="border-b border-slate-200 text-xs uppercase text-slate-500">
              <tr><th class="py-2 text-left">Показник</th><th class="pl-3 text-right" :style="{ color: M }">Матриця</th><th class="pl-3 text-right" :style="{ color: C }">Комбінований</th></tr>
            </thead>
            <tbody>
              <tr v-for="[label, get] in METRICS" :key="label" class="border-b border-slate-100 last:border-0">
                <td class="py-1.5 text-slate-600">{{ label }}</td>
                <td class="text-right font-medium">{{ get(S.matrix) }}</td>
                <td class="text-right font-medium">{{ get(S.combined) }}</td>
              </tr>
            </tbody>
          </table>
          <p class="mt-3 text-xs text-slate-400">
            Комбінований метод частіше оцінює ризик нижче: {{ pct(A.b_lower) }} сценаріїв, вище: {{ pct(A.b_higher) }}.
          </p>
        </Panel>
        <Panel title="Розподіл сценаріїв за рівнями ризику" class="xl:col-span-3">
          <div ref="levelsEl" class="h-80 w-full"></div>
        </Panel>
      </section>

      <section class="grid gap-6 xl:grid-cols-2">
        <Panel title="Бали ризику: матриця vs комбінований метод" subtitle="Колір точки — рівень за комбінованим методом; смуги — межі рівнів">
          <div ref="scatterEl" class="h-96 w-full"></div>
        </Panel>
        <Panel title="Матриця відповідності рівнів" subtitle="Рядки — матрична модель, стовпці — комбінований метод">
          <div ref="confusionEl" class="h-96 w-full"></div>
        </Panel>
      </section>

      <Panel title="Оцінки за сценаріями" subtitle="Сценарії впорядковано за балом комбінованого методу">
        <div ref="perScenarioEl" class="h-[460px] w-full"></div>
      </Panel>

      <section class="grid gap-6 xl:grid-cols-2">
        <Panel title="Внесок заходів захисту у зниження ризику" subtitle="Ефект заходу, впровадженого окремо; частка від суми ефектів усіх заходів">
          <div ref="measuresEl" class="h-[520px] w-full"></div>
        </Panel>
        <Panel title="Динаміка залишкового ризику за раундами оцінювання" subtitle="Поступове впровадження заходів (червень – листопад)">
          <div ref="dynamicsEl" class="h-[520px] w-full"></div>
        </Panel>
      </section>

      <Panel title="Результати за сценаріями">
        <div class="overflow-x-auto">
          <table class="w-full text-left text-xs">
            <thead class="border-b border-slate-200 uppercase text-slate-500">
              <tr>
                <th class="px-2 py-2">Актив / загроза</th>
                <th class="px-2 text-center">P×I</th><th class="px-2 text-center">Бал</th><th class="px-2">Рівень</th><th class="px-2 text-center">Залишк.</th>
                <th class="px-2 text-center">P дерева</th><th class="px-2 text-center">I</th><th class="px-2 text-center">Бал</th><th class="px-2">Рівень</th><th class="px-2 text-center">Залишк.</th>
                <th class="px-2 text-center">Вузлів / шляхів</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="r in data.scenarios" :key="r.id" class="border-b border-slate-100 hover:bg-slate-50">
                <td class="px-2 py-1.5">
                  <RouterLink :to="`/scenarios/${r.id}`" class="font-medium hover:text-blue-700">{{ r.asset }}</RouterLink>
                  <p class="text-slate-500">{{ r.threat }}</p>
                </td>
                <td class="px-2 text-center">{{ r.matrix.probability }}×{{ r.matrix.impact }}</td>
                <td class="px-2 text-center font-semibold">{{ fmt(r.matrix.score) }}</td>
                <td class="px-2"><LevelBadge :level="r.matrix.level" /></td>
                <td class="px-2 text-center">{{ fmt(r.matrix.residual) }}</td>
                <td class="px-2 text-center">{{ pct(r.combined.likelihood) }}</td>
                <td class="px-2 text-center">{{ fmt(r.combined.impact) }}</td>
                <td class="px-2 text-center font-semibold">{{ fmt(r.combined.score) }}</td>
                <td class="px-2"><LevelBadge :level="r.combined.level" /></td>
                <td class="px-2 text-center">{{ fmt(r.combined.residual) }}</td>
                <td class="px-2 text-center text-slate-500">{{ r.tree.nodes }} / {{ r.tree.attack_paths }}</td>
              </tr>
            </tbody>
          </table>
        </div>
        <p class="mt-2 text-xs text-slate-400">
          Матриця: P = ⌈(базова ймовірність загрози + критичність вразливості) / 2⌉, I = max(C, I, A).
          Комбінований: P — ймовірність досягнення кореня дерева атак, I — так само, бал — нечіткий висновок.
        </p>
      </Panel>
    </template>
  </div>
</template>
