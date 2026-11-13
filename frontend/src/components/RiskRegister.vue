<script setup>
import { computed, ref } from 'vue'
import LevelBadge from './LevelBadge.vue'
import { fmt, levelByScore, pct } from '../levels'

// Реєстр ризиків: сценарії з оцінками обома методами, сортування та пошук
const props = defineProps({
  rows: { type: Array, required: true },
  highlight: { type: Array, default: () => [] }, // id виділених сценаріїв
})

const query = ref('')
const sortKey = ref('score')
const sortDir = ref(-1)

const COLUMNS = [
  { key: 'asset', label: 'Актив' },
  { key: 'threat', label: 'Загроза' },
  { key: 'vulnerability', label: 'Вразливість' },
  { key: 'matrixScore', label: 'Матриця P×I', num: true },
  { key: 'likelihood', label: 'P (дерево атак)', num: true },
  { key: 'combinedScore', label: 'Комбінований', num: true },
  { key: 'score', label: 'Поточний', num: true },
  { key: 'residual', label: 'Залишковий', num: true },
  { key: 'measures', label: 'Заходи', num: true },
]

const value = (r, key) => ({
  matrixScore: r.matrix ? Number(r.matrix.score) : null,
  combinedScore: r.combined ? Number(r.combined.score) : null,
  likelihood: r.combined?.likelihood != null ? Number(r.combined.likelihood) : null,
  measures: r.measuresImplemented,
}[key] ?? r[key])

const shown = computed(() => {
  const q = query.value.trim().toLowerCase()
  const rows = q
    ? props.rows.filter((r) => `${r.asset} ${r.threat} ${r.vulnerability}`.toLowerCase().includes(q))
    : props.rows
  return [...rows].sort((a, b) => {
    const x = value(a, sortKey.value)
    const y = value(b, sortKey.value)
    if (x == null) return 1
    if (y == null) return -1
    return (typeof x === 'string' ? x.localeCompare(y, 'uk') : x - y) * sortDir.value
  })
})

function sortBy(key) {
  if (sortKey.value === key) sortDir.value = -sortDir.value
  else { sortKey.value = key; sortDir.value = -1 }
}
</script>

<template>
  <div>
    <input
      v-model="query" placeholder="Пошук за активом, загрозою чи вразливістю…"
      class="mb-3 w-full max-w-md rounded-lg border border-slate-300 px-3 py-1.5 text-sm outline-none focus:border-slate-500"
    />
    <div class="overflow-x-auto">
      <table class="w-full text-left text-sm">
        <thead class="border-b border-slate-200 text-xs uppercase text-slate-500">
          <tr>
            <th
              v-for="c in COLUMNS" :key="c.key"
              class="cursor-pointer select-none whitespace-nowrap px-3 py-2 hover:text-slate-800"
              :class="c.num && 'text-center'" @click="sortBy(c.key)"
            >
              {{ c.label }}<span v-if="sortKey === c.key">{{ sortDir < 0 ? ' ↓' : ' ↑' }}</span>
            </th>
            <th class="px-3 py-2">Рівень</th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="r in shown" :key="r.id"
            class="border-b border-slate-100 last:border-0 hover:bg-slate-50"
            :class="highlight.includes(r.id) && 'bg-amber-50'"
          >
            <td class="px-3 py-2 font-medium">
              <RouterLink :to="`/scenarios/${r.id}`" class="hover:text-blue-700 hover:underline">{{ r.asset }}</RouterLink>
            </td>
            <td class="px-3 py-2">{{ r.threat }}</td>
            <td class="px-3 py-2 text-slate-500">{{ r.vulnerability }}</td>
            <td class="px-3 py-2 text-center">{{ fmt(value(r, 'matrixScore')) }}</td>
            <td class="px-3 py-2 text-center text-slate-500">{{ pct(value(r, 'likelihood')) }}</td>
            <td class="px-3 py-2 text-center">{{ fmt(value(r, 'combinedScore')) }}</td>
            <td class="px-3 py-2 text-center font-semibold">{{ fmt(r.score) }}</td>
            <td class="px-3 py-2 text-center">
              <span v-if="r.residual != null" class="font-medium" :style="{ color: levelByScore(r.residual).color }">{{ fmt(r.residual) }}</span>
              <span v-else>—</span>
            </td>
            <td class="px-3 py-2 text-center text-xs text-slate-500" :title="`впроваджено ${r.measuresImplemented}, заплановано ${r.measuresPlanned}`">
              {{ r.measuresImplemented }}<span class="text-slate-300"> / {{ r.measuresPlanned }}</span>
            </td>
            <td class="px-3 py-2"><LevelBadge :level="r.level ?? ''" /></td>
          </tr>
          <tr v-if="!shown.length">
            <td :colspan="COLUMNS.length + 1" class="px-3 py-6 text-center text-slate-400">Сценаріїв не знайдено</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>
