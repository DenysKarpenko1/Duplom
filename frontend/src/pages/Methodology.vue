<script setup>
import { onMounted, ref, watch } from 'vue'
import { api } from '../api'
import { NIST_LEVELS, NIST_UK, fmt, levelByScore } from '../levels'
import Panel from '../components/Panel.vue'
import MembershipChart from '../components/MembershipChart.vue'

// Методика комбінованого методу: функції належності, база правил NIST і «пісочниця» висновку
const model = ref(null)
const likelihood = ref(0.6)
const impact = ref(4)
const result = ref(null)
const error = ref('')

onMounted(async () => {
  try {
    model.value = await api.get('/methodology/fuzzy')
    await infer()
  } catch (e) {
    error.value = 'Не вдалося завантажити параметри методики. Перевірте, чи запущено сервер.'
  }
})

async function infer() {
  result.value = await api.get(`/methodology/fuzzy/infer?likelihood=${likelihood.value}&impact=${impact.value}`)
}
let timer
watch([likelihood, impact], () => { clearTimeout(timer); timer = setTimeout(infer, 120) })

const rule = (l, i) => model.value.rules.find((r) => r.likelihood === l && r.impact === i).risk
const NIST_COLORS = { 'Very Low': '#22c55e', Low: '#84cc16', Moderate: '#eab308', High: '#f97316', 'Very High': '#dc2626' }
</script>

<template>
  <div class="space-y-6">
    <header>
      <h1 class="text-2xl font-semibold text-slate-900">Методика оцінювання</h1>
      <p class="text-sm text-slate-500">Комбінований метод: дерево атак → ймовірність P, нечіткий висновок за NIST SP 800-30 → рівень ризику</p>
    </header>
    <p v-if="error" class="rounded-lg bg-red-50 px-4 py-3 text-sm text-red-700">{{ error }}</p>

    <template v-if="model">
      <section class="grid gap-6 xl:grid-cols-3">
        <Panel><MembershipChart title="Ймовірність реалізації (Likelihood)" :terms="model.likelihood" :range="[0, 1]" :marker="likelihood" axis-name="P" /></Panel>
        <Panel><MembershipChart title="Рівень впливу (Impact)" :terms="model.impact" :range="[1, 5]" :marker="impact" axis-name="I" /></Panel>
        <Panel><MembershipChart title="Рівень ризику (Risk)" :terms="model.risk" :range="[0, 25]" :marker="result?.score ?? null" axis-name="R" /></Panel>
      </section>

      <section class="grid gap-6 xl:grid-cols-2">
        <Panel title="Пісочниця нечіткого висновку" subtitle="Імплікація Ларсена, агрегація max, дефазифікація центроїдом">
          <div class="space-y-4 text-sm">
            <label class="block">Ймовірність P = <b>{{ likelihood }}</b>
              <input v-model.number="likelihood" type="range" min="0" max="1" step="0.01" class="w-full accent-blue-600" />
            </label>
            <label class="block">Вплив I = <b>{{ impact }}</b>
              <input v-model.number="impact" type="range" min="1" max="5" step="0.1" class="w-full accent-blue-600" />
            </label>
            <div v-if="result" class="flex items-center gap-4 rounded-lg bg-slate-50 p-3">
              <span class="text-3xl font-semibold" :style="{ color: levelByScore(result.score).color }">{{ fmt(result.score) }}</span>
              <span>NIST: <b>{{ NIST_UK[result.nist_level] }}</b> ({{ result.nist_level }})<br />
                Система: <b>{{ levelByScore(result.score).name }}</b></span>
            </div>
            <table v-if="result" class="w-full text-xs">
              <thead class="text-slate-500"><tr><th class="text-left">Правило, що спрацювало</th><th>Сила</th></tr></thead>
              <tbody>
                <tr v-for="(r, i) in result.fired_rules" :key="i" class="border-t border-slate-100">
                  <td class="py-1">ЯКЩО P = {{ r.likelihood }} І I = {{ r.impact }}, ТО R = <b>{{ r.risk }}</b></td>
                  <td class="text-center">{{ fmt(r.strength, 3) }}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </Panel>

        <Panel title="База правил (NIST SP 800-30, Table I-2)" subtitle="Рядки — ймовірність, стовпці — вплив">
          <table class="w-full text-center text-xs">
            <thead>
              <tr><th></th><th v-for="i in NIST_LEVELS" :key="i" class="pb-2 text-slate-500">{{ i }}</th></tr>
            </thead>
            <tbody>
              <tr v-for="l in [...NIST_LEVELS].reverse()" :key="l">
                <th class="pr-2 text-right text-slate-500">{{ l }}</th>
                <td v-for="i in NIST_LEVELS" :key="i" class="p-0.5">
                  <div class="rounded-md py-3 font-medium text-white" :style="{ background: NIST_COLORS[rule(l, i)] }">{{ rule(l, i) }}</div>
                </td>
              </tr>
            </tbody>
          </table>
          <p class="mt-3 text-xs text-slate-500">
            Відповідність рівням системи: Very Low, Low → «Низький»; Moderate → «Середній»; High → «Високий»; Very High → «Критичний».
          </p>
        </Panel>
      </section>
    </template>
  </div>
</template>
