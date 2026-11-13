<script setup>
import { computed, onMounted, ref } from 'vue'
import { useScenarioStore } from '../stores/scenarios'
import { METHODS, fmt } from '../levels'
import StatCard from '../components/StatCard.vue'
import Panel from '../components/Panel.vue'
import MethodSwitch from '../components/MethodSwitch.vue'
import RiskHeatmap from '../components/RiskHeatmap.vue'
import ThreatsChart from '../components/ThreatsChart.vue'
import LevelPie from '../components/LevelPie.vue'
import HistoryChart from '../components/HistoryChart.vue'
import RiskRegister from '../components/RiskRegister.vue'

// Аналітичний дашборд: показники, матриця 5×5, діаграми загроз і рівнів, динаміка, реєстр
const store = useScenarioStore()
onMounted(store.fetchScenarios)

const selected = ref([])
const reduction = computed(() => {
  const { average, averageResidual } = store.stats
  return average ? (1 - averageResidual / average) * 100 : 0
})
</script>

<template>
  <div class="space-y-6">
    <header class="flex flex-wrap items-end justify-between gap-4">
      <div>
        <h1 class="text-2xl font-semibold text-slate-900">Панель моніторингу ризиків</h1>
        <p class="text-sm text-slate-500">
          Поточний стан ризиків ІБ підприємства · {{ METHODS[store.method].short }}
        </p>
      </div>
      <MethodSwitch v-model="store.method" />
    </header>

    <p v-if="store.error" class="rounded-lg bg-red-50 px-4 py-3 text-sm text-red-700">{{ store.error }}</p>

    <section class="grid grid-cols-2 gap-4 xl:grid-cols-5">
      <StatCard label="Сценаріїв ризику" :value="store.stats.total" hint="актив · загроза · вразливість" />
      <StatCard label="Критичних" :value="store.stats.critical" hint="бал ризику 15 і вище" accent="text-red-600" />
      <StatCard label="Середній бал" :value="fmt(store.stats.average, 1)" hint="за шкалою 0–25" />
      <StatCard label="Середній залишковий" :value="fmt(store.stats.averageResidual, 1)" hint="з урахуванням заходів" accent="text-green-700" />
      <StatCard label="Зниження ризику" :value="`${fmt(reduction, 1)}%`" hint="завдяки впровадженим заходам" />
    </section>

    <section class="grid gap-6 xl:grid-cols-2">
      <Panel
        title="Матриця ризиків 5×5"
        :subtitle="store.method === 'matrix' ? 'Колір — рівень за балом P×I' : 'Колір — рівень за NIST SP 800-30 Table I-2; натисніть клітинку'"
      >
        <RiskHeatmap :matrix="store.matrix" :method="store.method" @select="(rows) => (selected = rows.map((r) => r.id))" />
      </Panel>
      <Panel title="Найнебезпечніші загрози" subtitle="Найгірший сценарій кожної загрози: поточний і залишковий бал">
        <ThreatsChart :threats="store.threats" />
      </Panel>
    </section>

    <section class="grid gap-6 xl:grid-cols-3">
      <Panel title="Розподіл за рівнями" class="xl:col-span-1">
        <LevelPie :distribution="store.levelDistribution" />
      </Panel>
      <Panel title="Динаміка показників" subtitle="За історією оцінювань обома методами" class="xl:col-span-2">
        <HistoryChart :history="store.history" />
      </Panel>
    </section>

    <Panel title="Реєстр ризиків" subtitle="Натисніть на актив, щоб відкрити сценарій і дерево атак">
      <template #actions>
        <button v-if="selected.length" class="text-xs text-slate-500 hover:text-slate-900" @click="selected = []">
          Зняти виділення ({{ selected.length }})
        </button>
      </template>
      <RiskRegister :rows="store.register" :highlight="selected" />
    </Panel>
  </div>
</template>
