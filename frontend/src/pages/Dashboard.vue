<script setup>
import { onMounted } from 'vue'
import { useRiskStore } from '../stores/risks'
import StatCard from '../components/StatCard.vue'
import RiskMatrix from '../components/RiskMatrix.vue'
import TopThreatsChart from '../components/TopThreatsChart.vue'
import RiskTable from '../components/RiskTable.vue'

// Головна сторінка: зведені показники, матриця ризиків і топ загроз
const store = useRiskStore()
onMounted(store.fetchRisks)
</script>

<template>
  <div class="space-y-6">
    <header>
      <h1 class="text-2xl font-semibold text-slate-900">Панель моніторингу ризиків</h1>
      <p class="text-sm text-slate-500">Поточний стан ризиків інформаційної безпеки підприємства</p>
    </header>

    <p v-if="store.error" class="rounded-lg bg-red-50 px-4 py-3 text-sm text-red-700">{{ store.error }}</p>

    <!-- кількісні картки -->
    <section class="grid grid-cols-2 gap-4 xl:grid-cols-4">
      <StatCard label="Всього ризиків" :value="store.total" hint="зареєстрованих сценаріїв" />
      <StatCard
        label="Критичних ризиків"
        :value="store.criticalCount"
        hint="бал ризику 15 і вище"
        accent="text-red-600"
      />
      <StatCard
        label="Середній бал ризику"
        :value="store.averageScore.toFixed(1)"
        hint="за шкалою від 1 до 25"
      />
      <StatCard label="Активів під ризиком" :value="store.assetCount" hint="унікальних ІТ-активів" />
    </section>

    <!-- матриця та діаграма -->
    <section class="grid gap-6 xl:grid-cols-2">
      <div class="rounded-xl bg-white p-5 shadow-sm ring-1 ring-slate-200">
        <h2 class="mb-4 font-semibold text-slate-900">Матриця ризиків</h2>
        <RiskMatrix :matrix="store.matrix" />
      </div>
      <div class="rounded-xl bg-white p-5 shadow-sm ring-1 ring-slate-200">
        <h2 class="mb-4 font-semibold text-slate-900">Топ-5 найнебезпечніших загроз</h2>
        <TopThreatsChart :threats="store.topThreats" />
      </div>
    </section>

    <!-- реєстр ризиків -->
    <section class="rounded-xl bg-white p-5 shadow-sm ring-1 ring-slate-200">
      <h2 class="mb-2 font-semibold text-slate-900">Реєстр ризиків</h2>
      <RiskTable :risks="store.risks" />
    </section>
  </div>
</template>
