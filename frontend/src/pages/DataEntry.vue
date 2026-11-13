<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import { useRiskStore } from '../stores/risks'
import { IMPACT_LABELS, PROBABILITY_LABELS, levelByScore } from '../levels'
import RiskTable from '../components/RiskTable.vue'
import LevelBadge from '../components/LevelBadge.vue'

// Сторінка введення даних: актив, загроза, вразливість та їхні оцінки
const store = useRiskStore()
onMounted(() => { if (!store.total) store.fetchRisks() })

const empty = () => ({ asset: '', threat: '', vulnerability: '', probability: 3, impact: 3 })
const form = reactive(empty())
const saving = ref(false)
const message = ref('')
const failed = ref(false)

// Попередній перегляд; остаточний бал і рівень обчислює сервер
const preview = computed(() => {
  const score = form.probability * form.impact
  return { score, level: levelByScore(score).name }
})

async function submit() {
  saving.value = true
  message.value = ''
  try {
    const created = await store.addRisk({ ...form })
    failed.value = false
    message.value = `Ризик додано: бал ${created.score}, рівень «${created.level}».`
    Object.assign(form, empty())
  } catch (e) {
    failed.value = true
    message.value = 'Не вдалося зберегти ризик. Перевірте, чи запущено сервер.'
  } finally {
    saving.value = false
  }
}
</script>

<template>
  <div class="space-y-6">
    <header>
      <h1 class="text-2xl font-semibold text-slate-900">Введення даних</h1>
      <p class="text-sm text-slate-500">Додавання ІТ-активу, загрози та вразливості з оцінками за шкалою від 1 до 5</p>
    </header>

    <form class="rounded-xl bg-white p-6 shadow-sm ring-1 ring-slate-200" @submit.prevent="submit">
      <div class="grid gap-5 lg:grid-cols-3">
        <label class="block text-sm">
          <span class="font-medium text-slate-700">ІТ-актив</span>
          <input
            v-model.trim="form.asset" required maxlength="200" placeholder="напр., База даних клієнтів"
            class="mt-1 w-full rounded-lg border border-slate-300 px-3 py-2 outline-none focus:border-slate-500"
          />
        </label>
        <label class="block text-sm">
          <span class="font-medium text-slate-700">Загроза</span>
          <input
            v-model.trim="form.threat" required maxlength="200" placeholder="напр., Несанкціонований доступ"
            class="mt-1 w-full rounded-lg border border-slate-300 px-3 py-2 outline-none focus:border-slate-500"
          />
        </label>
        <label class="block text-sm">
          <span class="font-medium text-slate-700">Вразливість</span>
          <input
            v-model.trim="form.vulnerability" required maxlength="300" placeholder="напр., Відсутність оновлень"
            class="mt-1 w-full rounded-lg border border-slate-300 px-3 py-2 outline-none focus:border-slate-500"
          />
        </label>
      </div>

      <div class="mt-5 grid gap-5 lg:grid-cols-3">
        <label class="block text-sm">
          <span class="font-medium text-slate-700">Імовірність виникнення</span>
          <select
            v-model.number="form.probability"
            class="mt-1 w-full rounded-lg border border-slate-300 bg-white px-3 py-2 outline-none focus:border-slate-500"
          >
            <option v-for="n in 5" :key="n" :value="n">{{ n }} – {{ PROBABILITY_LABELS[n - 1] }}</option>
          </select>
        </label>
        <label class="block text-sm">
          <span class="font-medium text-slate-700">Рівень впливу (збитку)</span>
          <select
            v-model.number="form.impact"
            class="mt-1 w-full rounded-lg border border-slate-300 bg-white px-3 py-2 outline-none focus:border-slate-500"
          >
            <option v-for="n in 5" :key="n" :value="n">{{ n }} – {{ IMPACT_LABELS[n - 1] }}</option>
          </select>
        </label>
        <div class="text-sm">
          <span class="font-medium text-slate-700">Попередня оцінка ризику</span>
          <div class="mt-1 flex items-center gap-3 rounded-lg bg-slate-50 px-3 py-2">
            <span class="text-slate-500">{{ form.probability }} × {{ form.impact }} =</span>
            <span class="text-lg font-semibold">{{ preview.score }}</span>
            <LevelBadge :level="preview.level" />
          </div>
        </div>
      </div>

      <div class="mt-6 flex items-center gap-4">
        <button
          type="submit" :disabled="saving"
          class="rounded-lg bg-slate-900 px-5 py-2 text-sm font-medium text-white hover:bg-slate-700 disabled:opacity-50"
        >
          {{ saving ? 'Збереження…' : 'Додати ризик' }}
        </button>
        <p v-if="message" class="text-sm" :class="failed ? 'text-red-600' : 'text-green-700'">{{ message }}</p>
      </div>
    </form>

    <section class="rounded-xl bg-white p-5 shadow-sm ring-1 ring-slate-200">
      <h2 class="mb-2 font-semibold text-slate-900">Зареєстровані ризики</h2>
      <RiskTable :risks="store.risks" removable @remove="store.removeRisk" />
    </section>
  </div>
</template>
