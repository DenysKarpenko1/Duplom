<script setup>
import { computed, onMounted, reactive, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useCatalogStore } from '../stores/catalog'
import { MEASURE_TYPES, fmt, pct } from '../levels'
import Panel from '../components/Panel.vue'

// Довідники: ІТ-активи, загрози, вразливості, заходи захисту (з зв'язками M:N)
const store = useCatalogStore()
const route = useRoute()
const router = useRouter()
onMounted(() => store.fetchAll())


// Опис кожного довідника: поля форми та колонки таблиці
const TABS = {
  assets: {
    label: 'ІТ-активи',
    fields: [
      { key: 'name', label: 'Назва', type: 'text', required: true },
      { key: 'category_id', label: 'Категорія', type: 'select', options: () => store.items.assetCategories },
      { key: 'owner', label: 'Власник', type: 'text' },
      { key: 'confidentiality', label: 'Конфіденційність (C)', type: 'scale', default: 3 },
      { key: 'integrity', label: 'Цілісність (I)', type: 'scale', default: 3 },
      { key: 'availability', label: 'Доступність (A)', type: 'scale', default: 3 },
      { key: 'vulnerability_ids', label: 'Наявні вразливості', type: 'multi', options: () => store.items.vulnerabilities },
      { key: 'description', label: 'Опис', type: 'textarea' },
    ],
    columns: [
      ['Назва', (x) => x.name],
      ['Категорія', (x) => x.category?.name ?? '—'],
      ['Власник', (x) => x.owner ?? '—'],
      ['C / I / A', (x) => `${x.confidentiality} / ${x.integrity} / ${x.availability}`],
      ['Вразливості', (x) => x.vulnerabilities.length],
    ],
  },
  threats: {
    label: 'Загрози',
    fields: [
      { key: 'name', label: 'Назва', type: 'text', required: true },
      { key: 'category_id', label: 'Джерело загрози (NIST)', type: 'select', options: () => store.items.threatCategories },
      { key: 'base_likelihood', label: 'Базова ймовірність ініціювання', type: 'scale', default: 3 },
      { key: 'vulnerability_ids', label: 'Вразливості, які експлуатує', type: 'multi', options: () => store.items.vulnerabilities },
      { key: 'description', label: 'Опис', type: 'textarea' },
    ],
    columns: [
      ['Назва', (x) => x.name],
      ['Джерело', (x) => x.category?.name ?? '—'],
      ['Ймовірність', (x) => x.base_likelihood],
      ['Вразливості', (x) => x.vulnerabilities.map((v) => v.name).join('; ') || '—'],
    ],
  },
  vulnerabilities: {
    label: 'Вразливості',
    fields: [
      { key: 'name', label: 'Назва', type: 'text', required: true },
      { key: 'cve_id', label: 'Ідентифікатор CVE', type: 'text' },
      { key: 'cvss_score', label: 'Бал CVSS (0–10)', type: 'number', min: 0, max: 10, step: 0.1 },
      { key: 'severity', label: 'Критичність', type: 'scale', default: 3 },
      { key: 'description', label: 'Опис', type: 'textarea' },
    ],
    columns: [
      ['Назва', (x) => x.name],
      ['CVE', (x) => x.cve_id ?? '—'],
      ['CVSS', (x) => fmt(x.cvss_score, 1)],
      ['Критичність', (x) => x.severity],
      ['Загрози', (x) => x.threats.length],
      ['Активи', (x) => x.assets.length],
      ['Заходи', (x) => x.measures.map((m) => m.name).join('; ') || '—'],
    ],
  },
  measures: {
    label: 'Заходи захисту',
    fields: [
      { key: 'name', label: 'Назва', type: 'text', required: true },
      { key: 'control_ref', label: 'Контроль (ISO 27001 / NIST 800-53)', type: 'text' },
      { key: 'measure_type', label: 'Тип', type: 'enum', options: MEASURE_TYPES, default: 'preventive' },
      { key: 'effectiveness', label: 'Ефективність (0–1)', type: 'number', min: 0, max: 1, step: 0.05, default: 0.5 },
      { key: 'cost', label: 'Вартість, грн', type: 'number', min: 0, step: 100 },
      { key: 'vulnerability_ids', label: 'Закриває вразливості', type: 'multi', options: () => store.items.vulnerabilities },
      { key: 'description', label: 'Опис', type: 'textarea' },
    ],
    columns: [
      ['Назва', (x) => x.name],
      ['Контроль', (x) => x.control_ref ?? '—'],
      ['Тип', (x) => MEASURE_TYPES[x.measure_type]],
      ['Ефективність', (x) => pct(x.effectiveness, 0)],
      ['Вартість', (x) => (x.cost != null ? `${fmt(x.cost, 0)} грн` : '—')],
      ['Закриває', (x) => x.vulnerabilities.map((v) => v.name).join('; ') || '—'],
    ],
  },
}

const tab = ref(TABS[route.query.tab] ? route.query.tab : 'assets')
watch(tab, (t) => router.replace({ query: { tab: t } }))
const config = computed(() => TABS[tab.value])

// --- форма створення / редагування ---
const editingId = ref(null)
const formOpen = ref(false)
const form = reactive({})
const message = ref('')
const failed = ref(false)

function blank() {
  for (const k of Object.keys(form)) delete form[k]
  for (const f of config.value.fields) form[f.key] = f.type === 'multi' ? [] : (f.default ?? (f.type === 'select' ? null : ''))
}

function openCreate() {
  editingId.value = null
  blank()
  formOpen.value = true
  message.value = ''
}

function openEdit(item) {
  editingId.value = item.id
  blank()
  for (const f of config.value.fields) {
    if (f.type === 'multi') form[f.key] = item.vulnerabilities.map((v) => v.id)
    else if (f.key === 'category_id') form[f.key] = item.category?.id ?? null
    else form[f.key] = item[f.key] ?? (f.default ?? '')
  }
  formOpen.value = true
  message.value = ''
}

watch(tab, () => { formOpen.value = false })

async function submit() {
  const payload = {}
  for (const f of config.value.fields) {
    let v = form[f.key]
    if (v === '' || v === undefined) v = null
    if (f.type === 'number' && v != null) v = Number(v)
    payload[f.key] = v
  }
  try {
    await store.save(tab.value, payload, editingId.value)
    failed.value = false
    message.value = editingId.value ? 'Зміни збережено.' : 'Запис додано.'
    formOpen.value = false
  } catch (e) {
    failed.value = true
    message.value = e.message
  }
}

async function remove(item) {
  try {
    await store.remove(tab.value, item.id)
    failed.value = false
    message.value = `«${item.name}» видалено.`
  } catch (e) {
    failed.value = true
    message.value = e.message.includes('цілісності')
      ? 'Запис використовується в сценаріях ризику, тому його не можна видалити.'
      : e.message
  }
}

const input = 'mt-1 w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm outline-none focus:border-slate-500'
</script>

<template>
  <div class="space-y-6">
    <header class="flex flex-wrap items-end justify-between gap-4">
      <div>
        <h1 class="text-2xl font-semibold text-slate-900">Довідники</h1>
        <p class="text-sm text-slate-500">ІТ-активи, загрози, вразливості та заходи захисту з їхніми зв'язками</p>
      </div>
      <button class="rounded-lg bg-slate-900 px-4 py-2 text-sm font-medium text-white hover:bg-slate-700" @click="openCreate">
        + Додати
      </button>
    </header>

    <p v-if="store.error" class="rounded-lg bg-red-50 px-4 py-3 text-sm text-red-700">{{ store.error }}</p>

    <nav class="flex flex-wrap gap-2">
      <button
        v-for="(t, key) in TABS" :key="key"
        class="rounded-lg px-4 py-2 text-sm"
        :class="tab === key ? 'bg-slate-900 text-white' : 'bg-white text-slate-600 ring-1 ring-slate-200 hover:bg-slate-50'"
        @click="tab = key"
      >
        {{ t.label }} <span class="ml-1 text-xs opacity-60">{{ store.items[key].length }}</span>
      </button>
    </nav>

    <p v-if="message" class="text-sm" :class="failed ? 'text-red-600' : 'text-green-700'">{{ message }}</p>

    <Panel v-if="formOpen" :title="editingId ? 'Редагування' : `Новий запис: ${config.label.toLowerCase()}`">
      <form class="grid gap-4 md:grid-cols-2 xl:grid-cols-3" @submit.prevent="submit">
        <label
          v-for="f in config.fields" :key="f.key" class="block text-sm"
          :class="(f.type === 'multi' || f.type === 'textarea') && 'md:col-span-2 xl:col-span-3'"
        >
          <span class="font-medium text-slate-700">{{ f.label }}</span>
          <input v-if="f.type === 'text'" v-model.trim="form[f.key]" :required="f.required" :class="input" />
          <input
            v-else-if="f.type === 'number'" v-model="form[f.key]" type="number"
            :min="f.min" :max="f.max" :step="f.step" :class="input"
          />
          <textarea v-else-if="f.type === 'textarea'" v-model="form[f.key]" rows="2" :class="input" />
          <select v-else-if="f.type === 'select'" v-model="form[f.key]" :class="input">
            <option :value="null">— не вказано —</option>
            <option v-for="o in f.options()" :key="o.id" :value="o.id">{{ o.name }}</option>
          </select>
          <select v-else-if="f.type === 'enum'" v-model="form[f.key]" :class="input">
            <option v-for="(label, v) in f.options" :key="v" :value="v">{{ label }}</option>
          </select>
          <div v-else-if="f.type === 'scale'" class="mt-1 flex gap-1">
            <button
              v-for="n in 5" :key="n" type="button"
              class="h-9 flex-1 rounded-md text-sm font-medium"
              :class="form[f.key] === n ? 'bg-slate-900 text-white' : 'bg-slate-100 text-slate-600 hover:bg-slate-200'"
              @click="form[f.key] = n"
            >{{ n }}</button>
          </div>
          <div v-else-if="f.type === 'multi'" class="mt-1 flex max-h-44 flex-wrap gap-2 overflow-y-auto rounded-lg border border-slate-200 p-2">
            <label
              v-for="o in f.options()" :key="o.id"
              class="flex cursor-pointer items-center gap-1.5 rounded-md px-2 py-1 text-xs"
              :class="form[f.key].includes(o.id) ? 'bg-blue-100 text-blue-900' : 'bg-slate-50 text-slate-600'"
            >
              <input v-model="form[f.key]" type="checkbox" :value="o.id" class="accent-blue-600" />{{ o.name }}
            </label>
            <span v-if="!f.options().length" class="text-xs text-slate-400">Спершу додайте вразливості</span>
          </div>
        </label>
        <div class="flex items-center gap-3 md:col-span-2 xl:col-span-3">
          <button type="submit" class="rounded-lg bg-slate-900 px-5 py-2 text-sm font-medium text-white hover:bg-slate-700">Зберегти</button>
          <button type="button" class="text-sm text-slate-500 hover:text-slate-900" @click="formOpen = false">Скасувати</button>
        </div>
      </form>
    </Panel>

    <Panel>
      <div class="overflow-x-auto">
        <table class="w-full text-left text-sm">
          <thead class="border-b border-slate-200 text-xs uppercase text-slate-500">
            <tr>
              <th v-for="[label] in config.columns" :key="label" class="px-3 py-2">{{ label }}</th>
              <th class="px-3 py-2"></th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="item in store.items[tab]" :key="item.id" class="border-b border-slate-100 last:border-0 hover:bg-slate-50">
              <td v-for="([label, get], i) in config.columns" :key="label" class="px-3 py-2" :class="i === 0 ? 'font-medium' : 'text-slate-600'">
                {{ get(item) }}
              </td>
              <td class="whitespace-nowrap px-3 py-2 text-right text-xs">
                <button class="text-slate-500 hover:text-blue-700" @click="openEdit(item)">Змінити</button>
                <button class="ml-3 text-slate-400 hover:text-red-600" @click="remove(item)">Видалити</button>
              </td>
            </tr>
            <tr v-if="!store.items[tab].length">
              <td :colspan="config.columns.length + 1" class="px-3 py-6 text-center text-slate-400">Записів ще немає</td>
            </tr>
          </tbody>
        </table>
      </div>
    </Panel>
  </div>
</template>
