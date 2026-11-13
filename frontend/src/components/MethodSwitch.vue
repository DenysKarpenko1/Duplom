<script setup>
import { METHODS } from '../levels'

// Перемикач методу оцінювання, за яким будуються дашборди
const model = defineModel({ type: String, required: true })
</script>

<template>
  <div class="inline-flex rounded-lg bg-white p-1 shadow-sm ring-1 ring-slate-200">
    <button
      v-for="(m, key) in METHODS" :key="key" type="button"
      class="rounded-md px-3 py-1.5 text-sm transition"
      :class="model === key ? 'bg-slate-900 text-white' : 'text-slate-600 hover:bg-slate-100'"
      @click="model = key"
    >
      {{ m.label }}
    </button>
  </div>
</template>
