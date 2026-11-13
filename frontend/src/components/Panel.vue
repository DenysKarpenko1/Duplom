<script setup>
// Біла картка-секція з заголовком
defineProps({ title: { type: String, default: '' }, subtitle: { type: String, default: '' } })
</script>

<template>
  <section class="rounded-xl bg-white p-5 shadow-sm ring-1 ring-slate-200">
    <div v-if="title || $slots.actions" class="mb-3 flex flex-wrap items-start justify-between gap-2">
      <div>
        <h2 class="font-semibold text-slate-900">{{ title }}</h2>
        <p v-if="subtitle" class="text-xs text-slate-500">{{ subtitle }}</p>
      </div>
      <slot name="actions" />
    </div>
    <slot />
  </section>
</template>
