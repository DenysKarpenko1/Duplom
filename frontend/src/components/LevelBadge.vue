<script setup>
import { computed } from 'vue'
import { levelByName } from '../levels'

// Кольорова позначка рівня ризику
const props = defineProps({ level: { type: String, default: '' } })
const style = computed(() => levelByName(props.level).badge)
</script>

<template>
  <span v-if="level" class="inline-block whitespace-nowrap rounded-full px-2.5 py-0.5 text-xs font-medium" :class="style">
    {{ level }}
  </span>
  <span v-else class="text-xs text-slate-400">не оцінено</span>
</template>
