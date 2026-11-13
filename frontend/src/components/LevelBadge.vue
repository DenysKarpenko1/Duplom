<script setup>
import { computed } from 'vue'
import { levelByName } from '../levels'

// Кольорова позначка рівня ризику
const props = defineProps({ level: { type: String, required: true } })
const style = computed(() => levelByName(props.level).badge)
</script>

<template>
  <span class="inline-block rounded-full px-2.5 py-0.5 text-xs font-medium" :class="style">
    {{ level }}
  </span>
</template>
