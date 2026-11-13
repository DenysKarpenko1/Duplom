<script setup>
import LevelBadge from './LevelBadge.vue'

// Таблиця ризиків; кнопка видалення показується лише за потреби
defineProps({
  risks: { type: Array, required: true },
  removable: { type: Boolean, default: false },
})
defineEmits(['remove'])
</script>

<template>
  <div class="overflow-x-auto">
    <table class="w-full text-left text-sm">
      <thead class="border-b border-slate-200 text-xs uppercase text-slate-500">
        <tr>
          <th class="px-3 py-2">Актив</th>
          <th class="px-3 py-2">Загроза</th>
          <th class="px-3 py-2">Вразливість</th>
          <th class="px-3 py-2 text-center">Імовірність</th>
          <th class="px-3 py-2 text-center">Вплив</th>
          <th class="px-3 py-2 text-center">Ризик</th>
          <th class="px-3 py-2">Рівень</th>
          <th v-if="removable" class="px-3 py-2"></th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="r in risks" :key="r.id" class="border-b border-slate-100 last:border-0">
          <td class="px-3 py-2 font-medium">{{ r.asset }}</td>
          <td class="px-3 py-2">{{ r.threat }}</td>
          <td class="px-3 py-2 text-slate-500">{{ r.vulnerability }}</td>
          <td class="px-3 py-2 text-center">{{ r.probability }}</td>
          <td class="px-3 py-2 text-center">{{ r.impact }}</td>
          <td class="px-3 py-2 text-center font-semibold">{{ r.score }}</td>
          <td class="px-3 py-2"><LevelBadge :level="r.level" /></td>
          <td v-if="removable" class="px-3 py-2 text-right">
            <button class="text-xs text-slate-400 hover:text-red-600" @click="$emit('remove', r.id)">
              Видалити
            </button>
          </td>
        </tr>
        <tr v-if="!risks.length">
          <td :colspan="removable ? 8 : 7" class="px-3 py-6 text-center text-slate-400">Ризиків ще немає</td>
        </tr>
      </tbody>
    </table>
  </div>
</template>
