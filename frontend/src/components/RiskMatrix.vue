<script setup>
import { LEVELS, levelByScore } from '../levels'

// Матриця ризиків 5×5: рядки — імовірність (згори 5), стовпці — вплив (зліва 1)
defineProps({
  // matrix[p - 1][i - 1] — масив ризиків у клітинці
  matrix: { type: Array, required: true },
})

const probabilities = [5, 4, 3, 2, 1]
const impacts = [1, 2, 3, 4, 5]

// Підказка з переліком ризиків клітинки
const tooltip = (risks) => risks.map((r) => `${r.asset}: ${r.threat}`).join('\n')
</script>

<template>
  <div>
    <div class="flex">
      <!-- підпис осі Y -->
      <div class="flex w-6 items-center justify-center">
        <span class="-rotate-90 whitespace-nowrap text-xs font-medium text-slate-500">Імовірність</span>
      </div>

      <div class="flex-1">
        <div v-for="p in probabilities" :key="p" class="mb-1 flex items-stretch gap-1">
          <div class="flex w-6 items-center justify-center text-sm text-slate-500">{{ p }}</div>
          <div
            v-for="i in impacts"
            :key="i"
            class="flex h-16 flex-1 items-center justify-center rounded-md text-white"
            :class="[levelByScore(p * i).cell, matrix[p - 1][i - 1].length ? '' : 'opacity-40']"
            :title="tooltip(matrix[p - 1][i - 1])"
          >
            <span v-if="matrix[p - 1][i - 1].length" class="text-xl font-bold drop-shadow">
              {{ matrix[p - 1][i - 1].length }}
            </span>
          </div>
        </div>

        <!-- підписи осі X -->
        <div class="flex gap-1">
          <div class="w-6"></div>
          <div v-for="i in impacts" :key="i" class="flex-1 text-center text-sm text-slate-500">{{ i }}</div>
        </div>
        <p class="mt-1 text-center text-xs font-medium text-slate-500">Вплив</p>
      </div>
    </div>

    <!-- легенда -->
    <div class="mt-4 flex flex-wrap justify-center gap-4">
      <div v-for="level in LEVELS" :key="level.name" class="flex items-center gap-1.5 text-xs text-slate-600">
        <span class="h-3 w-3 rounded-sm" :class="level.cell"></span>{{ level.name }}
      </div>
    </div>
  </div>
</template>
