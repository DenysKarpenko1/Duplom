<script setup>
import { useChart, saveAsImage } from '../composables/useChart'
import { LEVELS, levelByScore, levelByName, NIST_LEVELS } from '../levels'

// Динамічна матриця ризиків 5×5 (ECharts heatmap). Колір клітинки — рівень ризику,
// число — кількість сценаріїв у ній.
const props = defineProps({
  matrix: { type: Array, required: true }, // matrix[p - 1][i - 1] -> рядки реєстру
  method: { type: String, default: 'matrix' },
})
const emit = defineEmits(['select'])

// NIST SP 800-30 Table I-2 -> рівні системи (VL, L -> Низький; M -> Середній; H -> Високий; VH -> Критичний)
const NIST_MATRIX = [
  [0, 0, 0, 1, 1], // VL
  [0, 1, 1, 1, 2], // L
  [0, 1, 2, 2, 3], // M
  [0, 1, 2, 3, 4], // H
  [0, 1, 2, 3, 4], // VH
]
const NIST_TO_SYSTEM = ['Низький', 'Низький', 'Середній', 'Високий', 'Критичний']

const cellLevel = (p, i) => (props.method === 'matrix'
  ? levelByScore(p * i)
  : levelByName(NIST_TO_SYSTEM[NIST_MATRIX[p - 1][i - 1]]))

const yLabels = () => (props.method === 'matrix'
  ? ['1', '2', '3', '4', '5']
  : NIST_LEVELS.map((l) => l.replace('Very ', 'V. ')))

function option() {
  const data = []
  for (let p = 1; p <= 5; p++) {
    for (let i = 1; i <= 5; i++) {
      const rows = props.matrix[p - 1][i - 1]
      const levelIndex = LEVELS.indexOf(cellLevel(p, i))
      data.push({
        value: [i - 1, p - 1, rows.length, levelIndex],
        rows,
        itemStyle: { opacity: rows.length ? 1 : 0.28, borderColor: '#fff', borderWidth: 3, borderRadius: 6 },
      })
    }
  }
  return {
    toolbox: saveAsImage,
    // колір клітинки задається рівнем ризику (4-й вимір даних)
    visualMap: {
      show: false, type: 'piecewise', dimension: 3,
      pieces: LEVELS.map((l, idx) => ({ value: idx, color: l.color })),
    },
    grid: { left: 96, right: 16, top: 28, bottom: 48 },
    tooltip: {
      formatter: ({ data }) => {
        const head = `Імовірність ${yLabels()[data.value[1]]}, вплив ${data.value[0] + 1}`
        if (!data.rows.length) return head
        return `${head}<br/>${data.rows.map((r) => `• ${r.asset}: ${r.threat}`).join('<br/>')}`
      },
    },
    xAxis: {
      type: 'category', data: ['1', '2', '3', '4', '5'], name: 'Вплив', nameLocation: 'middle', nameGap: 28,
      splitArea: { show: false }, axisTick: { show: false },
    },
    yAxis: {
      type: 'category', data: yLabels(), name: props.method === 'matrix' ? 'Імовірність' : 'Імовірність (NIST)',
      nameLocation: 'middle', nameGap: 76, axisTick: { show: false },
    },
    series: [{
      type: 'heatmap',
      data,
      label: { show: true, formatter: ({ data: d }) => (d.rows.length || ''), color: '#fff', fontSize: 18, fontWeight: 'bold' },
      emphasis: { itemStyle: { shadowBlur: 8, shadowColor: 'rgba(0,0,0,.3)' } },
    }],
  }
}

const el = useChart(option, () => [props.matrix, props.method], {
  onClick: ({ data }) => data?.rows?.length && emit('select', data.rows),
})
</script>

<template>
  <div ref="el" class="h-96 w-full"></div>
</template>
