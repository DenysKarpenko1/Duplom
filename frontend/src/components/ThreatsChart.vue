<script setup>
import { useChart, saveAsImage } from '../composables/useChart'
import { levelByScore } from '../levels'

// Діаграма загроз: поточний і залишковий бал ризику (найгірший сценарій загрози)
const props = defineProps({
  threats: { type: Array, required: true },
  limit: { type: Number, default: 8 },
})

function option() {
  const items = props.threats.slice(0, props.limit).reverse()
  return {
    toolbox: saveAsImage,
    legend: { top: 0, left: 0, data: ['Поточний ризик', 'Залишковий ризик'] },
    grid: { left: 190, right: 40, top: 32, bottom: 24 },
    tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
    xAxis: { type: 'value', min: 0, max: 25, interval: 5 },
    yAxis: {
      type: 'category', data: items.map((r) => r.threat), axisTick: { show: false },
      axisLabel: { width: 180, overflow: 'break', fontSize: 11, lineHeight: 14 },
    },
    series: [
      {
        name: 'Поточний ризик', type: 'bar', barGap: '10%', barWidth: 12,
        data: items.map((r) => ({ value: r.score, itemStyle: { color: levelByScore(r.score).color, borderRadius: [0, 4, 4, 0] } })),
        label: { show: true, position: 'right', fontSize: 10, formatter: ({ value }) => Number(value).toFixed(1).replace('.0', '') },
      },
      {
        name: 'Залишковий ризик', type: 'bar', barWidth: 12,
        data: items.map((r) => r.residual ?? r.score),
        itemStyle: { color: '#94a3b8', borderRadius: [0, 4, 4, 0] },
        label: { show: true, position: 'right', fontSize: 10, color: '#64748b', formatter: ({ value }) => Number(value).toFixed(1).replace('.0', '') },
      },
    ],
  }
}

const el = useChart(option, () => [props.threats, props.limit])
</script>

<template>
  <div ref="el" class="h-96 w-full"></div>
</template>
