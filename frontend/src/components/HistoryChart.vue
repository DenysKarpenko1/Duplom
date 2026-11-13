<script setup>
import { useChart, saveAsImage } from '../composables/useChart'
import { METHODS } from '../levels'

// Динаміка показників за історією оцінювань (обидва методи)
const props = defineProps({ history: { type: Object, required: true } })

function option() {
  const days = [...new Set(Object.values(props.history).flat().map((h) => h.day))].sort()
  const series = []
  for (const [m, meta] of Object.entries(METHODS)) {
    const byDay = new Map(props.history[m].map((h) => [h.day, h]))
    // стан реєстру переноситься на дати, коли цим методом не оцінювали
    let last = null
    const pick = (key) => days.map((d) => { last = byDay.get(d) ?? last; return last ? +last[key].toFixed(2) : null })
    series.push({ name: `${meta.label}: середній ризик`, type: 'line', smooth: true, symbolSize: 6, data: pick('average'), itemStyle: { color: meta.color } })
    last = null
    series.push({ name: `${meta.label}: залишковий`, type: 'line', smooth: true, symbolSize: 4, lineStyle: { type: 'dashed' }, data: pick('residual'), itemStyle: { color: meta.color } })
    last = null
    series.push({ name: `${meta.label}: критичних`, type: 'bar', yAxisIndex: 1, barMaxWidth: 14, data: pick('critical'), itemStyle: { color: meta.color, opacity: 0.25 } })
  }
  return {
    toolbox: saveAsImage,
    tooltip: { trigger: 'axis' },
    legend: { bottom: 34, left: 'center', itemGap: 12, textStyle: { fontSize: 11 } },
    grid: { left: 48, right: 48, top: 40, bottom: 110 },
    dataZoom: [{ type: 'inside' }, { type: 'slider', height: 14, bottom: 6 }],
    xAxis: { type: 'category', data: days, boundaryGap: true },
    yAxis: [
      { type: 'value', name: 'Бал ризику', min: 0, max: 25 },
      { type: 'value', name: 'Критичних', minInterval: 1, splitLine: { show: false } },
    ],
    series,
  }
}

const el = useChart(option, () => props.history)
</script>

<template>
  <div ref="el" class="h-[420px] w-full"></div>
</template>
