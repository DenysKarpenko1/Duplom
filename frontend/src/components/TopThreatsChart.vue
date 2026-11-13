<script setup>
import { onBeforeUnmount, onMounted, ref, watch } from 'vue'
import * as echarts from 'echarts/core'
import { BarChart } from 'echarts/charts'
import { GridComponent, TooltipComponent } from 'echarts/components'
import { CanvasRenderer } from 'echarts/renderers'
import { levelByName } from '../levels'

echarts.use([BarChart, GridComponent, TooltipComponent, CanvasRenderer])

// Стовпчаста діаграма найнебезпечніших загроз (обгортка над Apache ECharts)
const props = defineProps({
  // ризики, впорядковані за спаданням балу
  threats: { type: Array, required: true },
})

const el = ref(null)
let chart = null

function render() {
  if (!chart) return
  // ECharts малює категорії знизу вгору, тому найнебезпечніша загроза йде останньою
  const items = [...props.threats].reverse()
  chart.setOption({
    // Фіксоване поле зліва під підписи загроз, щоб довгі назви не обрізалися
    grid: { left: 160, right: 40, top: 8, bottom: 24 },
    tooltip: {
      trigger: 'axis',
      axisPointer: { type: 'shadow' },
      formatter: ([p]) => `${p.name}<br/>Актив: ${items[p.dataIndex].asset}<br/>Бал ризику: <b>${p.value}</b>`,
    },
    xAxis: { type: 'value', min: 0, max: 25, interval: 5 },
    yAxis: {
      type: 'category',
      data: items.map((r) => r.threat),
      axisLabel: { width: 150, overflow: 'break', fontSize: 11, lineHeight: 14 },
      axisTick: { show: false },
    },
    series: [{
      type: 'bar',
      barWidth: 22,
      data: items.map((r) => ({
        value: r.score,
        itemStyle: { color: levelByName(r.level).color, borderRadius: [0, 4, 4, 0] },
      })),
      label: { show: true, position: 'right', fontWeight: 'bold' },
    }],
  })
}

const onResize = () => chart?.resize()

onMounted(() => {
  chart = echarts.init(el.value)
  render()
  window.addEventListener('resize', onResize)
})

onBeforeUnmount(() => {
  window.removeEventListener('resize', onResize)
  chart?.dispose()
})

// Перемальовуємо діаграму після будь-якої зміни даних
watch(() => props.threats, render, { deep: true })
</script>

<template>
  <div ref="el" class="h-80 w-full"></div>
</template>
