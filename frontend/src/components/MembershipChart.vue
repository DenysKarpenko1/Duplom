<script setup>
import { useChart, saveAsImage } from '../composables/useChart'

// Графік функцій належності лінгвістичної змінної (трикутні та трапецієподібні)
const props = defineProps({
  title: { type: String, required: true },
  terms: { type: Object, required: true }, // назва терму -> [a,b,c] | [a,b,c,d] | {type, params}
  range: { type: Array, required: true }, // [min, max]
  marker: { type: Number, default: null }, // поточне значення змінної
  axisName: { type: String, default: '' },
})

const COLORS = ['#22c55e', '#84cc16', '#eab308', '#f97316', '#dc2626']

// Точки ламаної, що описує функцію належності
function points(def) {
  const params = Array.isArray(def) ? def : def.params
  const [lo, hi] = props.range
  if (params.length === 3) {
    const [a, b, c] = params
    return [[lo, 0], [a, 0], [b, 1], [c, 0], [hi, 0]].filter(([x], i, arr) => i === 0 || x >= arr[i - 1][0])
  }
  const [a, b, c, d] = params
  return [[lo, a === b ? 1 : 0], [a, a === b ? 1 : 0], [b, 1], [c, 1], [d, c === d ? 1 : 0], [hi, c === d ? 1 : 0]]
}

const el = useChart(() => ({
  toolbox: saveAsImage,
  title: { text: props.title, left: 0, textStyle: { fontSize: 13 } },
  legend: { top: 24 },
  tooltip: { trigger: 'axis' },
  grid: { left: 40, right: 20, top: 84, bottom: 36 },
  xAxis: { type: 'value', min: props.range[0], max: props.range[1], name: props.axisName, nameLocation: 'middle', nameGap: 24 },
  yAxis: { type: 'value', min: 0, max: 1, name: 'μ' },
  series: Object.entries(props.terms).map(([name, def], i) => ({
    name, type: 'line', data: points(def), symbol: 'none', lineStyle: { width: 2 }, itemStyle: { color: COLORS[i] },
    areaStyle: { opacity: 0.06 },
    ...(i === 0 && props.marker != null
      ? { markLine: { symbol: 'none', data: [{ xAxis: props.marker }], lineStyle: { color: '#0f172a', type: 'dashed' }, label: { formatter: String(props.marker) } } }
      : {}),
  })),
}), () => [props.terms, props.marker])
</script>

<template>
  <div ref="el" class="h-72 w-full"></div>
</template>
