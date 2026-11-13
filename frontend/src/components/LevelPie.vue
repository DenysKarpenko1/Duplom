<script setup>
import { useChart, saveAsImage } from '../composables/useChart'
import { LEVELS } from '../levels'

// Розподіл сценаріїв за рівнями: внутрішнє кільце — поточний, зовнішнє — залишковий ризик
const props = defineProps({ distribution: { type: Object, required: true } })

const series = (name, counts, radius) => ({
  name, type: 'pie', radius, avoidLabelOverlap: true,
  label: { show: radius[0] !== '0%' ? true : false, formatter: '{c}', fontWeight: 'bold' },
  data: LEVELS.map((l) => ({ name: l.name, value: counts[l.name] ?? 0, itemStyle: { color: l.color } }))
    .filter((d) => d.value > 0),
})

const el = useChart(() => ({
  toolbox: saveAsImage,
  tooltip: { trigger: 'item', formatter: '{a}<br/>{b}: {c} ({d}%)' },
  legend: { bottom: 0 },
  series: [
    { ...series('Поточний ризик', props.distribution.inherent, ['0%', '42%']), label: { position: 'inside', formatter: '{c}', color: '#fff', fontWeight: 'bold' }, center: ['50%', '45%'] },
    { ...series('Залишковий ризик', props.distribution.residual, ['52%', '68%']), center: ['50%', '45%'], label: { position: 'inside', formatter: '{c}', color: '#fff', fontWeight: 'bold' } },
  ],
}), () => props.distribution)
</script>

<template>
  <div>
    <div ref="el" class="h-80 w-full"></div>
    <p class="text-center text-xs text-slate-400">внутрішнє кільце — поточний ризик, зовнішнє — залишковий</p>
  </div>
</template>
