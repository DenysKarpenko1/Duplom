<script setup>
import { useChart, saveAsImage } from '../composables/useChart'

// Візуалізація дерева атак (ECharts tree). Червоним виділено найімовірніший сценарій атаки,
// у підписі — обчислена ймовірність без заходів і з урахуванням впроваджених заходів.
const props = defineProps({
  root: { type: Object, required: true },
  showResidual: { type: Boolean, default: true },
})

const p = (x) => `${(x * 100).toFixed(1).replace('.0', '')}%`
// Перенесення довгих назв по словах (ECharts не переносить rich-текст із кількома рядками)
function wrap(text, max = 24) {
  const lines = []
  let line = ''
  for (const word of text.split(' ')) {
    if (line && (line + ' ' + word).length > max) { lines.push(line); line = word } else line = line ? `${line} ${word}` : word
  }
  if (line) lines.push(line)
  return lines
}

const GATE_COLORS = { AND: '#7c3aed', OR: '#0891b2', LEAF: '#475569' }

function convert(node) {
  const color = node.on_critical_path ? '#dc2626' : GATE_COLORS[node.gate]
  const reduced = props.showResidual && node.residual < node.computed - 1e-9
  return {
    name: node.name,
    raw: node,
    value: node.computed,
    symbol: node.gate === 'LEAF' ? 'circle' : 'roundRect',
    symbolSize: node.gate === 'LEAF' ? 12 : [34, 18],
    itemStyle: { color, borderColor: color },
    lineStyle: { color: node.on_critical_path ? '#fca5a5' : '#cbd5e1', width: node.on_critical_path ? 3 : 1.5 },
    label: {
      backgroundColor: 'rgba(255,255,255,0.92)', padding: [2, 4], borderRadius: 4,
      formatter: [
        node.gate === 'LEAF' ? '' : `{gate|${node.gate}}`,
        ...wrap(node.name).map((line) => `{name|${line}}`),
        `{p|P = ${p(node.computed)}}${reduced ? `  {res|→ ${p(node.residual)}}` : ''}`,
      ].filter(Boolean).join('\n'),
      rich: {
        gate: { color: '#fff', backgroundColor: color, padding: [1, 4], borderRadius: 3, fontSize: 10, fontWeight: 'bold' },
        name: { fontSize: 11, color: '#0f172a', lineHeight: 14, align: 'center' },
        p: { fontSize: 11, color: node.on_critical_path ? '#dc2626' : '#334155', fontWeight: 'bold' },
        res: { fontSize: 11, color: '#16a34a', fontWeight: 'bold' },
      },
    },
    children: (node.children ?? []).map(convert),
  }
}

function option() {
  return {
    toolbox: saveAsImage,
    tooltip: {
      formatter: ({ data }) => {
        const n = data.raw
        const lines = [`<b>${n.name}</b>`, `Тип вузла: ${n.gate}`]
        if (n.gate === 'LEAF') lines.push(`Задана ймовірність: ${p(n.probability)}`)
        lines.push(`Обчислена: ${p(n.computed)}`, `З урахуванням заходів: ${p(n.residual)}`)
        if (n.on_critical_path) lines.push('<span style="color:#dc2626">Найімовірніший шлях атаки</span>')
        return lines.join('<br/>')
      },
    },
    series: [{
      type: 'tree',
      data: [convert(props.root)],
      orient: 'TB',
      top: 50, bottom: 110, left: 90, right: 90,
      edgeShape: 'polyline',
      expandAndCollapse: false,
      initialTreeDepth: -1,
      label: { position: 'bottom', distance: 6, align: 'center', verticalAlign: 'top' },
      leaves: { label: { position: 'bottom', align: 'center' } },
      animationDuration: 300,
    }],
  }
}

const el = useChart(option, () => [props.root, props.showResidual])
</script>

<template>
  <div ref="el" class="h-[520px] w-full"></div>
</template>
