// Обгортка над Apache ECharts: ініціалізація, перемальовування та звільнення ресурсів
import { onBeforeUnmount, onMounted, ref, watch } from 'vue'
import * as echarts from 'echarts/core'
import { BarChart, HeatmapChart, LineChart, PieChart, ScatterChart, TreeChart } from 'echarts/charts'
import {
  DataZoomComponent, GridComponent, LegendComponent, MarkAreaComponent, MarkLineComponent,
  TitleComponent, ToolboxComponent, TooltipComponent, VisualMapComponent,
} from 'echarts/components'
import { CanvasRenderer } from 'echarts/renderers'

echarts.use([
  BarChart, HeatmapChart, LineChart, PieChart, ScatterChart, TreeChart,
  DataZoomComponent, GridComponent, LegendComponent, MarkAreaComponent, MarkLineComponent,
  TitleComponent, ToolboxComponent, TooltipComponent, VisualMapComponent, CanvasRenderer,
])

// Кнопка «зберегти як зображення» — для скріншотів у дисертацію
export const saveAsImage = {
  feature: { saveAsImage: { title: 'Зберегти PNG', pixelRatio: 2, backgroundColor: '#fff' } },
  right: 8, top: 0,
}

/**
 * @param {() => object} buildOption функція, що повертає option для ECharts
 * @param {() => any} source реактивне джерело; зміна викликає перемальовування
 */
export function useChart(buildOption, source, { onClick } = {}) {
  const el = ref(null)
  let chart = null
  const render = () => chart?.setOption(buildOption(), { notMerge: true })
  const resize = () => chart?.resize()

  onMounted(() => {
    chart = echarts.init(el.value)
    if (onClick) chart.on('click', onClick)
    render()
    window.addEventListener('resize', resize)
  })
  onBeforeUnmount(() => {
    window.removeEventListener('resize', resize)
    chart?.dispose()
  })
  watch(source, render, { deep: true })
  return el
}
