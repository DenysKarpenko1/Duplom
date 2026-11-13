import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import tailwindcss from '@tailwindcss/vite'

export default defineConfig({
  plugins: [vue(), tailwindcss()],
  // ECharts виносимо в окремий файл, щоб код сторінок кешувався незалежно
  build: { rollupOptions: { output: { manualChunks: { echarts: ['echarts', 'zrender'] } } }, chunkSizeWarningLimit: 700 },
  server: {
    port: 5173,
    // Запити /api під час розробки перенаправляються на сервер FastAPI
    proxy: { '/api': 'http://127.0.0.1:8000' },
  },
})
