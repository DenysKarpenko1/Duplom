<script setup>
// Каркас застосунку: бічна навігація та область сторінки
const links = [
  { to: '/', label: 'Дашборд' },
  { to: '/scenarios', label: 'Сценарії ризику' },
  { to: '/catalog', label: 'Довідники' },
  { to: '/comparison', label: 'Порівняння моделей' },
  { to: '/methodology', label: 'Методика' },
  { to: '/data', label: 'Швидке введення' },
]
</script>

<template>
  <div class="flex min-h-screen">
    <aside class="flex w-60 shrink-0 flex-col bg-slate-900 text-slate-300">
      <div class="border-b border-slate-700 px-6 py-5">
        <p class="text-lg font-semibold text-white">RiskMonitor</p>
        <p class="text-xs text-slate-400">Оцінка ризиків ІБ</p>
      </div>
      <nav class="flex flex-col gap-1 p-3">
        <RouterLink
          v-for="link in links"
          :key="link.to"
          :to="link.to"
          class="rounded-lg px-3 py-2 text-sm transition hover:bg-slate-800 hover:text-white"
          exact-active-class="bg-slate-800 font-medium text-white"
          :active-class="link.to === '/' ? '' : 'bg-slate-800 font-medium text-white'"
        >
          {{ link.label }}
        </RouterLink>
      </nav>
      <p class="mt-auto px-6 py-4 text-xs text-slate-500">ISO/IEC 27005 · NIST SP 800-30</p>
    </aside>

    <main class="min-w-0 flex-1 p-8">
      <RouterView />
    </main>
  </div>
</template>
