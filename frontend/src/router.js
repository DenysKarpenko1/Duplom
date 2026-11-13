import { createRouter, createWebHistory } from 'vue-router'
import Dashboard from './pages/Dashboard.vue'

export default createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', name: 'dashboard', component: Dashboard },
    // Решта сторінок завантажується відкладено
    { path: '/scenarios', name: 'scenarios', component: () => import('./pages/Scenarios.vue') },
    { path: '/scenarios/:id', name: 'scenario', component: () => import('./pages/ScenarioDetail.vue') },
    { path: '/catalog', name: 'catalog', component: () => import('./pages/Catalog.vue') },
    { path: '/methodology', name: 'methodology', component: () => import('./pages/Methodology.vue') },
    { path: '/data', name: 'data', component: () => import('./pages/DataEntry.vue') },
  ],
})
