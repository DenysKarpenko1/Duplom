// Оформлення рівнів ризику; межі балів збігаються з довідником risk_levels на сервері
export const LEVELS = [
  { name: 'Низький', max: 4, color: '#22c55e', cell: 'bg-green-500', badge: 'bg-green-100 text-green-800' },
  { name: 'Середній', max: 9, color: '#eab308', cell: 'bg-yellow-400', badge: 'bg-yellow-100 text-yellow-800' },
  { name: 'Високий', max: 14, color: '#f97316', cell: 'bg-orange-500', badge: 'bg-orange-100 text-orange-800' },
  { name: 'Критичний', max: 25, color: '#dc2626', cell: 'bg-red-600', badge: 'bg-red-100 text-red-800' },
]

// Рівень за балом; використовується для розфарбовування
export const levelByScore = (score) => LEVELS.find((l) => score <= l.max) ?? LEVELS.at(-1)

export const levelByName = (name) => LEVELS.find((l) => l.name === name) ?? LEVELS[0]

// Словесні позначки шкали 1..5 для ймовірності та для впливу
export const PROBABILITY_LABELS = ['Дуже низька', 'Низька', 'Середня', 'Висока', 'Дуже висока']
export const IMPACT_LABELS = ['Дуже низький', 'Низький', 'Середній', 'Високий', 'Дуже високий']

// П'ять якісних рівнів NIST SP 800-30
export const NIST_LEVELS = ['Very Low', 'Low', 'Moderate', 'High', 'Very High']
export const NIST_UK = {
  'Very Low': 'Дуже низький', Low: 'Низький', Moderate: 'Помірний', High: 'Високий', 'Very High': 'Дуже високий',
}

export const METHODS = {
  matrix: { label: 'Матрична модель', short: 'Матриця P×I', color: '#64748b' },
  combined: { label: 'Комбінований метод', short: 'Дерево атак + нечітка логіка', color: '#2563eb' },
}

export const MEASURE_TYPES = { preventive: 'Превентивний', detective: 'Детективний', corrective: 'Коригувальний' }

// Бал без зайвих нулів: 20 -> «20», 12.5 -> «12,5»
export const fmt = (x, digits = 2) =>
  x == null ? '—' : Number(x).toLocaleString('uk-UA', { maximumFractionDigits: digits })

export const pct = (x, digits = 1) =>
  x == null ? '—' : `${(Number(x) * 100).toLocaleString('uk-UA', { maximumFractionDigits: digits })}%`
