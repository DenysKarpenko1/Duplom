// Оформлення рівнів ризику; межі балів збігаються з математичним ядром на сервері
export const LEVELS = [
  { name: 'Низький', max: 4, color: '#22c55e', cell: 'bg-green-500', badge: 'bg-green-100 text-green-800' },
  { name: 'Середній', max: 9, color: '#eab308', cell: 'bg-yellow-400', badge: 'bg-yellow-100 text-yellow-800' },
  { name: 'Високий', max: 14, color: '#f97316', cell: 'bg-orange-500', badge: 'bg-orange-100 text-orange-800' },
  { name: 'Критичний', max: 25, color: '#dc2626', cell: 'bg-red-600', badge: 'bg-red-100 text-red-800' },
]

// Рівень за балом; використовується лише для розфарбовування клітинок матриці
export const levelByScore = (score) => LEVELS.find((l) => score <= l.max) ?? LEVELS.at(-1)

export const levelByName = (name) => LEVELS.find((l) => l.name === name) ?? LEVELS[0]

// Словесні позначки шкали 1..5 для ймовірності та для впливу
export const PROBABILITY_LABELS = ['Дуже низька', 'Низька', 'Середня', 'Висока', 'Дуже висока']
export const IMPACT_LABELS = ['Дуже низький', 'Низький', 'Середній', 'Високий', 'Дуже високий']
