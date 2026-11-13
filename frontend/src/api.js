// Єдиний клієнт API: базова адреса, JSON та обробка помилок в одному місці
const BASE_URL = import.meta.env.VITE_API_URL ?? '/api'

async function request(path, options = {}) {
  const response = await fetch(BASE_URL + path, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  })
  if (!response.ok) {
    // FastAPI повертає пояснення у полі detail
    let detail = ''
    try {
      const body = await response.json()
      detail = typeof body.detail === 'string' ? body.detail : body.detail?.[0]?.msg ?? ''
    } catch { /* тіло без JSON */ }
    throw new Error(detail || `Помилка сервера (${response.status})`)
  }
  // Відповідь 204 не має тіла
  return response.status === 204 ? null : response.json()
}

export const api = {
  get: (path) => request(path),
  post: (path, body) => request(path, { method: 'POST', body: JSON.stringify(body ?? {}) }),
  put: (path, body) => request(path, { method: 'PUT', body: JSON.stringify(body) }),
  delete: (path) => request(path, { method: 'DELETE' }),
}
