// Small shared formatting helpers (pure where possible; unit-tested).

export function fmtDateTime(iso?: string): string {
  if (!iso) return '—'
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? '—' : d.toLocaleString()
}

// usesLabel renders consumption against a cap; max 0 means unlimited (matches the
// backend's max_uses==0 convention).
export function usesLabel(used: number, max: number): string {
  return max > 0 ? `${used} / ${max}` : `${used} / ∞`
}

// downloadText triggers a client-side file download (no server round-trip) — used so an
// operator can save a one-time join-key secret offline at creation time.
export function downloadText(filename: string, text: string): void {
  const blob = new Blob([text], { type: 'text/plain' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  a.click()
  URL.revokeObjectURL(url)
}
