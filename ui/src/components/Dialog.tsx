import { useEffect, type ReactNode } from 'react'

// Dialog — a minimal accessible modal (role=dialog, aria-modal, Escape + backdrop to
// close). Pass a no-op onClose to make dismissal deliberate (e.g. the one-time-secret
// modal gated behind an acknowledgement). A full focus-trap / Radix-ization is a later
// UI increment; this covers UI-1's confirm + form + secret dialogs.
export function Dialog({
  open,
  onClose,
  title,
  children,
  footer,
}: {
  open: boolean
  onClose: () => void
  title: string
  children: ReactNode
  footer?: ReactNode
}) {
  useEffect(() => {
    if (!open) return
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [open, onClose])

  if (!open) return null
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4" role="dialog" aria-modal="true" aria-label={title}>
      <div className="absolute inset-0 bg-black/60" onClick={onClose} aria-hidden />
      <div className="relative z-10 flex w-full max-w-md flex-col rounded-md border border-edge bg-mesh-1">
        <div className="border-b border-edge px-4 py-3 font-semibold text-ink">{title}</div>
        <div className="px-4 py-4">{children}</div>
        {footer && <div className="flex justify-end gap-2 border-t border-edge px-4 py-3">{footer}</div>}
      </div>
    </div>
  )
}
