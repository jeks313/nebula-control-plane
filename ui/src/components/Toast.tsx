import { createContext, useCallback, useContext, useMemo, useRef, useState, type ReactNode } from 'react'
import { cx } from './ui'

type ToastTone = 'info' | 'success' | 'error'
interface Toast {
  id: number
  tone: ToastTone
  message: string
}
interface ToastApi {
  notify: (message: string, tone?: ToastTone) => void
}

const ToastCtx = createContext<ToastApi | null>(null)

// Lightweight, dependency-free toast for mutation feedback (approved / denied / revoked
// / errors). Auto-dismisses; non-blocking. Mutation results — not authority — so a
// transient confirmation is the right affordance.
export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([])
  const idRef = useRef(0)

  const notify = useCallback((message: string, tone: ToastTone = 'info') => {
    const id = ++idRef.current
    setToasts((t) => [...t, { id, tone, message }])
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), 5000)
  }, [])

  const api = useMemo(() => ({ notify }), [notify])
  return (
    <ToastCtx.Provider value={api}>
      {children}
      <div className="fixed bottom-4 right-4 z-[60] flex max-w-sm flex-col gap-2">
        {toasts.map((t) => (
          <div
            key={t.id}
            role="status"
            className={cx('rounded-md border bg-mesh-1 px-3 py-2 text-[13px] shadow-lg', toneClass(t.tone))}
          >
            {t.message}
          </div>
        ))}
      </div>
    </ToastCtx.Provider>
  )
}

function toneClass(tone: ToastTone): string {
  if (tone === 'success') return 'border-permit/50 text-permit'
  if (tone === 'error') return 'border-danger/50 text-danger'
  return 'border-edge text-ink'
}

export function useToast(): ToastApi {
  const ctx = useContext(ToastCtx)
  if (!ctx) throw new Error('useToast must be used within ToastProvider')
  return ctx
}
