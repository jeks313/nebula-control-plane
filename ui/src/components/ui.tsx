import type { ReactNode } from 'react'

export function cx(...parts: Array<string | false | undefined | null>): string {
  return parts.filter(Boolean).join(' ')
}

// Card — borders-first elevation (a raised surface + hairline, no shadow).
export function Card({ children, className }: { children: ReactNode; className?: string }) {
  return <div className={cx('rounded-md border border-edge bg-mesh-1', className)}>{children}</div>
}

// Page — a titled content region with consistent gutters.
export function Page({ title, subtitle, actions, children }: {
  title: string
  subtitle?: string
  actions?: ReactNode
  children: ReactNode
}) {
  return (
    <div className="mx-auto max-w-[1200px] px-6 py-6">
      <div className="mb-5 flex items-end justify-between gap-4">
        <div>
          <h1 className="text-[20px] font-semibold tracking-[-0.01em] text-ink">{title}</h1>
          {subtitle && <p className="mt-0.5 text-ink-dim">{subtitle}</p>}
        </div>
        {actions}
      </div>
      {children}
    </div>
  )
}

// Loading / error / empty states, kept uniform across screens.
export function StateBlock({ kind, message }: { kind: 'loading' | 'error' | 'empty'; message: string }) {
  const tone = kind === 'error' ? 'text-danger' : 'text-ink-faint'
  return (
    <div className={cx('rounded-md border border-edge bg-mesh-1 px-4 py-8 text-center', tone)}>{message}</div>
  )
}
