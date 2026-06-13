import type { ButtonHTMLAttributes, ReactNode } from 'react'
import { errorMessage } from '../api/errors'

export function cx(...parts: Array<string | false | undefined | null>): string {
  return parts.filter(Boolean).join(' ')
}

// Button — one consistent control. variant carries intent: primary = the affirmative
// action (accent), danger = destructive/veto (amber-red), default/ghost = neutral.
type ButtonVariant = 'default' | 'primary' | 'danger' | 'ghost'
const BUTTON_VARIANTS: Record<ButtonVariant, string> = {
  default: 'border border-edge text-ink-dim hover:bg-mesh-2 hover:text-ink',
  primary: 'border border-permit/60 bg-permit/15 text-permit hover:bg-permit/25',
  danger: 'border border-danger/60 bg-danger/10 text-danger hover:bg-danger/20',
  ghost: 'text-ink-dim hover:bg-mesh-2 hover:text-ink',
}
export function Button({
  variant = 'default',
  className,
  ...props
}: { variant?: ButtonVariant } & ButtonHTMLAttributes<HTMLButtonElement>) {
  return (
    <button
      className={cx(
        'rounded-[6px] px-3 py-1.5 text-[13px] transition-colors disabled:cursor-not-allowed disabled:opacity-50',
        BUTTON_VARIANTS[variant],
        className,
      )}
      {...props}
    />
  )
}

// Chip — a small inline tag (groups, flags, status) with a tone.
type ChipTone = 'default' | 'warn' | 'permit' | 'danger'
const CHIP_TONES: Record<ChipTone, string> = {
  default: 'border-edge text-ink-dim',
  warn: 'border-warn/40 text-warn',
  permit: 'border-permit/40 text-permit',
  danger: 'border-danger/40 text-danger',
}
export function Chip({ children, tone = 'default' }: { children: ReactNode; tone?: ChipTone }) {
  return (
    <span className={cx('inline-block rounded-[4px] border px-1.5 py-0.5 text-[11px]', CHIP_TONES[tone])}>
      {children}
    </span>
  )
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

// ErrorState renders a query failure using the server's problem+json message (title/
// detail) when present, falling back to a screen-appropriate line for opaque network
// failures. Use this instead of hardcoding error copy — it surfaces server reasons
// (e.g. a 403 "requires permission: …") honestly.
export function ErrorState({ error, fallback }: { error: unknown; fallback?: string }) {
  return <StateBlock kind="error" message={errorMessage(error, fallback)} />
}
