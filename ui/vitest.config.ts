import { defineConfig } from 'vitest/config'

// Unit tests cover the pure, security-critical auth logic (problem+json parsing,
// return_to sanitization, CSRF/login URL building) — no DOM needed, so a node
// environment keeps them fast. Component/flow tests (Playwright) come later.
export default defineConfig({
  test: {
    environment: 'node',
    include: ['src/**/*.test.ts'],
  },
})
