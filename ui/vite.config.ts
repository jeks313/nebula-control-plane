import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// The SPA is served same-origin by Harbor Core (go:embed). In `vite dev`, proxy the
// admin API + auth routes to a locally running `harbor admin-api` so the dev server
// and the API look same-origin (cookies + the login redirect work).
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    proxy: {
      '/admin': { target: 'http://localhost:8445', changeOrigin: false },
    },
  },
  // Build straight into the Go embed package so `go build -tags ui ./cmd/harbor`
  // bundles the SPA into the Core binary (single artifact, lockstep versioning).
  build: { outDir: '../internal/adminui/dist', emptyOutDir: true },
})
