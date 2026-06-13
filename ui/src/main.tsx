import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import { QueryClient, QueryCache, QueryClientProvider } from '@tanstack/react-query'
import '@fontsource-variable/geist'
import '@fontsource-variable/geist-mono'
import './index.css'
import { App } from './app'
import { isUnauthenticated } from './api/errors'

// A session that expires mid-use surfaces as a 401 on some background query (e.g. the
// 15s fleet-health poll). REMOVE the cached /me (don't just invalidate it): an
// invalidate refetches in the background while /me stays status:'success', so the gate
// would keep painting the authed chrome behind a dead session for one round-trip.
// removeQueries resets /me to pending, so the AuthGate flips to the splash this tick
// and then to login — we never paint stale data behind a dead session. Skip 'me'
// itself to avoid a loop: its own 401 already drives the gate.
let queryClient: QueryClient
const queryCache = new QueryCache({
  onError(error, query) {
    if (isUnauthenticated(error) && query.queryKey[0] !== 'me') {
      queryClient.removeQueries({ queryKey: ['me'] })
    }
  },
})
queryClient = new QueryClient({
  queryCache,
  defaultOptions: {
    queries: { retry: false, refetchOnWindowFocus: false, staleTime: 10_000 },
  },
})

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <App />
      </BrowserRouter>
    </QueryClientProvider>
  </StrictMode>,
)
