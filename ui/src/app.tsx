import { Routes, Route, Navigate } from 'react-router-dom'
import { AuthGate } from './components/AuthGate'
import { Shell } from './components/Shell'
import { Dashboard } from './pages/Dashboard'
import { Devices } from './pages/Devices'
import { Audit } from './pages/Audit'

export function App() {
  // AuthGate renders the authed chrome (Shell + routes) only for a live session;
  // otherwise it owns the screen (login / loading / Core-unreachable).
  return (
    <AuthGate>
      <Shell>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/devices" element={<Devices />} />
          <Route path="/audit" element={<Audit />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </Shell>
    </AuthGate>
  )
}
