import { Routes, Route, Navigate } from 'react-router-dom'
import { AuthGate } from './components/AuthGate'
import { Shell } from './components/Shell'
import { Dashboard } from './pages/Dashboard'
import { Enrollments } from './pages/Enrollments'
import { Devices } from './pages/Devices'
import { JoinKeys } from './pages/JoinKeys'
import { CloudTrust } from './pages/CloudTrust'
import { UserTrust } from './pages/UserTrust'
import { IPAM } from './pages/IPAM'
import { Policy } from './pages/Policy'
import { CARotation } from './pages/CARotation'
import { Releases } from './pages/Releases'
import { Approvals } from './pages/Approvals'
import { Audit } from './pages/Audit'
import { Changelog } from './pages/Changelog'

export function App() {
  // AuthGate renders the authed chrome (Shell + routes) only for a live session;
  // otherwise it owns the screen (login / loading / Core-unreachable).
  return (
    <AuthGate>
      <Shell>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/enrollments" element={<Enrollments />} />
          <Route path="/devices" element={<Devices />} />
          <Route path="/joinkeys" element={<JoinKeys />} />
          <Route path="/cloudtrust" element={<CloudTrust />} />
          <Route path="/usertrust" element={<UserTrust />} />
          <Route path="/ipam" element={<IPAM />} />
          <Route path="/policy" element={<Policy />} />
          <Route path="/ca" element={<CARotation />} />
          <Route path="/releases" element={<Releases />} />
          <Route path="/approvals" element={<Approvals />} />
          <Route path="/audit" element={<Audit />} />
          <Route path="/changelog" element={<Changelog />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </Shell>
    </AuthGate>
  )
}
