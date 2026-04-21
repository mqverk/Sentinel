import { Navigate, Route, Routes } from "react-router-dom";
import { getAuthToken } from "@/lib/auth";
import { useCurrentUser } from "@/hooks/useAuth";
import { Shell } from "@/components/layout/Shell";
import { LoginPage } from "@/features/access/LoginPage";
import { DashboardPage } from "@/features/dashboard/DashboardPage";
import { AccessPage } from "@/features/access/AccessPage";
import { SessionsPage } from "@/features/sessions/SessionsPage";
import { AuditPage } from "@/features/audit/AuditPage";
import { HostsPage } from "@/features/hosts/HostsPage";
import { SettingsPage } from "@/features/settings/SettingsPage";

function Protected() {
  const token = getAuthToken();
  const me = useCurrentUser();

  if (!token) {
    return <Navigate to="/login" replace />;
  }
  if (me.isLoading) {
    return <div className="p-8 text-sm text-mute">Loading secure context...</div>;
  }
  if (me.isError) {
    return <Navigate to="/login" replace />;
  }

  return <Shell />;
}

export function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route path="/" element={<Protected />}>
        <Route index element={<DashboardPage />} />
        <Route path="access" element={<AccessPage />} />
        <Route path="sessions" element={<SessionsPage />} />
        <Route path="audit" element={<AuditPage />} />
        <Route path="hosts" element={<HostsPage />} />
        <Route path="settings" element={<SettingsPage />} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
