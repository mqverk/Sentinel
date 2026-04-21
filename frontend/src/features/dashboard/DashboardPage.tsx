import { useQuery } from "@tanstack/react-query";
import { getDashboardOverview, listSessions } from "@/api/sentinel";
import { Card, CardBody, CardHeader } from "@/components/ui/Card";
import { Pill } from "@/components/ui/Pill";

export function DashboardPage() {
  const overview = useQuery({ queryKey: ["dashboard", "overview"], queryFn: getDashboardOverview });
  const sessions = useQuery({ queryKey: ["sessions", "active"], queryFn: () => listSessions("active") });

  return (
    <div className="space-y-5">
      <header>
        <h1 className="text-2xl font-semibold">Security Dashboard</h1>
        <p className="mt-1 text-sm text-mute">Real-time command center for active ingress and authentication posture.</p>
      </header>

      <div className="grid gap-4 md:grid-cols-3">
        <Stat label="Active Sessions" value={overview.data?.activeSessions ?? 0} tone="ok" />
        <Stat label="Open Alerts (24h)" value={overview.data?.openAlerts ?? 0} tone="warn" />
        <Stat label="Live Session Rows" value={sessions.data?.length ?? 0} tone="default" />
      </div>

      <Card>
        <CardHeader>
          <h2 className="font-semibold">Recent Logins</h2>
        </CardHeader>
        <CardBody>
          <div className="space-y-2 text-sm">
            {(overview.data?.recentLogins ?? []).map((log) => (
              <div key={log.id} className="grid grid-cols-[150px_1fr_auto] items-center gap-2 rounded-lg bg-panel2 px-3 py-2">
                <span className="font-mono text-xs text-mute">{new Date(log.createdAt).toLocaleString()}</span>
                <span>
                  {log.actorUsername} from {log.sourceIp}
                </span>
                <Pill label={log.outcome} tone={log.outcome === "allow" ? "ok" : "danger"} />
              </div>
            ))}
            {overview.data?.recentLogins?.length ? null : <div className="text-mute">No login events captured.</div>}
          </div>
        </CardBody>
      </Card>
    </div>
  );
}

function Stat({ label, value, tone }: { label: string; value: number; tone: "default" | "warn" | "ok" }) {
  return (
    <Card>
      <CardBody className="space-y-2">
        <p className="text-xs uppercase tracking-wide text-mute">{label}</p>
        <div className="flex items-center justify-between">
          <p className="text-3xl font-semibold">{value}</p>
          <Pill label={tone} tone={tone} />
        </div>
      </CardBody>
    </Card>
  );
}
