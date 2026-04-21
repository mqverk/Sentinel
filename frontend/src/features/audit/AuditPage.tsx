import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { listAuditLogs } from "@/api/sentinel";
import { Card, CardBody, CardHeader } from "@/components/ui/Card";
import { Input } from "@/components/ui/Input";
import { Pill } from "@/components/ui/Pill";

export function AuditPage() {
  const [query, setQuery] = useState("");
  const logs = useQuery({ queryKey: ["audit", query], queryFn: () => listAuditLogs(query, 300) });

  const parsed = useMemo(
    () =>
      (logs.data ?? []).map((entry) => {
        let details: Record<string, unknown> = {};
        try {
          details = JSON.parse(entry.detailsJson) as Record<string, unknown>;
        } catch {
          details = { raw: entry.detailsJson };
        }
        return { ...entry, details };
      }),
    [logs.data]
  );

  return (
    <div className="space-y-5">
      <header className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold">Audit Logs</h1>
          <p className="text-sm text-mute">Filterable event stream for all authentication and access operations.</p>
        </div>
        <Input
          className="w-full max-w-sm"
          placeholder="Search action, actor, host, ip..."
          value={query}
          onChange={(e) => setQuery(e.target.value)}
        />
      </header>

      <Card>
        <CardHeader>
          <h2 className="font-semibold">Structured Events</h2>
        </CardHeader>
        <CardBody>
          <div className="space-y-2 text-sm">
            {parsed.map((entry) => (
              <article key={entry.id} className="rounded-xl border border-edge bg-panel2 p-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="font-medium">
                    {entry.actorUsername} · {entry.action}
                  </div>
                  <Pill label={entry.outcome} tone={entry.outcome === "allow" ? "ok" : "danger"} />
                </div>
                <div className="mt-1 text-xs text-mute">
                  {new Date(entry.createdAt).toLocaleString()} · {entry.sourceIp}
                </div>
                <pre className="mt-2 overflow-auto rounded bg-bg/70 p-2 font-mono text-xs text-text">
                  {JSON.stringify(entry.details, null, 2)}
                </pre>
              </article>
            ))}
            {parsed.length ? null : <p className="text-mute">No logs found for current filter.</p>}
          </div>
        </CardBody>
      </Card>
    </div>
  );
}
