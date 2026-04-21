import { useQuery } from "@tanstack/react-query";
import { listHosts } from "@/api/sentinel";
import { Card, CardBody, CardHeader } from "@/components/ui/Card";
import { Pill } from "@/components/ui/Pill";

export function HostsPage() {
  const hosts = useQuery({ queryKey: ["hosts"], queryFn: listHosts });

  return (
    <div className="space-y-5">
      <header>
        <h1 className="text-2xl font-semibold">Infrastructure</h1>
        <p className="text-sm text-mute">Managed internal nodes and attached host access policies.</p>
      </header>

      <div className="grid gap-4 lg:grid-cols-2">
        {(hosts.data ?? []).map((host) => (
          <Card key={host.id}>
            <CardHeader>
              <div className="flex items-center justify-between">
                <h2 className="font-semibold">{host.name}</h2>
                <Pill label={host.environment || "unknown"} />
              </div>
            </CardHeader>
            <CardBody>
              <div className="space-y-2 text-sm text-mute">
                <div>
                  {host.address}:{host.port}
                </div>
                <div>Criticality: {host.criticality || "n/a"}</div>
                <div className="rounded-lg bg-panel2 p-2">
                  <div className="mb-1 text-xs uppercase tracking-wide text-mute">Policies</div>
                  <div className="space-y-1">
                    {host.policies.map((policy) => (
                      <div key={policy.id} className="text-xs">
                        role={policy.roleId} connect={String(policy.canConnect)} mfa={String(policy.requireMfa)}
                      </div>
                    ))}
                    {host.policies.length ? null : <div className="text-xs">No policies configured.</div>}
                  </div>
                </div>
              </div>
            </CardBody>
          </Card>
        ))}
      </div>
    </div>
  );
}
