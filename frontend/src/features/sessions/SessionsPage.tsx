import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { listSessions, replaySession, terminateSession } from "@/api/sentinel";
import { Button } from "@/components/ui/Button";
import { Card, CardBody, CardHeader } from "@/components/ui/Card";
import { Pill } from "@/components/ui/Pill";

export function SessionsPage() {
  const queryClient = useQueryClient();
  const [selectedSessionId, setSelectedSessionId] = useState<string>("");
  const sessions = useQuery({ queryKey: ["sessions", "all"], queryFn: () => listSessions("") });
  const replay = useQuery({
    queryKey: ["sessions", "replay", selectedSessionId],
    queryFn: () => replaySession(selectedSessionId),
    enabled: Boolean(selectedSessionId),
  });

  const terminate = useMutation({
    mutationFn: terminateSession,
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["sessions"] });
    },
  });

  const active = useMemo(() => (sessions.data ?? []).filter((session) => session.status === "active"), [sessions.data]);

  return (
    <div className="grid gap-5 xl:grid-cols-[1fr_1.2fr]">
      <div className="space-y-5">
        <Card>
          <CardHeader>
            <h2 className="font-semibold">Live Sessions</h2>
          </CardHeader>
          <CardBody>
            <div className="space-y-2 text-sm">
              {active.map((session) => (
                <div key={session.id} className="rounded-xl bg-panel2 p-3">
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-xs text-mute">{session.id}</span>
                    <Pill label={session.status} tone="ok" />
                  </div>
                  <div className="mt-2 flex gap-2">
                    <Button tone="muted" onClick={() => setSelectedSessionId(session.id)}>
                      Replay
                    </Button>
                    <Button tone="danger" onClick={() => terminate.mutate(session.id)}>
                      Terminate
                    </Button>
                  </div>
                </div>
              ))}
              {active.length ? null : <p className="text-mute">No active sessions.</p>}
            </div>
          </CardBody>
        </Card>

        <Card>
          <CardHeader>
            <h2 className="font-semibold">Session History</h2>
          </CardHeader>
          <CardBody>
            <div className="space-y-1 text-sm">
              {(sessions.data ?? []).map((session) => (
                <button
                  key={session.id}
                  onClick={() => setSelectedSessionId(session.id)}
                  className="block w-full rounded-lg bg-panel2 px-3 py-2 text-left hover:bg-edge"
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-mono text-xs text-mute">{session.id}</span>
                    <Pill label={session.status} tone={session.status === "active" ? "ok" : "default"} />
                  </div>
                  <p className="mt-1 text-xs text-mute">Host: {session.hostId}</p>
                </button>
              ))}
            </div>
          </CardBody>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <h2 className="font-semibold">Replay Timeline</h2>
        </CardHeader>
        <CardBody>
          {!selectedSessionId ? <p className="text-sm text-mute">Select a session to inspect frame playback.</p> : null}
          {replay.isLoading ? <p className="text-sm text-mute">Loading replay stream...</p> : null}
          {replay.isError ? <p className="text-sm text-danger">{replay.error.message}</p> : null}
          <div className="max-h-[520px] space-y-2 overflow-auto font-mono text-xs">
            {(replay.data ?? []).map((frame, index) => (
              <div key={`${frame.offsetMillis}-${index}`} className="rounded-md bg-panel2 p-2">
                <div className="mb-1 text-[10px] uppercase tracking-wide text-mute">
                  +{frame.offsetMillis}ms · {frame.stream}
                </div>
                <pre className="whitespace-pre-wrap text-text">{frame.payload}</pre>
              </div>
            ))}
          </div>
        </CardBody>
      </Card>
    </div>
  );
}
