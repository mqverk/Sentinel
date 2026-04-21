import { FormEvent, useState } from "react";
import { Navigate } from "react-router-dom";
import { useLogin } from "@/hooks/useAuth";
import { getAuthToken } from "@/lib/auth";
import { Card, CardBody, CardHeader } from "@/components/ui/Card";
import { Input } from "@/components/ui/Input";
import { Button } from "@/components/ui/Button";

export function LoginPage() {
  const mutation = useLogin();
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("Sentinel!ChangeMe");

  if (getAuthToken()) {
    return <Navigate to="/" replace />;
  }

  const submit = (event: FormEvent) => {
    event.preventDefault();
    mutation.mutate({ username, password });
  };

  return (
    <div className="mx-auto flex min-h-screen max-w-5xl items-center px-4 py-8">
      <div className="grid w-full gap-6 md:grid-cols-[1.2fr_1fr]">
        <section className="rounded-3xl border border-edge bg-panel/80 p-8">
          <h1 className="text-4xl font-semibold leading-tight">Sentinel Control Plane</h1>
          <p className="mt-4 max-w-lg text-mute">
            Hardened ingress. Verified identities. Complete session traceability. Secure your private estate through a single zero-trust access gateway.
          </p>
          <div className="mt-6 grid grid-cols-2 gap-3 text-sm">
            <div className="rounded-xl bg-panel2 p-3">End-to-end SSH session recording</div>
            <div className="rounded-xl bg-panel2 p-3">Policy-driven host authorization</div>
            <div className="rounded-xl bg-panel2 p-3">Structured audit evidence</div>
            <div className="rounded-xl bg-panel2 p-3">Role and permission governance</div>
          </div>
        </section>

        <Card className="self-center">
          <CardHeader>
            <h2 className="text-lg font-semibold">Sign In</h2>
          </CardHeader>
          <CardBody>
            <form className="space-y-3" onSubmit={submit}>
              <label className="space-y-1 text-sm">
                <span className="text-mute">Username</span>
                <Input value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" />
              </label>
              <label className="space-y-1 text-sm">
                <span className="text-mute">Password</span>
                <Input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  autoComplete="current-password"
                />
              </label>
              {mutation.isError ? <p className="text-sm text-danger">{mutation.error.message}</p> : null}
              <Button className="w-full" disabled={mutation.isPending}>
                {mutation.isPending ? "Authorizing..." : "Enter Sentinel"}
              </Button>
            </form>
          </CardBody>
        </Card>
      </div>
    </div>
  );
}
