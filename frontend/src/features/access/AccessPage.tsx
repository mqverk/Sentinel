import { FormEvent, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { createUser, listRoles, listUsers } from "@/api/sentinel";
import { Button } from "@/components/ui/Button";
import { Card, CardBody, CardHeader } from "@/components/ui/Card";
import { Input } from "@/components/ui/Input";
import { Pill } from "@/components/ui/Pill";

export function AccessPage() {
  const queryClient = useQueryClient();
  const users = useQuery({ queryKey: ["users"], queryFn: listUsers });
  const roles = useQuery({ queryKey: ["roles"], queryFn: listRoles });

  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [roleIds, setRoleIds] = useState<string[]>([]);

  const create = useMutation({
    mutationFn: createUser,
    onSuccess: async () => {
      setUsername("");
      setEmail("");
      setPassword("");
      setRoleIds([]);
      await queryClient.invalidateQueries({ queryKey: ["users"] });
    },
  });

  const toggleRole = (id: string) => {
    setRoleIds((current) => (current.includes(id) ? current.filter((v) => v !== id) : [...current, id]));
  };

  const submit = (event: FormEvent) => {
    event.preventDefault();
    create.mutate({ username, email, password, roleIds });
  };

  return (
    <div className="grid gap-5 xl:grid-cols-[1.1fr_1.5fr]">
      <Card>
        <CardHeader>
          <h2 className="font-semibold">Create User</h2>
        </CardHeader>
        <CardBody>
          <form className="space-y-3" onSubmit={submit}>
            <Input placeholder="Username" value={username} onChange={(e) => setUsername(e.target.value)} />
            <Input placeholder="Email" value={email} onChange={(e) => setEmail(e.target.value)} />
            <Input
              type="password"
              placeholder="Temporary Password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />

            <div className="space-y-2">
              <p className="text-xs uppercase tracking-wide text-mute">Assign Roles</p>
              <div className="flex flex-wrap gap-2">
                {(roles.data ?? []).map((role) => (
                  <button
                    type="button"
                    key={role.id}
                    onClick={() => toggleRole(role.id)}
                    className={[
                      "rounded-full border px-2 py-1 text-xs",
                      roleIds.includes(role.id) ? "border-accent bg-accent/20 text-accent" : "border-edge text-mute",
                    ].join(" ")}
                  >
                    {role.name}
                  </button>
                ))}
              </div>
            </div>

            {create.isError ? <p className="text-sm text-danger">{create.error.message}</p> : null}
            <Button disabled={create.isPending}>{create.isPending ? "Creating..." : "Create User"}</Button>
          </form>
        </CardBody>
      </Card>

      <Card>
        <CardHeader>
          <h2 className="font-semibold">Users</h2>
        </CardHeader>
        <CardBody>
          <div className="space-y-2 text-sm">
            {(users.data ?? []).map((user) => (
              <div key={user.id} className="rounded-xl bg-panel2 p-3">
                <div className="flex items-center justify-between gap-2">
                  <div>
                    <div className="font-semibold">{user.username}</div>
                    <div className="text-xs text-mute">{user.email}</div>
                  </div>
                  <Pill label={user.disabled ? "disabled" : "active"} tone={user.disabled ? "danger" : "ok"} />
                </div>
                <div className="mt-2 flex flex-wrap gap-1">
                  {user.roles.map((role) => (
                    <span key={role.id} className="rounded-full bg-edge px-2 py-1 text-xs text-mute">
                      {role.name}
                    </span>
                  ))}
                </div>
              </div>
            ))}
            {users.data?.length ? null : <p className="text-mute">No users returned.</p>}
          </div>
        </CardBody>
      </Card>
    </div>
  );
}
