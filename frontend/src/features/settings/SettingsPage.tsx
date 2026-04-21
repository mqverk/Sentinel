import { FormEvent, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { getSettings, upsertSetting } from "@/api/sentinel";
import { Button } from "@/components/ui/Button";
import { Card, CardBody, CardHeader } from "@/components/ui/Card";
import { Input } from "@/components/ui/Input";

export function SettingsPage() {
  const queryClient = useQueryClient();
  const settings = useQuery({ queryKey: ["settings"], queryFn: getSettings });
  const [key, setKey] = useState("session.retentionDays");
  const [value, setValue] = useState("30");

  const mutation = useMutation({
    mutationFn: ({ key, value }: { key: string; value: unknown }) => upsertSetting(key, value),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["settings"] });
    },
  });

  const submit = (event: FormEvent) => {
    event.preventDefault();
    let parsed: unknown = value;
    try {
      parsed = JSON.parse(value);
    } catch {
      parsed = value;
    }
    mutation.mutate({ key, value: parsed });
  };

  return (
    <div className="grid gap-5 lg:grid-cols-[1fr_1.2fr]">
      <Card>
        <CardHeader>
          <h2 className="font-semibold">Safe Config Editor</h2>
        </CardHeader>
        <CardBody>
          <form className="space-y-3" onSubmit={submit}>
            <Input value={key} onChange={(e) => setKey(e.target.value)} placeholder="setting.key" />
            <Input value={value} onChange={(e) => setValue(e.target.value)} placeholder="JSON value or string" />
            {mutation.isError ? <p className="text-sm text-danger">{mutation.error.message}</p> : null}
            <Button disabled={mutation.isPending}>{mutation.isPending ? "Saving..." : "Save Setting"}</Button>
          </form>
        </CardBody>
      </Card>

      <Card>
        <CardHeader>
          <h2 className="font-semibold">Current Settings</h2>
        </CardHeader>
        <CardBody>
          <pre className="max-h-[520px] overflow-auto rounded-xl bg-panel2 p-3 font-mono text-xs text-mute">
            {JSON.stringify(settings.data ?? {}, null, 2)}
          </pre>
        </CardBody>
      </Card>
    </div>
  );
}
