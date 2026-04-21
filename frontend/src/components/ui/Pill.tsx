import { cn } from "@/lib/cn";

type PillProps = {
  label: string;
  tone?: "default" | "warn" | "danger" | "ok";
};

export function Pill({ label, tone = "default" }: PillProps) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-full px-2 py-1 text-[11px] font-semibold uppercase tracking-wide",
        tone === "default" && "bg-panel2 text-mute",
        tone === "warn" && "bg-warn/20 text-warn",
        tone === "danger" && "bg-danger/20 text-danger",
        tone === "ok" && "bg-accent/20 text-accent"
      )}
    >
      {label}
    </span>
  );
}
