import type { InputHTMLAttributes } from "react";
import { cn } from "@/lib/cn";

export function Input(props: InputHTMLAttributes<HTMLInputElement>) {
  return (
    <input
      {...props}
      className={cn(
        "w-full rounded-xl border border-edge bg-panel2 px-3 py-2 text-sm text-text placeholder:text-mute focus:border-accent/70 focus:outline-none",
        props.className
      )}
    />
  );
}
