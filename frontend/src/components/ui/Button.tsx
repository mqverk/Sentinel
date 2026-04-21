import type { ButtonHTMLAttributes, ReactNode } from "react";
import { cn } from "@/lib/cn";

type ButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & {
  children: ReactNode;
  tone?: "primary" | "muted" | "danger";
};

export function Button({ children, className, tone = "primary", ...props }: ButtonProps) {
  return (
    <button
      className={cn(
        "inline-flex items-center justify-center rounded-xl px-3 py-2 text-sm font-semibold transition-all duration-200 disabled:cursor-not-allowed disabled:opacity-45",
        tone === "primary" && "bg-accent/90 text-slate-900 hover:bg-accent",
        tone === "muted" && "bg-panel2 text-text hover:bg-edge",
        tone === "danger" && "bg-danger/90 text-white hover:bg-danger",
        className
      )}
      {...props}
    >
      {children}
    </button>
  );
}
