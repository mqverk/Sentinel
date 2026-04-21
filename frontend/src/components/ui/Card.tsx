import type { ReactNode } from "react";
import { cn } from "@/lib/cn";

type CardProps = {
  children: ReactNode;
  className?: string;
};

export function Card({ children, className }: CardProps) {
  return (
    <section
      className={cn(
        "rounded-2xl border border-edge bg-panel/90 backdrop-blur-sm shadow-[0_20px_48px_-28px_rgba(6,182,212,0.45)]",
        className
      )}
    >
      {children}
    </section>
  );
}

export function CardHeader({ children, className }: CardProps) {
  return <header className={cn("border-b border-edge px-5 py-4", className)}>{children}</header>;
}

export function CardBody({ children, className }: CardProps) {
  return <div className={cn("px-5 py-4", className)}>{children}</div>;
}
