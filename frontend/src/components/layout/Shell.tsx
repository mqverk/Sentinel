import { Link, NavLink, Outlet } from "react-router-dom";
import { useCurrentUser, useLogout } from "@/hooks/useAuth";
import { Button } from "@/components/ui/Button";

const nav = [
  ["Dashboard", "/"],
  ["Access", "/access"],
  ["Sessions", "/sessions"],
  ["Audit", "/audit"],
  ["Hosts", "/hosts"],
  ["Settings", "/settings"],
] as const;

export function Shell() {
  const { data: me } = useCurrentUser();
  const logout = useLogout();

  return (
    <div className="mx-auto grid min-h-screen max-w-[1440px] grid-cols-1 gap-4 px-3 py-3 lg:grid-cols-[260px_1fr] lg:px-6">
      <aside className="rounded-2xl border border-edge bg-panel/85 p-4 backdrop-blur-sm">
        <Link to="/" className="block rounded-xl bg-panel2 px-3 py-4">
          <div className="font-mono text-xs text-accent">SENTINEL</div>
          <div className="mt-1 text-xl font-semibold">Zero-Trust Bastion</div>
        </Link>

        <nav className="mt-4 space-y-1">
          {nav.map(([label, path]) => (
            <NavLink
              key={path}
              to={path}
              className={({ isActive }) =>
                [
                  "block rounded-xl px-3 py-2 text-sm transition-colors",
                  isActive ? "bg-accent/20 text-accent" : "text-mute hover:bg-panel2 hover:text-text",
                ].join(" ")
              }
            >
              {label}
            </NavLink>
          ))}
        </nav>

        <div className="mt-6 rounded-xl border border-edge bg-panel2 p-3 text-xs text-mute">
          <div className="font-semibold text-text">Signed In</div>
          <div className="mt-1">{me?.username ?? "Unknown"}</div>
          <div className="mt-2 flex flex-wrap gap-1">
            {(me?.roles ?? []).map((role) => (
              <span key={role} className="rounded-full bg-edge px-2 py-1">
                {role}
              </span>
            ))}
          </div>
          <Button className="mt-3 w-full" tone="muted" onClick={logout}>
            Sign Out
          </Button>
        </div>
      </aside>

      <main className="animate-floatIn rounded-2xl border border-edge bg-panel/60 p-4 backdrop-blur-sm lg:p-6">
        <Outlet />
      </main>
    </div>
  );
}
