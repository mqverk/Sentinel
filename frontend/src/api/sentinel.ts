import { apiFetch } from "@/api/client";
import type {
  AuditLog,
  DashboardOverview,
  Host,
  LoginResponse,
  Permission,
  Principal,
  ReplayFrame,
  Role,
  Session,
  User,
} from "@/types/api";

export function login(username: string, password: string): Promise<LoginResponse> {
  return apiFetch<LoginResponse>("/auth/login", {
    method: "POST",
    body: JSON.stringify({ username, password }),
  });
}

export function getMe(): Promise<Principal> {
  return apiFetch<Principal>("/auth/me");
}

export function getDashboardOverview(): Promise<DashboardOverview> {
  return apiFetch<DashboardOverview>("/dashboard/overview");
}

export function listUsers(): Promise<User[]> {
  return apiFetch<User[]>("/users");
}

export function createUser(input: {
  username: string;
  email: string;
  password: string;
  roleIds: string[];
}): Promise<User> {
  return apiFetch<User>("/users", {
    method: "POST",
    body: JSON.stringify(input),
  });
}

export function replaceUserRoles(userId: string, roleIds: string[]): Promise<{ status: string }> {
  return apiFetch<{ status: string }>(`/users/${userId}/roles`, {
    method: "PUT",
    body: JSON.stringify({ roleIds }),
  });
}

export function listRoles(): Promise<Role[]> {
  return apiFetch<Role[]>("/roles");
}

export function listPermissions(): Promise<Permission[]> {
  return apiFetch<Permission[]>("/permissions");
}

export function listSessions(status = ""): Promise<Session[]> {
  return apiFetch<Session[]>("/sessions", { query: { status } });
}

export function terminateSession(sessionId: string): Promise<{ status: string }> {
  return apiFetch<{ status: string }>(`/sessions/${sessionId}/terminate`, {
    method: "POST",
  });
}

export async function replaySession(sessionId: string): Promise<ReplayFrame[]> {
  const payload = await apiFetch<{ sessionId: string; frames: ReplayFrame[] }>(`/sessions/${sessionId}/replay`);
  return payload.frames;
}

export function listAuditLogs(q = "", limit = 200): Promise<AuditLog[]> {
  return apiFetch<AuditLog[]>("/audit/logs", { query: { q, limit } });
}

export function listHosts(): Promise<Host[]> {
  return apiFetch<Host[]>("/hosts");
}

export function getSettings(): Promise<Record<string, unknown>> {
  return apiFetch<Record<string, unknown>>("/settings");
}

export function upsertSetting(key: string, value: unknown): Promise<{ status: string }> {
  return apiFetch<{ status: string }>("/settings", {
    method: "PUT",
    body: JSON.stringify({ key, value }),
  });
}
