export type Principal = {
  userId: string;
  username: string;
  roles: string[];
  permissions: string[];
  authenticated: boolean;
};

export type LoginResponse = {
  token: string;
  expiresAt: string;
  principal: Principal;
};

export type AuditLog = {
  id: string;
  actorId: string;
  actorUsername: string;
  action: string;
  resource: string;
  outcome: "allow" | "deny" | string;
  sourceIp: string;
  detailsJson: string;
  createdAt: string;
};

export type Session = {
  id: string;
  userId: string;
  hostId: string;
  status: string;
  startedAt: string;
  endedAt?: string;
  recordingPath: string;
  metadataJson: string;
};

export type ReplayFrame = {
  offsetMillis: number;
  stream: string;
  payload: string;
};

export type HostPolicy = {
  id: string;
  roleId: string;
  hostId: string;
  canConnect: boolean;
  requireMfa: boolean;
  createdAt: string;
};

export type Host = {
  id: string;
  name: string;
  address: string;
  port: number;
  environment: string;
  criticality: string;
  createdAt: string;
  policies: HostPolicy[];
};

export type Permission = {
  id: string;
  resource: string;
  action: string;
  description: string;
  createdAt: string;
};

export type Role = {
  id: string;
  name: string;
  description: string;
  createdAt: string;
  permissions: Permission[];
};

export type User = {
  id: string;
  username: string;
  email: string;
  disabled: boolean;
  createdAt: string;
  lastLoginAt?: string;
  roles: Array<{ id: string; name: string; description: string; createdAt: string }>;
};

export type DashboardOverview = {
  activeSessions: number;
  recentLogins: AuditLog[];
  openAlerts: number;
};
