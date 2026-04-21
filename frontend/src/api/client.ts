import { clearAuthToken, getAuthToken } from "@/lib/auth";

const API_BASE = "/api/v1";

type RequestInitExt = RequestInit & {
  query?: Record<string, string | number | undefined>;
};

export async function apiFetch<T>(path: string, init: RequestInitExt = {}): Promise<T> {
  const url = new URL(`${API_BASE}${path}`, window.location.origin);
  if (init.query) {
    Object.entries(init.query).forEach(([key, value]) => {
      if (value !== undefined && value !== "") {
        url.searchParams.set(key, String(value));
      }
    });
  }

  const token = getAuthToken();
  const headers = new Headers(init.headers ?? {});
  headers.set("Content-Type", "application/json");
  if (token) {
    headers.set("Authorization", `Bearer ${token}`);
  }

  const response = await fetch(url, {
    ...init,
    headers,
  });

  if (response.status === 401) {
    clearAuthToken();
  }

  if (!response.ok) {
    const fallback = `${response.status} ${response.statusText}`;
    let message = fallback;
    try {
      const payload = (await response.json()) as { error?: string };
      if (payload.error) {
        message = payload.error;
      }
    } catch {
      message = fallback;
    }
    throw new Error(message);
  }

  if (response.status === 204) {
    return undefined as T;
  }

  return (await response.json()) as T;
}
