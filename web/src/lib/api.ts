// Thin fetch client. The bearer token belongs to the persona chosen in the header switcher.

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}

let token: string | null = null;
let relogin: (() => Promise<string>) | null = null;

export function setToken(value: string | null) {
  token = value;
}

/** Called on 401 (e.g. the demo server restarted with new signing keys) to get a fresh token once. */
export function setRelogin(fn: () => Promise<string>) {
  relogin = fn;
}

function detailMessage(body: unknown, fallback: string): string {
  if (body && typeof body === "object" && "detail" in body) {
    const detail = (body as { detail: unknown }).detail;
    if (typeof detail === "string") return detail;
    if (detail && typeof detail === "object" && "message" in detail) return String((detail as { message: unknown }).message);
    return JSON.stringify(detail);
  }
  return fallback;
}

type Options = { method?: string; body?: unknown; query?: Record<string, string | number | boolean | undefined | null> };

export async function api<T>(path: string, options: Options = {}, retried = false): Promise<T> {
  const query = Object.entries(options.query ?? {}).filter(([, v]) => v !== undefined && v !== null && v !== "");
  const url = query.length ? `${path}?${new URLSearchParams(query.map(([k, v]) => [k, String(v)]))}` : path;
  const response = await fetch(url, {
    method: options.method ?? (options.body !== undefined ? "POST" : "GET"),
    headers: {
      ...(options.body !== undefined ? { "content-type": "application/json" } : {}),
      ...(token ? { authorization: `Bearer ${token}` } : {}),
    },
    body: options.body !== undefined ? JSON.stringify(options.body) : undefined,
  });
  if (response.status === 401 && !retried && relogin && !path.startsWith("/idp/")) {
    token = await relogin();
    return api<T>(path, options, true);
  }
  const text = await response.text();
  const body = text ? JSON.parse(text) : null;
  if (!response.ok) throw new ApiError(response.status, detailMessage(body, `${response.status} ${response.statusText}`));
  return body as T;
}

export const post = <T,>(path: string, body: unknown = {}) => api<T>(path, { method: "POST", body });

/** Fetch an authenticated attachment without treating ZIP bytes as JSON. */
export async function downloadFile(path: string, retried = false): Promise<{ blob: Blob; filename: string }> {
  const response = await fetch(path, { headers: token ? { authorization: `Bearer ${token}` } : {} });
  if (response.status === 401 && !retried && relogin) {
    token = await relogin();
    return downloadFile(path, true);
  }
  if (!response.ok) {
    const text = await response.text();
    let message = `${response.status} ${response.statusText}`;
    try {
      message = detailMessage(JSON.parse(text), message);
    } catch {
      if (text) message = text;
    }
    throw new ApiError(response.status, message);
  }
  const filename = response.headers.get("content-disposition")?.match(/filename="([^"]+)"/)?.[1] ?? "aegis-evidence.zip";
  return { blob: await response.blob(), filename };
}
