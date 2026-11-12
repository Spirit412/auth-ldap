import { useAuthStore } from '../stores/auth';

/**
 * Minimal same-origin API client.
 *
 * Security behaviour (ТЗ S-10 / F-20 / F-15):
 *  - Every non-GET request carries `X-Requested-With: XMLHttpRequest`
 *    (anti-CSRF, paired with the SameSite=Strict refresh cookie).
 *  - The refresh token NEVER enters JS storage: silent refresh relies on the
 *    HttpOnly `aps_refresh` cookie; the token from response bodies is ignored.
 *  - On 401 with a stale access token we refresh once through the cookie and
 *    replay the original request (F-15 automatic refresh).
 */

const BASE = '/api/v1';

export class ApiError extends Error {
  status: number;
  title: string;
  detail: string;
  retryAfter?: number;

  constructor(status: number, title: string, detail: string, retryAfter?: number) {
    super(detail || title);
    this.status = status;
    this.title = title;
    this.detail = detail;
    this.retryAfter = retryAfter;
  }
}

interface ProblemBody {
  title?: string;
  status?: number;
  detail?: string;
}

async function parseProblem(res: Response): Promise<ApiError> {
  const retryAfter = Number(res.headers.get('Retry-After')) || undefined;
  let body: ProblemBody = {};
  try {
    body = (await res.json()) as ProblemBody;
  } catch {
    // non-JSON error body — keep generic
  }
  return new ApiError(res.status, body.title ?? res.statusText, body.detail ?? '', retryAfter);
}

let refreshInFlight: Promise<string | null> | null = null;

/** Refresh once (cookie-based). Concurrent callers share one request. */
export function silentRefresh(): Promise<string | null> {
  if (!refreshInFlight) {
    refreshInFlight = doRefresh().finally(() => {
      refreshInFlight = null;
    });
  }
  return refreshInFlight;
}

async function doRefresh(): Promise<string | null> {
  const res = await fetch(`${BASE}/auth/refresh`, {
    method: 'POST',
    headers: { 'X-Requested-With': 'XMLHttpRequest' },
  });
  if (!res.ok) {
    useAuthStore.getState().clear();
    return null;
  }
  const data = (await res.json()) as { access_token: string };
  // NOTE: data.refresh_token is deliberately NOT stored anywhere.
  const current = useAuthStore.getState().user;
  useAuthStore.getState().setAuth(data.access_token, current);
  return data.access_token;
}

export interface ApiOptions {
  /** Skip the 401-refresh-retry cycle (used by login itself). */
  raw?: boolean;
  signal?: AbortSignal;
}

export async function apiFetch<T>(path: string, init: RequestInit = {}, opts: ApiOptions = {}): Promise<T> {
  const call = (): Promise<Response> => {
    const headers = new Headers(init.headers);
    const method = (init.method ?? 'GET').toUpperCase();
    if (method !== 'GET' && method !== 'HEAD') {
      headers.set('X-Requested-With', 'XMLHttpRequest');
    }
    const token = useAuthStore.getState().accessToken;
    if (token) {
      headers.set('Authorization', `Bearer ${token}`);
    }
    return fetch(`${BASE}${path}`, { ...init, headers, signal: opts.signal });
  };

  let res = await call();
  if (res.status === 401 && !opts.raw && useAuthStore.getState().accessToken) {
    const fresh = await silentRefresh();
    if (fresh) {
      res = await call();
    }
  }
  if (!res.ok) {
    throw await parseProblem(res);
  }
  if (res.status === 204) {
    return undefined as T;
  }
  return (await res.json()) as T;
}

export const get = <T>(path: string, opts?: ApiOptions) => apiFetch<T>(path, {}, opts);

export const post = <T>(path: string, body?: unknown, opts?: ApiOptions) =>
  apiFetch<T>(
    path,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
    },
    opts,
  );

export const del = <T>(path: string, opts?: ApiOptions) =>
  apiFetch<T>(path, { method: 'DELETE' }, opts);
