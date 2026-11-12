import { describe, it, expect, vi, beforeEach } from 'vitest';
import { apiFetch, silentRefresh } from './api';
import { useAuthStore } from '../stores/auth';

// Fetch mock helper: sequential responses.
function mockFetch(responses: Array<{ status: number; body?: unknown }>) {
  const impl = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => {
    const r = responses.shift() ?? { status: 500, body: {} };
    return new Response(JSON.stringify(r.body ?? {}), {
      status: r.status,
      headers: { 'Content-Type': 'application/json' },
    });
  });
  vi.stubGlobal('fetch', impl);
  return impl;
}

const initOf = (call: unknown[] | undefined): RequestInit =>
  (call?.[1] as RequestInit | undefined) ?? {};

describe('api client', () => {
  beforeEach(() => {
    useAuthStore.getState().clear();
    vi.unstubAllGlobals();
  });

  // S-10 / F-20: every POST carries the anti-CSRF header.
  it('adds X-Requested-With to POST', async () => {
    const f = mockFetch([{ status: 200, body: { ok: true } }]);
    await apiFetch('/auth/login', { method: 'POST', body: '{}' }, { raw: true });
    const headers = new Headers(initOf(f.mock.calls[0]).headers);
    expect(headers.get('X-Requested-With')).toBe('XMLHttpRequest');
  });

  it('does not add X-Requested-With to GET', async () => {
    const f = mockFetch([{ status: 200, body: {} }]);
    await apiFetch('/auth/me');
    const headers = new Headers(initOf(f.mock.calls[0]).headers);
    expect(headers.get('X-Requested-With')).toBeNull();
  });

  // F-15: on 401 the client silently refreshes via cookie and replays.
  it('refreshes once and retries after 401', async () => {
    useAuthStore.getState().setAuth('stale-token', null);
    const f = mockFetch([
      { status: 401, body: { title: 'Unauthorized' } },
      { status: 200, body: { access_token: 'fresh-token' } },
      { status: 200, body: { username: 'alice' } },
    ]);

    const data = await apiFetch<{ username: string }>('/auth/me');
    expect(data.username).toBe('alice');
    expect(useAuthStore.getState().accessToken).toBe('fresh-token');

    // first call -> original; second -> refresh; third -> replay
    expect(f).toHaveBeenCalledTimes(3);
    const replayHeaders = new Headers(initOf(f.mock.calls[2]).headers);
    expect(replayHeaders.get('Authorization')).toBe('Bearer fresh-token');

    // refresh call must have the anti-CSRF header and no Authorization
    const refreshHeaders = new Headers(initOf(f.mock.calls[1]).headers);
    expect(refreshHeaders.get('X-Requested-With')).toBe('XMLHttpRequest');
    expect(refreshHeaders.get('Authorization')).toBeNull();
  });

  it('does not loop refresh on repeated 401', async () => {
    useAuthStore.getState().setAuth('stale-token', null);
    const f = mockFetch([
      { status: 401, body: {} },
      { status: 200, body: { access_token: 'fresh-token' } },
      { status: 401, body: {} },
    ]);
    await expect(apiFetch('/auth/me')).rejects.toMatchObject({ status: 401 });
    expect(f).toHaveBeenCalledTimes(3); // original + refresh + single replay
  });

  it('silent refresh clears auth on failure', async () => {
    useAuthStore.getState().setAuth('stale-token', null);
    mockFetch([{ status: 401, body: {} }]);
    const tok = await silentRefresh();
    expect(tok).toBeNull();
    expect(useAuthStore.getState().accessToken).toBeNull();
  });

  it('surfaces problem+json details with Retry-After', async () => {
    const impl = vi.fn(async () =>
      new Response(JSON.stringify({ title: 'Too Many Requests', detail: 'rate limit exceeded' }), {
        status: 429,
        headers: { 'Content-Type': 'application/problem+json', 'Retry-After': '45' },
      }),
    );
    vi.stubGlobal('fetch', impl);
    await expect(apiFetch('/auth/login', { method: 'POST', body: '{}' }, { raw: true })).rejects.toMatchObject({
      status: 429,
      retryAfter: 45,
      detail: 'rate limit exceeded',
    });
  });
});
