import { describe, it, expect, beforeEach } from 'vitest';
import { useAuthStore, isAdmin } from './auth';

// F-20: the refresh token must never touch localStorage/sessionStorage.
// The auth store only holds the in-memory access token.
describe('auth store', () => {
  beforeEach(() => {
    localStorage.clear();
    sessionStorage.clear();
    useAuthStore.getState().clear();
  });

  it('keeps token in memory only', () => {
    useAuthStore.getState().setAuth('tok-1', { username: 'alice', displayName: '', email: '', roles: ['admin'] });
    expect(useAuthStore.getState().accessToken).toBe('tok-1');
    useAuthStore.getState().clear();
    expect(useAuthStore.getState().accessToken).toBeNull();
  });

  it('writes nothing to web storage', () => {
    useAuthStore.getState().setAuth('tok-2', null);
    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(0);
  });

  it('detects admin role', () => {
    useAuthStore.getState().setUser({ username: 'a', displayName: '', email: '', roles: ['admin'] });
    expect(isAdmin(useAuthStore.getState())).toBe(true);
    useAuthStore.getState().setUser({ username: 'b', displayName: '', email: '', roles: [] });
    expect(isAdmin(useAuthStore.getState())).toBe(false);
  });
});
