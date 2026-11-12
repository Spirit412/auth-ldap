import { silentRefresh, post, get } from '../lib/api';
import { useAuthStore, type AuthUser } from '../stores/auth';
import type { LoginRequest, Tokens, User } from '@aps/shared-types';

/** profile shape served by GET /auth/me (userstore.User) */
export type MeProfile = User;

export async function login(body: LoginRequest): Promise<Tokens> {
  // raw: 401 here is a genuine bad-credential case, not a stale token.
  return post<Tokens>('/auth/login', body, { raw: true });
}

export async function logout(): Promise<void> {
  try {
    await post<void>('/auth/logout');
  } finally {
    useAuthStore.getState().clear();
  }
}

export async function fetchMe(): Promise<MeProfile> {
  return get<MeProfile>('/auth/me');
}

/** Boots the session after a page reload via the HttpOnly refresh cookie. */
export async function bootstrapSession(): Promise<string | null> {
  const token = await silentRefresh();
  if (token) {
    try {
      const me = await fetchMe();
      useAuthStore.getState().setUser(toAuthUser(me));
    } catch {
      // profile unavailable (deleted) — keep the session, UI degrades
    }
  }
  return token;
}

export function toAuthUser(u: MeProfile): AuthUser {
  return {
    username: u.username,
    displayName: u.display_name ?? '',
    email: u.email ?? '',
    roles: u.roles ?? [],
  };
}
