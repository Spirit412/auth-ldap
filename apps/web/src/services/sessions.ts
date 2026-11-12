import { get, del } from '../lib/api';
import type { SessionItem, SessionsOutputBody } from '@aps/shared-types';

export interface SessionsQuery {
  username?: string;
  limit?: number;
  cursor?: string;
}

export async function listSessions(q: SessionsQuery): Promise<SessionsOutputBody> {
  const params = new URLSearchParams();
  if (q.username) params.set('username', q.username);
  if (q.limit) params.set('limit', String(q.limit));
  if (q.cursor) params.set('cursor', q.cursor);
  const suffix = params.size ? `?${params.toString()}` : '';
  return get<SessionsOutputBody>(`/auth/sessions${suffix}`);
}

export const revokeSession = (id: string) => del<void>(`/auth/sessions/${encodeURIComponent(id)}`);
export type { SessionItem };
