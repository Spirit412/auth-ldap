import { get, del } from '../lib/api';
import type { User, UsersOutputBody } from '@aps/shared-types';

export interface UsersQuery {
  q?: string;
  status?: 'active' | 'deleted' | 'all';
  role?: string;
  limit?: number;
  cursor?: string;
}

export async function listUsers(q: UsersQuery): Promise<UsersOutputBody> {
  const params = new URLSearchParams();
  if (q.q) params.set('q', q.q);
  if (q.status && q.status !== 'active') params.set('status', q.status);
  if (q.role) params.set('role', q.role);
  if (q.limit) params.set('limit', String(q.limit));
  if (q.cursor) params.set('cursor', q.cursor);
  const suffix = params.size ? `?${params.toString()}` : '';
  return get<UsersOutputBody>(`/users${suffix}`);
}

export const getUser = (id: string) => get<User>(`/users/${encodeURIComponent(id)}`);
export const deleteUser = (id: string) => del<void>(`/users/${encodeURIComponent(id)}`);
export type { User };
