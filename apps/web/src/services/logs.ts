import { get } from '../lib/api';

/** Одна строка JSON-лога; сервер отдаёт все поля строки как есть. */
export interface LogEntry {
  ts?: string;
  level?: string;
  message?: string;
  event?: string;
  result?: string;
  username?: string;
  ip?: string;
  user_agent?: string;
  request_id?: string;
  method?: string;
  path?: string;
  status?: number;
  duration?: number;
  [key: string]: unknown;
}

export interface LogsPage {
  items: LogEntry[];
  next_offset: number;
}

export async function listLogDates(): Promise<string[]> {
  const r = await get<{ dates: string[] }>('/admin/logs/dates');
  return r.dates ?? [];
}

export interface LogsQuery {
  date?: string;
  offset?: number;
  limit?: number;
  level?: string;
  event?: string;
}

export async function fetchLogs(q: LogsQuery): Promise<LogsPage> {
  const params = new URLSearchParams();
  if (q.date) params.set('date', q.date);
  if (q.offset) params.set('offset', String(q.offset));
  if (q.limit) params.set('limit', String(q.limit));
  if (q.level) params.set('level', q.level);
  if (q.event) params.set('event', q.event);
  const suffix = params.size ? `?${params.toString()}` : '';
  return get<LogsPage>(`/admin/logs${suffix}`);
}
