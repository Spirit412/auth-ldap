import { get, post } from '../lib/api';

/** Настройки подключения (без секретов) — GET /admin/ldap/config. */
export interface LdapSettings {
  mode: 'service-bind' | 'self-bind';
  url: string;
  start_tls: boolean;
  tls_insecure: boolean;
  ca_file?: string;
  bind_dn?: string;
  base_dn: string;
  object_class: string;
  user_attr: string;
  name_attr: string;
  mail_attr: string;
  upn_suffix?: string;
  netbios_domain?: string;
  admin_group_dn?: string;
  pool_size: number;
  timeout: string;
  retry: number;
}

export const getLdapSettings = () => get<LdapSettings>('/admin/ldap/config');

/** Один шаг диагностической попытки. */
export interface LdapTraceStep {
  step: string;
  ok: boolean;
  detail?: string;
  ms: number;
}

export interface LdapTrace {
  mode: string;
  ok: boolean;
  steps: LdapTraceStep[];
}

export interface LdapUserInfo {
  dn: string;
  username: string;
  display_name: string;
  email: string;
  member_of: string[];
  roles: string[];
}

export interface LdapTestResult {
  trace: LdapTrace;
  user?: LdapUserInfo;
}

export interface LdapTestRequest {
  username: string;
  password: string;
}

/** Проверка авторизации с пошаговым отчётом — POST /admin/ldap/test. */
export const testLdapAuth = (body: LdapTestRequest) =>
  post<LdapTestResult>('/admin/ldap/test', body, { raw: true });
