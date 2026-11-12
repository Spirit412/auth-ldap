import { Card, Col, Descriptions, Row, Tag, Typography, Input, Button, Alert, Space, App as AntApp } from 'antd';
import { SafetyCertificateOutlined, UserOutlined } from '@ant-design/icons';
import { useMutation, useQuery } from '@tanstack/react-query';
import { getLdapSettings, testLdapAuth, type LdapTestResult, type LdapUserInfo } from '../services/ldap';
import { useState } from 'react';

const stepNames: Record<string, string> = {
  resolve_login: 'Разбор логина',
  dial_tls: 'Подключение (TLS/LDAPS)',
  bind: 'Bind от имени пользователя',
  service_bind: 'Bind сервисной учётки',
  search: 'Поиск в каталоге',
  user_bind: 'Bind для проверки пароля',
  read_attrs: 'Чтение атрибутов',
  map_roles: 'Маппинг ролей',
};

export function LdapPage() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [result, setResult] = useState<LdapTestResult | null>(null);
  const { message } = AntApp.useApp();

  const settingsQuery = useQuery({ queryKey: ['ldap-config'], queryFn: getLdapSettings });

  const testMutation = useMutation({
    mutationFn: () => testLdapAuth({ username, password }),
    onSuccess: (data) => {
      setResult(data);
      if (data.trace.ok) void message.success('LDAP: авторизация успешна');
      else void message.warning('LDAP: авторизация не прошла — см. лог попытки');
    },
    onError: (e) => void message.error(`Ошибка запроса: ${e instanceof Error ? e.message : 'неизвестно'}`),
  });

  const settings = settingsQuery.data;
  const user: LdapUserInfo | undefined = result?.user;

  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!username || !password) {
      void message.warning('Введите логин и пароль');
      return;
    }
    setResult(null);
    testMutation.mutate();
  };

  return (
    <Row gutter={[16, 16]}>
      <Col xs={24} lg={10}>
        <Card title="Настройки подключения к LDAP" size="small" loading={settingsQuery.isLoading}>
          {settings && (
            <Descriptions column={1} size="small">
              <Descriptions.Item label="Режим">
                <Tag color={settings.mode === 'self-bind' ? 'green' : 'blue'}>
                  {settings.mode === 'self-bind' ? 'Self-bind (без сервисной учётки)' : 'Service-bind'}
                </Tag>
              </Descriptions.Item>
              <Descriptions.Item label="URL">
                <Typography.Text code>{settings.url}</Typography.Text>
                {settings.tls_insecure && <Tag color="orange" style={{ marginLeft: 8 }}>без проверки сертификата</Tag>}
              </Descriptions.Item>
              <Descriptions.Item label="Base DN"><Typography.Text code>{settings.base_dn}</Typography.Text></Descriptions.Item>
              <Descriptions.Item label="Bind DN">{settings.bind_dn ? <Typography.Text code>{settings.bind_dn}</Typography.Text> : '—'}</Descriptions.Item>
              <Descriptions.Item label="objectClass"><Typography.Text code>{settings.object_class}</Typography.Text></Descriptions.Item>
              <Descriptions.Item label="Атрибуты">
                вход <Typography.Text code>{settings.user_attr}</Typography.Text>, имя{' '}
                <Typography.Text code>{settings.name_attr}</Typography.Text>, почта{' '}
                <Typography.Text code>{settings.mail_attr}</Typography.Text>
              </Descriptions.Item>
              <Descriptions.Item label="UPN-суффикс">{settings.upn_suffix || '—'}</Descriptions.Item>
              <Descriptions.Item label="NetBIOS-домен">{settings.netbios_domain || '—'}</Descriptions.Item>
              <Descriptions.Item label="Группа admin">{settings.admin_group_dn || '—'}</Descriptions.Item>
              <Descriptions.Item label="Пул / таймаут / retry">
                {settings.pool_size} / {settings.timeout} / {settings.retry}
              </Descriptions.Item>
            </Descriptions>
          )}
        </Card>
      </Col>
      <Col xs={24} lg={14}>
        <Card
          title={<Space><SafetyCertificateOutlined /> Проверка авторизации в LDAP</Space>}
          size="small"
        >
          <form onSubmit={submit}>
            <Space direction="vertical" style={{ width: '100%' }} size={8}>
              <Input
                prefix={<UserOutlined />}
                placeholder="Логин (короткое имя, DOMAIN\user или user@unicont.spb)"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                autoComplete="username"
              />
              <Input.Password
                placeholder="Пароль доменной учётной записи"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete="current-password"
              />
              <Space>
                <Button type="primary" htmlType="submit" loading={testMutation.isPending}>
                  Проверить вход
                </Button>
                <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                  Пароль используется только для bind и не сохраняется.
                </Typography.Text>
              </Space>
            </Space>
          </form>

          {result && (
            <div style={{ marginTop: 16 }}>
              <Alert
                type={result.trace.ok ? 'success' : 'error'}
                showIcon
                message={result.trace.ok ? 'ОК — авторизация в LDAP выполнена' : 'Ошибка авторизации'}
                description={`Режим: ${result.trace.mode}`}
              />

              <Typography.Title level={5} style={{ marginTop: 16 }}>Лог попытки</Typography.Title>
              <div style={{ background: '#fafafa', border: '1px solid #eee', borderRadius: 6, padding: 12, fontFamily: 'monospace', fontSize: 12 }}>
                {result.trace.steps.map((s, i) => (
                  <div key={i} style={{ padding: '2px 0' }}>
                    <Tag color={s.ok ? 'green' : 'red'} style={{ marginRight: 8 }}>{s.ok ? 'OK' : 'FAIL'}</Tag>
                    <b>{stepNames[s.step] ?? s.step}</b>
                    <span style={{ color: '#888' }}> [{s.ms}мс]</span>
                    {s.detail && <div style={{ paddingLeft: 52, color: s.ok ? '#555' : '#cf1322' }}>{s.detail}</div>}
                  </div>
                ))}
              </div>

              {user && (
                <>
                  <Typography.Title level={5} style={{ marginTop: 16 }}>
                    <Space><UserOutlined /> Данные пользователя</Space>
                  </Typography.Title>
                  <pre
                    style={{
                      background: '#f6f8fa', border: '1px solid #e1e4e8', borderRadius: 6,
                      padding: 12, fontSize: 12, overflow: 'auto', margin: 0,
                    }}
                  >
                    {JSON.stringify(user, null, 2)}
                  </pre>
                </>
              )}
            </div>
          )}
        </Card>
      </Col>
    </Row>
  );
}
