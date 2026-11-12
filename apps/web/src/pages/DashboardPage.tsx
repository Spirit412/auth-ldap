import { Card, Col, Descriptions, Row, Typography, Tag } from 'antd';
import { useQuery } from '@tanstack/react-query';
import { fetchMe } from '../services/auth';
import { useAuthStore } from '../stores/auth';
import { SessionsTable } from '../features/sessions/SessionsTable';

export function DashboardPage() {
  const user = useAuthStore((s) => s.user);
  const meQuery = useQuery({ queryKey: ['me'], queryFn: fetchMe });

  const profile = meQuery.data ?? undefined;

  return (
    <Row gutter={[16, 16]}>
      <Col xs={24} lg={10}>
        <Card title="Мой профиль" size="small">
          <Descriptions column={1} size="small">
            <Descriptions.Item label="Username">{profile?.username ?? user?.username}</Descriptions.Item>
            <Descriptions.Item label="Имя">{profile?.display_name || user?.displayName || '—'}</Descriptions.Item>
            <Descriptions.Item label="Email">{profile?.email || user?.email || '—'}</Descriptions.Item>
            <Descriptions.Item label="Роли">
              {(profile?.roles ?? user?.roles ?? []).length
                ? (profile?.roles ?? user?.roles ?? []).map((r) => <Tag key={r} color="blue">{r}</Tag>)
                : '—'}
            </Descriptions.Item>
            <Descriptions.Item label="ID (UUIDv7)">
              <Typography.Text code>{profile?.id ?? '—'}</Typography.Text>
            </Descriptions.Item>
            <Descriptions.Item label="Создан">{profile?.created_at ?? '—'}</Descriptions.Item>
            <Descriptions.Item label="Обновлён">{profile?.updated_at ?? '—'}</Descriptions.Item>
            <Descriptions.Item label="Последний вход">{profile?.last_login_at ?? '—'}</Descriptions.Item>
          </Descriptions>
        </Card>
      </Col>
      <Col xs={24} lg={14}>
        <Card title="Активные сессии" size="small">
          <SessionsTable />
        </Card>
      </Col>
    </Row>
  );
}
