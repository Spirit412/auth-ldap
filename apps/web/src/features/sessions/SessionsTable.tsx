import { Table, Button, Popconfirm, Tag, App as AntApp } from 'antd';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { listSessions, revokeSession } from '../../services/sessions';
import { useAuthStore, isAdmin } from '../../stores/auth';

export function SessionsTable({ usernameFilter }: { usernameFilter?: string }) {
  const token = useAuthStore((s) => s.accessToken);
  const admin = isAdmin(useAuthStore.getState());
  const [cursor, setCursor] = useState<string | undefined>();
  const qc = useQueryClient();
  const { message } = AntApp.useApp();

  const query = useQuery({
    enabled: !!token && admin,
    queryKey: ['sessions', usernameFilter, cursor],
    queryFn: () => listSessions({ username: usernameFilter, limit: 20, cursor }),
  });

  const revoke = useMutation({
    mutationFn: revokeSession,
    onSuccess: () => {
      void message.success('Сессия отозвана');
      void qc.invalidateQueries({ queryKey: ['sessions'] });
    },
    onError: (e) => void message.error(`Ошибка отзыва: ${e instanceof Error ? e.message : 'неизвестно'}`),
  });

  if (!admin) {
    return <Tag>Список сессий доступен только администраторам</Tag>;
  }

  return (
    <>
      <Table
        rowKey="id"
        size="small"
        loading={query.isLoading}
        dataSource={query.data?.items ?? []}
        pagination={false}
        columns={[
          { title: 'Пользователь', dataIndex: 'username' },
          { title: 'Создана', dataIndex: 'created_at', width: 190 },
          { title: 'IP', dataIndex: 'ip', width: 150 },
          { title: 'User-Agent', dataIndex: 'user_agent', ellipsis: true },
          {
            title: '',
            width: 130,
            render: (_, rec) => (
              <Popconfirm title="Отозвать сессию?" onConfirm={() => revoke.mutate(rec.id)}>
                <Button danger size="small" loading={revoke.isPending && revoke.variables === rec.id}>
                  Отозвать
                </Button>
              </Popconfirm>
            ),
          },
        ]}
      />
      <div style={{ marginTop: 12, display: 'flex', gap: 8 }}>
        <Button size="small" disabled={!cursor} onClick={() => setCursor(undefined)}>
          В начало
        </Button>
        <Button size="small" disabled={!query.data?.next_cursor} onClick={() => setCursor(query.data?.next_cursor)}>
          Далее
        </Button>
      </div>
    </>
  );
}
