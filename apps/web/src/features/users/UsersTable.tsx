import { Table, Button, Popconfirm, Tag, Input, Select, Space, App as AntApp } from 'antd';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { listUsers, deleteUser, type UsersQuery } from '../../services/users';

export function UsersTable() {
  const [q, setQ] = useState('');
  const [status, setStatus] = useState<NonNullable<UsersQuery['status']>>('active');
  const [cursor, setCursor] = useState<string | undefined>();
  const qc = useQueryClient();
  const { message } = AntApp.useApp();

  const query = useQuery({
    queryKey: ['users', q, status, cursor],
    queryFn: () => listUsers({ q: q || undefined, status, limit: 20, cursor }),
  });

  const remove = useMutation({
    mutationFn: deleteUser,
    onSuccess: () => {
      void message.success('Профиль удалён (soft delete), сессии отозваны');
      void qc.invalidateQueries({ queryKey: ['users'] });
    },
    onError: (e) => void message.error(`Ошибка удаления: ${e instanceof Error ? e.message : 'неизвестно'}`),
  });

  return (
    <>
      <Space style={{ marginBottom: 16 }} wrap>
        <Input.Search
          placeholder="Поиск: имя / email / username"
          allowClear
          onSearch={(v) => {
            setQ(v);
            setCursor(undefined);
          }}
          style={{ width: 320 }}
        />
        <Select
          value={status}
          style={{ width: 160 }}
          onChange={(v) => {
            setStatus(v);
            setCursor(undefined);
          }}
          options={[
            { value: 'active', label: 'Активные' },
            { value: 'deleted', label: 'Удалённые' },
            { value: 'all', label: 'Все' },
          ]}
        />
      </Space>
      <Table
        rowKey="id"
        size="small"
        loading={query.isLoading}
        dataSource={query.data?.items ?? []}
        pagination={false}
        columns={[
          { title: 'Username', dataIndex: 'username' },
          { title: 'Имя', dataIndex: 'display_name' },
          { title: 'Email', dataIndex: 'email' },
          {
            title: 'Роли',
            dataIndex: 'roles',
            width: 120,
            render: (roles: string[]) =>
              roles?.length ? roles.map((r) => <Tag key={r} color="blue">{r}</Tag>) : '—',
          },
          { title: 'Последний вход', dataIndex: 'last_login_at', width: 190, render: (v?: string) => v ?? '—' },
          {
            title: 'Удалён',
            dataIndex: 'deleted_at',
            width: 190,
            render: (v?: string) => (v ? <Tag color="red">{v}</Tag> : <Tag color="green">активен</Tag>),
          },
          {
            title: '',
            width: 110,
            render: (_, rec) =>
              rec.deleted_at ? (
                <Tag>архив</Tag>
              ) : (
                <Popconfirm
                  title="Удалить профиль и отозвать сессии?"
                  onConfirm={() => remove.mutate(rec.id)}
                >
                  <Button danger size="small" loading={remove.isPending && remove.variables === rec.id}>
                    Удалить
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
