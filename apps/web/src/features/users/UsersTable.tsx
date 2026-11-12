import { Table, Button, Popconfirm, Tag, Input, Select, Space, App as AntApp, Drawer, Descriptions, Form, Typography } from 'antd';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState, type ReactNode } from 'react';
import { listUsers, deleteUser, restoreUser, updateUser, type UsersQuery } from '../../services/users';
import type { User } from '@aps/shared-types';

export function UsersTable() {
  const [q, setQ] = useState('');
  const [status, setStatus] = useState<NonNullable<UsersQuery['status']>>('active');
  const [cursor, setCursor] = useState<string | undefined>();
  const [detail, setDetail] = useState<User | null>(null);
  const [editing, setEditing] = useState(false);
  const [editForm] = Form.useForm<{ display_name: string; email: string }>();
  const qc = useQueryClient();
  const { message } = AntApp.useApp();

  const query = useQuery({
    queryKey: ['users', q, status, cursor],
    queryFn: () => listUsers({ q: q || undefined, status, limit: 20, cursor }),
  });

  const invalidate = () => {
    void qc.invalidateQueries({ queryKey: ['users'] });
    void qc.invalidateQueries({ queryKey: ['user'] });
  };

  const remove = useMutation({
    mutationFn: deleteUser,
    onSuccess: () => {
      void message.success('Профиль удалён (soft delete), сессии отозваны');
      invalidate();
      setDetail(null);
    },
    onError: (e) => void message.error(`Ошибка удаления: ${e instanceof Error ? e.message : 'неизвестно'}`),
  });

  const restore = useMutation({
    mutationFn: restoreUser,
    onSuccess: (u) => {
      void message.success(`Профиль ${u.username} восстановлен`);
      invalidate();
      setDetail(null);
    },
    onError: (e) => void message.error(`Ошибка восстановления: ${e instanceof Error ? e.message : 'неизвестно'}`),
  });

  const save = useMutation({
    mutationFn: (vals: { display_name: string; email: string }) =>
      updateUser(detail!.id, vals),
    onSuccess: (u) => {
      void message.success('Профиль сохранён (локальная правка кэша)');
      setDetail(u);
      setEditing(false);
      invalidate();
    },
    onError: (e) => void message.error(`Ошибка сохранения: ${e instanceof Error ? e.message : 'неизвестно'}`),
  });

  const openDetail = (u: User) => {
    setDetail(u);
    setEditing(false);
    editForm.setFieldsValue({ display_name: u.display_name ?? '', email: u.email ?? '' });
  };

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
        onRow={(rec) => ({ onClick: () => openDetail(rec), style: { cursor: 'pointer' } })}
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
            title: 'Статус',
            dataIndex: 'deleted_at',
            width: 130,
            render: (v?: string) => (v ? <Tag color="red">удалён</Tag> : <Tag color="green">активен</Tag>),
          },
          {
            title: '',
            width: 200,
            render: (_, rec) => (
              <Space onClick={(e) => e.stopPropagation()}>
                {rec.deleted_at ? (
                  <Popconfirm title="Восстановить профиль?" onConfirm={() => restore.mutate(rec.id)}>
                    <Button size="small" loading={restore.isPending && restore.variables === rec.id}>
                      Восстановить
                    </Button>
                  </Popconfirm>
                ) : (
                  <Button size="small" onClick={() => openDetail(rec)}>
                    Изменить
                  </Button>
                )}
                {!rec.deleted_at && (
                  <Popconfirm
                    title="Удалить профиль и отозвать сессии?"
                    onConfirm={() => remove.mutate(rec.id)}
                  >
                    <Button danger size="small" loading={remove.isPending && remove.variables === rec.id}>
                      Удалить
                    </Button>
                  </Popconfirm>
                )}
              </Space>
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

      <Drawer
        title={detail ? `Профиль: ${detail.username}` : ''}
        placement="right"
        width={480}
        open={!!detail}
        onClose={() => setDetail(null)}
        destroyOnHidden
      >
        {detail && (
          <>
            <Descriptions column={1} size="small" bordered>
              <Descriptions.Item label="ID"><TypographyCode>{detail.id}</TypographyCode></Descriptions.Item>
              <Descriptions.Item label="Username">{detail.username}</Descriptions.Item>
              <Descriptions.Item label="Роли">{detail.roles?.length ? detail.roles.map((r) => <Tag key={r} color="blue">{r}</Tag>) : '—'}</Descriptions.Item>
              <Descriptions.Item label="Создан">{detail.created_at}</Descriptions.Item>
              <Descriptions.Item label="Обновлён">{detail.updated_at}</Descriptions.Item>
              <Descriptions.Item label="Последний вход">{detail.last_login_at ?? '—'}</Descriptions.Item>
              <Descriptions.Item label="Удалён">{String(detail.deleted_at ?? "—")}</Descriptions.Item>
            </Descriptions>

            {detail.deleted_at ? (
              <Popconfirm title="Восстановить профиль?" onConfirm={() => restore.mutate(detail.id)}>
                <Button style={{ marginTop: 16 }} loading={restore.isPending}>
                  Восстановить профиль
                </Button>
              </Popconfirm>
            ) : (
              <>
                {editing ? (
                  <Form
                    form={editForm}
                    layout="vertical"
                    style={{ marginTop: 16 }}
                    onFinish={(vals) => save.mutate(vals)}
                  >
                    <Form.Item
                      name="display_name"
                      label="Отображаемое имя"
                      rules={[{ max: 512, message: 'До 512 символов' }]}
                    >
                      <Input />
                    </Form.Item>
                    <Form.Item
                      name="email"
                      label="Email"
                      rules={[{ type: 'email', message: 'Некорректный email' }]}
                    >
                      <Input />
                    </Form.Item>
                    <Space>
                      <Button type="primary" htmlType="submit" loading={save.isPending}>
                        Сохранить
                      </Button>
                      <Button onClick={() => setEditing(false)}>Отмена</Button>
                    </Space>
                  </Form>
                ) : (
                  <Button style={{ marginTop: 16 }} onClick={() => setEditing(true)}>
                    Редактировать имя и email
                  </Button>
                )}
                <Typography.Paragraph type="secondary" style={{ marginTop: 12, fontSize: 12 }}>
                  Правки — локальные: при следующем входе пользователя AD перезапишет
                  display_name и email значениями из каталога.
                </Typography.Paragraph>
                <Popconfirm title="Удалить профиль и отозвать сессии?" onConfirm={() => remove.mutate(detail.id)}>
                  <Button danger loading={remove.isPending}>Удалить профиль</Button>
                </Popconfirm>
              </>
            )}
          </>
        )}
      </Drawer>
    </>
  );
}

function TypographyCode({ children }: { children: ReactNode }) {
  return <code style={{ fontSize: 11, wordBreak: 'break-all' }}>{children}</code>;
}
