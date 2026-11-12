import { Card, Typography } from 'antd';
import { UsersTable } from '../features/users/UsersTable';

export function UsersPage() {
  return (
    <Card title={<Typography.Title level={5} style={{ margin: 0 }}>Пользователи (кэш профилей AD)</Typography.Title>} size="small">
      <Typography.Paragraph type="secondary" style={{ marginBottom: 12 }}>
        Данные обновляются при каждом успешном входе. Пароли не хранятся. Удаление — мягкое
        (deleted_at); следующий вход пользователя реактивирует профиль.
      </Typography.Paragraph>
      <UsersTable />
    </Card>
  );
}
