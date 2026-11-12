import { Layout, Menu, Button, Tag, Space, Typography, App as AntApp } from 'antd';
import { LogoutOutlined, DashboardOutlined, TeamOutlined, MenuFoldOutlined, MenuUnfoldOutlined } from '@ant-design/icons';
import { Outlet, useNavigate, useRouterState } from '@tanstack/react-router';
import { useAuthStore, isAdmin } from '../stores/auth';
import { useUiStore } from '../stores/ui';
import { logout } from '../services/auth';

const { Header, Sider, Content } = Layout;

export function ProtectedLayout() {
  const navigate = useNavigate();
  const pathname = useRouterState({ select: (s) => s.location.pathname });
  const { user, clear } = useAuthStore();
  const { siderCollapsed, toggleSider } = useUiStore();
  const { message } = AntApp.useApp();

  const onLogout = async () => {
    await logout();
    clear();
    void message.success('Вы вышли из системы');
    void navigate({ to: '/login' });
  };

  return (
    <Layout style={{ minHeight: '100vh' }}>
      <Sider collapsible collapsed={siderCollapsed} trigger={null}>
        <div style={{ color: '#fff', padding: 16, fontWeight: 600, fontSize: siderCollapsed ? 12 : 16 }}>
          {siderCollapsed ? 'APS' : 'APS · Auth Proxy'}
        </div>
        <Menu
          theme="dark"
          mode="inline"
          selectedKeys={[pathname]}
          items={[
            { key: '/', icon: <DashboardOutlined />, label: 'Дашборд', onClick: () => void navigate({ to: '/' }) },
            ...(isAdmin(useAuthStore.getState())
              ? [{ key: '/users', icon: <TeamOutlined />, label: 'Пользователи', onClick: () => void navigate({ to: '/users' }) }]
              : []),
          ]}
        />
      </Sider>
      <Layout>
        <Header style={{ background: '#fff', display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '0 24px' }}>
          <Space>
            <Button type="text" onClick={toggleSider} icon={siderCollapsed ? <MenuUnfoldOutlined /> : <MenuFoldOutlined />} />
            <Typography.Text strong>Центральная аутентификация AD</Typography.Text>
          </Space>
          <Space>
            <Typography.Text>{user?.displayName || user?.username}</Typography.Text>
            {isAdmin(useAuthStore.getState()) && <Tag color="blue">admin</Tag>}
            <Button icon={<LogoutOutlined />} onClick={() => void onLogout()}>
              Выйти
            </Button>
          </Space>
        </Header>
        <Content style={{ padding: 24 }}>
          <Outlet />
        </Content>
      </Layout>
    </Layout>
  );
}
