import { Alert, Card, Typography } from 'antd';
import { LoginForm } from '../features/auth/LoginForm';
import { useAuthStore } from '../stores/auth';
import { useNavigate, useRouterState } from '@tanstack/react-router';
import { useEffect } from 'react';

export function LoginPage() {
  const navigate = useNavigate();
  const token = useAuthStore((s) => s.accessToken);
  const expired = useRouterState({ select: (s) => (s.location.search as { expired?: string }).expired === '1' });

  // Already authenticated (e.g. silent refresh succeeded) — go to dashboard.
  useEffect(() => {
    if (token) void navigate({ to: '/' });
  }, [token, navigate]);

  return (
    <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', background: '#f5f5f5' }}>
      <Card style={{ width: 380 }}>
        <Typography.Title level={4} style={{ textAlign: 'center' }}>
          APS — вход по учётной записи AD
        </Typography.Title>
        {expired && (
          <Alert
            type="warning"
            showIcon
            message="Сессия истекла"
            description="Войдите заново, чтобы продолжить."
            style={{ marginBottom: 16 }}
          />
        )}
        <LoginForm onSuccess={() => void navigate({ to: '/' })} />
      </Card>
    </div>
  );
}
