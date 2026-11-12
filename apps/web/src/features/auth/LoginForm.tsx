import { Button, Form, Input, App as AntApp } from 'antd';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { useState } from 'react';
import { login, toAuthUser, fetchMe } from '../../services/auth';
import { useAuthStore } from '../../stores/auth';
import { ApiError } from '../../lib/api';

// F-14: React Hook Form + Zod; AntD renders the fields.
const schema = z.object({
  username: z.string().min(1, 'Введите имя пользователя').max(128),
  password: z.string().min(1, 'Введите пароль').max(256),
});
type FormValues = z.infer<typeof schema>;

export function LoginForm({ onSuccess }: { onSuccess: () => void }) {
  const { register, handleSubmit, formState } = useForm<FormValues>({
    resolver: zodResolver(schema),
    defaultValues: { username: '', password: '' },
  });
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const setAuth = useAuthStore((s) => s.setAuth);
  const { message } = AntApp.useApp();

  const onSubmit = handleSubmit(async (values) => {
    setSubmitting(true);
    setError(null);
    try {
      const tokens = await login(values);
      // Refresh token stays in the HttpOnly cookie / response body only —
      // nothing is written to localStorage/sessionStorage (S-10).
      setAuth(tokens.access_token, null);
      const me = await fetchMe();
      setAuth(tokens.access_token, toAuthUser(me));
      void message.success('Вход выполнен');
      onSuccess();
    } catch (e) {
      // F-18: do not distinguish "no such user" from "wrong password".
      if (e instanceof ApiError) {
        setError(e.status === 429 ? `Слишком много попыток. Повторите через ~${e.retryAfter ?? 60} c.` : 'Неверное имя пользователя или пароль');
      } else {
        setError('Сервис аутентификации недоступен, попробуйте позже');
      }
    } finally {
      setSubmitting(false);
    }
  });

  return (
    <form onSubmit={onSubmit} noValidate>
      <Form layout="vertical" component="div">
        <Form.Item label="Имя пользователя" validateStatus={formState.errors.username ? 'error' : ''} help={formState.errors.username?.message}>
          <Input autoComplete="username" autoFocus {...register('username')} />
        </Form.Item>
        <Form.Item label="Пароль" validateStatus={formState.errors.password ? 'error' : ''} help={formState.errors.password?.message}>
          <Input.Password autoComplete="current-password" {...register('password')} />
        </Form.Item>
        {error && (
          <Form.Item>
            <Alertish text={error} />
          </Form.Item>
        )}
        <Button type="primary" htmlType="submit" block loading={submitting}>
          Войти
        </Button>
      </Form>
    </form>
  );
}

function Alertish({ text }: { text: string }) {
  return (
    <div style={{ color: '#cf1322', background: '#fff1f0', border: '1px solid #ffa39e', borderRadius: 6, padding: '6px 10px', fontSize: 13 }}>
      {text}
    </div>
  );
}
