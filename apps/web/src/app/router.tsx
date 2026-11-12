import { createRootRoute, createRoute, createRouter, Outlet, redirect } from '@tanstack/react-router';
import { bootstrapSession } from '../services/auth';
import { useAuthStore } from '../stores/auth';
import { ProtectedLayout } from '../components/ProtectedLayout';
import { LoginPage } from '../pages/LoginPage';
import { DashboardPage } from '../pages/DashboardPage';
import { UsersPage } from '../pages/UsersPage';

const rootRoute = createRootRoute({ component: () => <Outlet /> });

const loginRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/login',
  component: LoginPage,
});

// Protected subtree: guarantees an access token exists (silent refresh via
// the HttpOnly cookie happens at bootstrap and on demand, F-15).
const protectedRoute = createRoute({
  getParentRoute: () => rootRoute,
  id: 'protected',
  beforeLoad: async () => {
    if (!useAuthStore.getState().accessToken) {
      const token = await bootstrapSession();
      if (!token) {
        throw redirect({ to: '/login', search: { expired: '1' } });
      }
    }
  },
  component: ProtectedLayout,
});

const indexRoute = createRoute({
  getParentRoute: () => protectedRoute,
  path: '/',
  component: DashboardPage,
});

const usersRoute = createRoute({
  getParentRoute: () => protectedRoute,
  path: '/users',
  component: UsersPage,
});

const routeTree = rootRoute.addChildren([
  loginRoute,
  protectedRoute.addChildren([indexRoute, usersRoute]),
]);

export const router = createRouter({ routeTree });

declare module '@tanstack/react-router' {
  interface Register {
    router: typeof router;
  }
}
