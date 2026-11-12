import { create } from 'zustand';

export interface AuthUser {
  username: string;
  displayName: string;
  email: string;
  roles: string[];
}

interface AuthState {
  /** Access token lives in memory only. It is NEVER written to
   *  localStorage/sessionStorage (ТЗ S-10 / F-20). On reload it is restored
   *  via a silent cookie-based /auth/refresh call. */
  accessToken: string | null;
  user: AuthUser | null;
  setAuth: (token: string, user: AuthUser | null) => void;
  setUser: (user: AuthUser | null) => void;
  clear: () => void;
}

export const useAuthStore = create<AuthState>((set) => ({
  accessToken: null,
  user: null,
  setAuth: (accessToken, user) => set({ accessToken, user }),
  setUser: (user) => set({ user }),
  clear: () => set({ accessToken: null, user: null }),
}));

export const isAdmin = (s: AuthState | Pick<AuthState, 'user'>): boolean =>
  !!s.user?.roles?.includes('admin');
