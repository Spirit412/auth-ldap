import { create } from 'zustand';

interface UiState {
  siderCollapsed: boolean;
  toggleSider: () => void;
}

export const useUiStore = create<UiState>((set) => ({
  siderCollapsed: false,
  toggleSider: () => set((s) => ({ siderCollapsed: !s.siderCollapsed })),
}));
