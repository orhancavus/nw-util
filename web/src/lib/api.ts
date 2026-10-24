import type { Capabilities, HistoryRecord, Job, NetworkContext, ScanSettings, SecurityProfile } from '../types';

const API = '/api/v1';

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API}${path}`, {
    ...init,
    headers: { 'Content-Type': 'application/json', ...init?.headers },
  });
  if (!response.ok) {
    const body = await response.json().catch(() => null);
    const message = body?.detail?.message ?? body?.detail ?? `Request failed (${response.status})`;
    throw new Error(typeof message === 'string' ? message : JSON.stringify(message));
  }
  return response.json() as Promise<T>;
}

export const api = {
  context: () => request<NetworkContext>('/context'),
  capabilities: () => request<Capabilities>('/capabilities'),
  createScan: (settings: ScanSettings) => request<Job>('/scans', { method: 'POST', body: JSON.stringify(settings) }),
  getScan: (id: string) => request<Job>(`/scans/${id}`),
  cancelScan: (id: string) => request<Job>(`/scans/${id}`, { method: 'DELETE' }),
  createWatch: (settings: ScanSettings, interval: number) =>
    request<Job>('/watches', { method: 'POST', body: JSON.stringify({ ...settings, interval }) }),
  stopWatch: (id: string) => request<Job>(`/watches/${id}`, { method: 'DELETE' }),
  history: (q = '') => request<{ records: HistoryRecord[]; count: number }>(`/history${q ? `?q=${encodeURIComponent(q)}` : ''}`),
  setAlias: (target: string, name: string) =>
    request<{ target: string; name: string }>(`/aliases/${encodeURIComponent(target)}`, {
      method: 'PUT',
      body: JSON.stringify({ name }),
    }),
  removeAlias: (target: string) => request(`/aliases/${encodeURIComponent(target)}`, { method: 'DELETE' }),
  createSecurity: (target: string) =>
    request<Job>('/security-profiles', { method: 'POST', body: JSON.stringify({ target, timeout: 1 }) }),
  getSecurity: (id: string) => request<Job<SecurityProfile>>(`/security-profiles/${id}`),
  eventUrl: (kind: 'scans' | 'watches' | 'security-profiles', id: string) => `${API}/${kind}/${id}/events`,
  exportUrl: (id: string, format: 'json' | 'csv') => `${API}/scans/${id}/export?format=${format}`,
};
