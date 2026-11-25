const API_BASE = import.meta.env.VITE_API_URL || '';

function getToken() {
  return localStorage.getItem('dlp_token');
}

export function setToken(token) {
  if (token) {
    localStorage.setItem('dlp_token', token);
  } else {
    localStorage.removeItem('dlp_token');
  }
}

async function apiFetch(path, options = {}) {
  const token = getToken();
  const headers = { ...(options.headers || {}) };
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  if (!(options.body instanceof FormData) && !headers['Content-Type']) {
    headers['Content-Type'] = 'application/json';
  }

  const res = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers,
  });

  const contentType = res.headers.get('content-type') || '';
  const data = contentType.includes('application/json') ? await res.json() : await res.text();

  if (!res.ok) {
    const msg = (data && data.detail) ? data.detail : `Request failed (${res.status})`;
    const err = new Error(msg);
    err.status = res.status;
    err.data = data;
    throw err;
  }
  return data;
}

export const api = {
  login: (email, password) =>
    apiFetch('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    }),
  register: (email, password, full_name, role = 'user') =>
    apiFetch('/api/auth/register', {
      method: 'POST',
      body: JSON.stringify({ email, password, full_name, role }),
    }),
  logout: () => apiFetch('/api/auth/logout', { method: 'POST' }),
  getMe: () => apiFetch('/api/auth/me'),

  uploadFile: (file) => {
    const formData = new FormData();
    formData.append('file', file);
    return apiFetch('/api/scan/upload', {
      method: 'POST',
      body: formData,
    });
  },
  downloadFileUrl: (eventId) => `${API_BASE}/api/scan/download/${eventId}`,
  downloadFileBlob: async (eventId, filename) => {
    const token = getToken();
    const res = await fetch(`${API_BASE}/api/scan/download/${eventId}`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      throw new Error(data.detail || 'Download failed');
    }
    const blob = await res.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    window.URL.revokeObjectURL(url);
  },

  getDashboardStats: () => apiFetch('/api/dashboard/stats'),
  getEvents: (params = {}) => {
    const qs = new URLSearchParams(params).toString();
    return apiFetch(`/api/events${qs ? `?${qs}` : ''}`);
  },
  getEventDetail: (eventId) => apiFetch(`/api/events/${eventId}`),
  getAuditLogs: () => apiFetch('/api/audit-logs'),

  getPolicies: () => apiFetch('/api/policies'),
  updatePolicy: (id, payload) =>
    apiFetch(`/api/policies/${id}`, {
      method: 'PUT',
      body: JSON.stringify(payload),
    }),

  getSecurityMode: () => apiFetch('/api/security/mode'),
  setSecurityMode: (mode) =>
    apiFetch('/api/security/mode', {
      method: 'POST',
      body: JSON.stringify({ mode }),
    }),
  getS3Audit: () => apiFetch('/api/security/s3-audit'),
  getBucketsComparison: () => apiFetch('/api/security/buckets-comparison'),
  runReDoSTest: (payload) =>
    apiFetch('/api/security/redos-test', {
      method: 'POST',
      body: JSON.stringify({ payload }),
    }),
};
