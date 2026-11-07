import axios from 'axios'

// Same origin in production (the Go backend serves this UI). In development
// (`npm run dev`) set NEXT_PUBLIC_API_URL=http://localhost:8080 and run the
// backend with CORS_ALLOWED_ORIGIN=http://localhost:3000.
const API_URL = process.env.NEXT_PUBLIC_API_URL || ''

const api = axios.create({
  baseURL: API_URL,
  withCredentials: true,
  headers: {
    'Content-Type': 'application/json',
    // The backend refuses state-changing requests without it (CSRF guard).
    'X-Requested-With': 'stepca-ui',
  },
})

export interface Certificate {
  id: string
  cn: string
  sans: string[]
  serial: string
  not_after: string
  status: string
  key_strategy: string
  owner: string
  profile: string
  source: 'ui' | 'import' | 'cert-manager' | string
  external_ref?: string
  created_at: string
  updated_at: string
}

export type Role = 'admin' | 'viewer'

export interface AuthUser {
  username: string
  role: Role
  auth?: 'session' | 'proxy'
}

export interface Profile {
  name: string
  label: string
  key_type?: string
  key_size?: number
  default_days: number
  max_days: number
}

export interface UserAccount {
  id: number
  username: string
  role: Role
  created_at: string
}

export interface IssueRequest {
  profile?: string
  cn: string
  sans: string[]
  not_after_days: number
  format: 'pem' | 'pfx'
  pfx_password?: string
}

export interface SignCSRRequest {
  profile?: string
  csr_pem: string
  not_after_days: number
}

export interface CertBundle {
  data: string
  filename: string
  mime_type: string
}

export interface CASettings {
  ca_url: string
  root_fingerprint: string
  acme_directories: string[]
}

export interface VersionInfo {
  version: string
  commit: string
  build_date: string
  go_version?: string
}

export interface FrontendSystemInfo {
  version: string
  commit: string
  build_date: string
  node_version: string
  next_version: string
}

export const certificateApi = {
  // Issue a new certificate
  issueCertificate: async (data: IssueRequest) => {
    const response = await api.post('/api/certs/issue', data)
    return response.data
  },

  // Sign a CSR
  signCSR: async (data: SignCSRRequest) => {
    const response = await api.post('/api/certs/sign-csr', data)
    return response.data
  },

  // List certificates
  listCertificates: async (params?: {
    limit?: number
    offset?: number
    status?: string
  }) => {
    const response = await api.get('/api/certs', { params })
    return response.data
  },

  // Get a specific certificate
  getCertificate: async (id: string) => {
    const response = await api.get(`/api/certs/${id}`)
    return response.data
  },

  // Renew a certificate
  renewCertificate: async (id: string) => {
    const response = await api.post(`/api/certs/${id}/renew`)
    return response.data
  },

  // Revoke a certificate
  revokeCertificate: async (id: string) => {
    const response = await api.post(`/api/certs/${id}/revoke`)
    return response.data
  },

  // Get CA settings
  getCASettings: async () => {
    const response = await api.get('/api/settings/ca')
    return response.data
  },

  // Issuance profiles (provisioner + limits)
  listProfiles: async (): Promise<Profile[]> => {
    const response = await api.get('/api/profiles')
    return response.data.profiles
  },

  // Record already-issued certificates (PEM) in the inventory
  importCertificate: async (pem: string) => {
    const response = await api.post('/api/certs/import', { pem })
    return response.data
  },

  // Re-read the cert-manager Certificates now
  syncNow: async () => {
    const response = await api.post('/api/sync')
    return response.data
  },

  // Health check
  health: async () => {
    const response = await api.get('/health')
    return response.data
  },

  // Backend build identity (version, commit, build date, Go version)
  getVersion: async (): Promise<VersionInfo> => {
    const response = await api.get('/api/version')
    return response.data
  },
}

// User accounts and sessions. Login/logout/me are usable by anyone (me
// reports 401 when there's no valid session); the user-management calls
// are admin-only at the backend, so a viewer calling them just gets a 403.
export const authApi = {
  login: async (username: string, password: string): Promise<AuthUser> => {
    const response = await api.post('/api/auth/login', { username, password })
    return response.data
  },

  logout: async (): Promise<void> => {
    await api.post('/api/auth/logout')
  },

  me: async (): Promise<AuthUser> => {
    const response = await api.get('/api/auth/me')
    return response.data
  },

  listUsers: async (): Promise<UserAccount[]> => {
    const response = await api.get('/api/users')
    return response.data.users
  },

  createUser: async (data: { username: string; password: string; role: Role }): Promise<UserAccount> => {
    const response = await api.post('/api/users', data)
    return response.data.user
  },

  updateUser: async (id: number, data: { password?: string; role?: Role }): Promise<UserAccount> => {
    const response = await api.put(`/api/users/${id}`, data)
    return response.data.user
  },

  deleteUser: async (id: number): Promise<void> => {
    await api.delete(`/api/users/${id}`)
  },
}

// Frontend build identity: baked in at build time (static export, no server).
export const getFrontendSystemInfo = async (): Promise<FrontendSystemInfo> => ({
  version: process.env.NEXT_PUBLIC_APP_VERSION || 'unknown',
  commit: process.env.NEXT_PUBLIC_APP_COMMIT || 'unknown',
  build_date: process.env.NEXT_PUBLIC_APP_BUILD_DATE || 'unknown',
  node_version: 'static export',
  next_version: 'static export',
})

export default api
