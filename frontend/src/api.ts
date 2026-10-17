import axios from 'axios';
import {
  AuthResponse, User, RecipientOption, DocumentItem,
  SendDocumentResponse, InvestigationResult, AdminStats,
  InvestigationHistoryItem, PrepareStatusResponse, PrepareDocumentResponse
} from './types';

const API_BASE = '/api';

const api = axios.create({
  baseURL: API_BASE,
});

// Attach Authorization header if token exists
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('secureshare_token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

export const authApi = {
  login: async (username: string, password: string, role?: string): Promise<AuthResponse> => {
    const res = await api.post<AuthResponse>('/login', { username, password, role });
    return res.data;
  },
  getMe: async (): Promise<User> => {
    const res = await api.get<User>('/me');
    return res.data;
  }
};

export const adminApi = {
  getRecipients: async (): Promise<RecipientOption[]> => {
    const res = await api.get<RecipientOption[]>('/admin/recipients');
    return res.data;
  },
  getStats: async (): Promise<AdminStats> => {
    const res = await api.get<AdminStats>('/admin/stats');
    return res.data;
  },
  sendDocument: async (file: File, recipientId: string): Promise<SendDocumentResponse> => {
    const formData = new FormData();
    formData.append('file', file);
    formData.append('recipient_id', recipientId);
    const res = await api.post<SendDocumentResponse>('/admin/documents', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    });
    return res.data;
  }
};

export const recipientApi = {
  getDocuments: async (): Promise<DocumentItem[]> => {
    const res = await api.get<DocumentItem[]>('/recipient/documents');
    return res.data;
  },
  openDocumentBlob: async (documentId: string): Promise<Blob> => {
    const res = await api.post(`/recipient/documents/${documentId}/open`, null, {
      responseType: 'blob',
    });
    return res.data;
  },
  prepareDocument: async (documentId: string): Promise<PrepareDocumentResponse> => {
    const res = await api.post<PrepareDocumentResponse>(`/recipient/documents/${documentId}/prepare`);
    return res.data;
  },
  getPrepareStatus: async (jobId: string): Promise<PrepareStatusResponse> => {
    const res = await api.get<PrepareStatusResponse>(`/recipient/documents/prepare-status/${jobId}`);
    return res.data;
  },
  downloadProtectedPdf: async (jobId: string): Promise<Blob> => {
    const res = await api.get(`/recipient/documents/download-protected/${jobId}`, {
      responseType: 'blob',
    });
    return res.data;
  }
};

export const investigatorApi = {
  analyzeDocument: async (file: File): Promise<InvestigationResult> => {
    const formData = new FormData();
    formData.append('file', file);
    const res = await api.post<InvestigationResult>('/investigator/analyze', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    });
    return res.data;
  },
  getHistory: async (): Promise<InvestigationHistoryItem[]> => {
    const res = await api.get<InvestigationHistoryItem[]>('/investigator/history');
    return res.data;
  },
  downloadReport: async (evidenceData: any): Promise<Blob> => {
    const res = await api.post('/investigator/report', evidenceData, {
      responseType: 'blob',
    });
    return res.data;
  }
};

export default api;
