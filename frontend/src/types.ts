export type UserRole = 'ADMIN' | 'RECIPIENT' | 'INVESTIGATOR';

export interface User {
  id: string;
  username: string;
  name: string;
  role: UserRole;
  ml_kem_public_key?: string;
  ml_dsa_public_key?: string;
}

export interface AuthResponse {
  access_token: string;
  token_type: string;
  user: User;
}

export interface RecipientOption {
  id: string;
  username: string;
  name: string;
}

export interface DocumentItem {
  id: string;
  filename: string;
  created_at: string;
  status: string;
  shared_by: string;
}

export interface SendDocumentResponse {
  success: boolean;
  message: string;
  document_id: string;
  filename: string;
  recipient_name: string;
  recipient_username: string;
}

export interface PrepareDocumentResponse {
  job_id: string;
  status: string;
}

export interface PrepareStatusResponse {
  job_id: string;
  status: 'PROCESSING' | 'COMPLETED' | 'FAILED';
  current_step?: string;
  completed_steps: string[];
  error?: string;
  watermark_id?: string;
  session_id?: string;
  document_id?: string;
  filename?: string;
}

export interface AdminStats {
  documents_count: number;
  recipients_count: number;
  access_events_count: number;
  protected_copies_count: number;
}

export interface InvestigationStage {
  id: number;
  name: string;
  status: 'PENDING' | 'PROCESSING' | 'COMPLETED' | 'FAILED';
  detail?: string;
}

export interface TechnicalEvidence {
  document_sha256: string;
  watermark_id?: string;
  session_id?: string;
  event_id?: string;
  event_hash?: string;
  signature_algorithm: string;
  signature_preview?: string;
  key_identifier?: string;
  timestamp?: string;
  ledger_status: string;
  ledger_message: string;
}

export interface InvestigationResult {
  investigation_id?: string;
  status: 'MATCH_FOUND' | 'NO_WATERMARK' | 'EVENT_NOT_FOUND' | 'SIGNATURE_FAILED' | 'INTEGRITY_FAILED';
  title: string;
  status_label: string;
  document_filename?: string;
  watermark_id?: string;
  access_event_id?: string;
  recipient_identity?: string;
  session_id?: string;
  access_timestamp?: string;
  forensic_statement: string;
  attribution_disclaimer: string;
  verification_checks: Array<{ label: string; verified: boolean }>;
  technical_evidence?: TechnicalEvidence;
  stages: InvestigationStage[];
  explanations?: string[];
}

export interface InvestigationHistoryItem {
  investigation_id: string;
  document_name: string;
  status: string;
  status_label: string;
  recipient_identity?: string;
  verification_status: string;
  timestamp: string;
}

