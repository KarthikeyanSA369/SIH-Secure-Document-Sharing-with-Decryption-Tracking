-- =======================================================
-- SecureShare Database Schema
-- Post-Quantum Secure Document Distribution Platform
-- Target Database: MySQL 8.0+
-- =======================================================

CREATE DATABASE IF NOT EXISTS secureshare CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE secureshare;

-- -------------------------------------------------------
-- 1. Users Table
-- Roles: ADMIN, RECIPIENT
-- -------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id VARCHAR(64) PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    name VARCHAR(100) NOT NULL,
    role ENUM('ADMIN', 'RECIPIENT', 'INVESTIGATOR') NOT NULL,
    ml_kem_public_key TEXT,
    ml_dsa_public_key TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- -------------------------------------------------------
-- 2. Documents Table
-- Tracks metadata and SHA-256 hash of encrypted documents
-- -------------------------------------------------------
CREATE TABLE IF NOT EXISTS documents (
    id VARCHAR(64) PRIMARY KEY,
    filename VARCHAR(255) NOT NULL,
    sha256_hash VARCHAR(64) NOT NULL,
    encrypted_file_path VARCHAR(500) NOT NULL,
    created_by VARCHAR(64) NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_documents_created_by FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- -------------------------------------------------------
-- 3. Document Recipients Table
-- Access control and ML-KEM wrapped AES keys for recipients
-- -------------------------------------------------------
CREATE TABLE IF NOT EXISTS document_recipients (
    id VARCHAR(64) PRIMARY KEY,
    document_id VARCHAR(64) NOT NULL,
    recipient_id VARCHAR(64) NOT NULL,
    status ENUM('AUTHORIZED', 'REVOKED') DEFAULT 'AUTHORIZED',
    kem_ciphertext MEDIUMTEXT,
    wrapped_key TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_recipients_document FOREIGN KEY (document_id) REFERENCES documents(id) ON DELETE CASCADE,
    CONSTRAINT fk_recipients_user FOREIGN KEY (recipient_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE KEY uq_doc_recipient (document_id, recipient_id)
) ENGINE=InnoDB;

-- -------------------------------------------------------
-- 4. Access Events Table
-- Auditable access logs signed with ML-DSA-65 post-quantum signatures
-- -------------------------------------------------------
CREATE TABLE IF NOT EXISTS access_events (
    id VARCHAR(64) PRIMARY KEY,
    document_id VARCHAR(64) NOT NULL,
    recipient_id VARCHAR(64) NOT NULL,
    session_id VARCHAR(64) NOT NULL,
    watermark_id VARCHAR(64) NOT NULL,
    document_hash VARCHAR(64) NOT NULL,
    signature MEDIUMTEXT NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    event_hash VARCHAR(64) NOT NULL,
    INDEX idx_events_doc (document_id),
    INDEX idx_events_recipient (recipient_id),
    INDEX idx_events_timestamp (timestamp)
) ENGINE=InnoDB;

-- -------------------------------------------------------
-- 5. Audit Logs Table
-- System operational audit trail (LOGIN, UPLOAD, SHARE, OPEN, INVESTIGATE)
-- -------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_logs (
    id VARCHAR(64) PRIMARY KEY,
    user_id VARCHAR(64),
    action VARCHAR(50) NOT NULL,
    details TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_audit_user (user_id),
    INDEX idx_audit_action (action),
    INDEX idx_audit_time (timestamp)
) ENGINE=InnoDB;
