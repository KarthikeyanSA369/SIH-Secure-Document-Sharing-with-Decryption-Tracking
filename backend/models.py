import datetime
from sqlalchemy import Column, String, Text, DateTime, ForeignKey, BigInteger, CHAR
from sqlalchemy.orm import relationship
from database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(String(64), primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    name = Column(String(100), nullable=False)
    role = Column(String(20), nullable=False)  # 'ADMIN' or 'RECIPIENT'
    ml_kem_public_key = Column(Text, nullable=True)
    ml_dsa_public_key = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    documents_created = relationship("Document", back_populates="creator")
    recipient_assignments = relationship("DocumentRecipient", back_populates="recipient")

class Document(Base):
    __tablename__ = "documents"

    id = Column(String(64), primary_key=True, index=True)
    filename = Column(String(255), nullable=False)
    sha256_hash = Column(String(64), nullable=False)
    encrypted_file_path = Column(String(500), nullable=False)
    created_by = Column(String(64), ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    creator = relationship("User", back_populates="documents_created")
    recipients = relationship("DocumentRecipient", back_populates="document", cascade="all, delete-orphan")

class DocumentRecipient(Base):
    __tablename__ = "document_recipients"

    id = Column(String(64), primary_key=True, index=True)
    document_id = Column(String(64), ForeignKey("documents.id"), nullable=False)
    recipient_id = Column(String(64), ForeignKey("users.id"), nullable=False)
    status = Column(String(20), default="AUTHORIZED")  # 'AUTHORIZED' or 'REVOKED'
    kem_ciphertext = Column(Text, nullable=True)       # Encapsulated ML-KEM-768 ciphertext
    wrapped_key = Column(Text, nullable=True)          # Document AES key wrapped with KDF(shared_secret)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    document = relationship("Document", back_populates="recipients")
    recipient = relationship("User", back_populates="recipient_assignments")

class WatermarkRecord(Base):
    __tablename__ = "watermark_records"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    watermark_id = Column(String(255), unique=True, nullable=False, index=True)
    session_id = Column(String(150), unique=True, nullable=False, index=True)
    document_id = Column(String(64), ForeignKey("documents.id"), nullable=False, index=True)
    recipient_id = Column(String(64), ForeignKey("users.id"), nullable=False, index=True)
    document_hash = Column(CHAR(64), nullable=False)
    watermarked_pdf_hash = Column(CHAR(64), nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    document = relationship("Document")
    recipient = relationship("User")

class AccessEvent(Base):
    __tablename__ = "access_events"

    id = Column(String(64), primary_key=True, index=True)
    document_id = Column(String(64), nullable=False, index=True)
    recipient_id = Column(String(64), nullable=False, index=True)
    session_id = Column(String(64), nullable=False)
    watermark_id = Column(String(64), nullable=False)
    document_hash = Column(String(64), nullable=False)
    signature = Column(Text, nullable=False)  # ML-DSA-65 post-quantum signature
    timestamp = Column(DateTime, default=datetime.datetime.utcnow, index=True)
    event_hash = Column(String(64), nullable=False)

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(String(64), primary_key=True, index=True)
    user_id = Column(String(64), nullable=True, index=True)
    action = Column(String(50), nullable=False, index=True)
    details = Column(Text, nullable=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow, index=True)
