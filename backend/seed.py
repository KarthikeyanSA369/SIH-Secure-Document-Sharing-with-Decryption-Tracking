import pymysql
from database import SessionLocal, engine, Base
from models import User, Document, DocumentRecipient, AccessEvent
from auth import hash_password
from crypto.ml_kem import generate_ml_kem_keypair
from crypto.ml_dsa import generate_ml_dsa_keypair
from crypto.keystore import KeyStore
from config import settings

def reset_and_seed_database():
    """Recreate secureshare database, create tables, and seed demo accounts."""
    print("--- Resetting Database Schema for SecureShare ---")
    
    try:
        conn = pymysql.connect(
            host=settings.DB_HOST,
            port=settings.DB_PORT,
            user=settings.DB_USER,
            password=settings.DB_PASSWORD
        )
        with conn.cursor() as cur:
            cur.execute(f"DROP DATABASE IF EXISTS `{settings.DB_NAME}`;")
            cur.execute(f"CREATE DATABASE `{settings.DB_NAME}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;")
        conn.commit()
        conn.close()
        print("[OK] Clean database recreated.")
    except Exception as e:
        print(f"[Warning] Database recreation: {e}")

    # Create tables defined in models
    Base.metadata.create_all(bind=engine)
    print("[OK] Created tables: users, documents, document_recipients, access_events")

    keystore = KeyStore(str(settings.KEYSTORE_PATH))
    db = SessionLocal()

    try:
        # 1. Create Admin
        print("Generating Post-Quantum Keys for Admin (ML-KEM-768 & ML-DSA-65)...")
        admin_kem_pk, admin_kem_sk = generate_ml_kem_keypair()
        admin_dsa_pk, admin_dsa_sk = generate_ml_dsa_keypair()
        admin_id = "USER-ADMIN-01"

        admin = User(
            id=admin_id,
            username="admin",
            password_hash=hash_password("admin123"),
            name="System Administrator",
            role="ADMIN",
            ml_kem_public_key=admin_kem_pk,
            ml_dsa_public_key=admin_dsa_pk
        )
        db.add(admin)
        keystore.save_user_keys(admin_id, admin_kem_sk, admin_dsa_sk)
        keystore.save_server_signing_key(admin_dsa_sk, admin_dsa_pk)
        print("[OK] Created Demo Admin: admin / admin123")

        # 2. Create Alice (Recipient)
        print("Generating Post-Quantum Keys for Alice (ML-KEM-768 & ML-DSA-65)...")
        alice_kem_pk, alice_kem_sk = generate_ml_kem_keypair()
        alice_dsa_pk, alice_dsa_sk = generate_ml_dsa_keypair()
        alice_id = "USER-ALICE-01"

        alice = User(
            id=alice_id,
            username="alice",
            password_hash=hash_password("alice123"),
            name="Alice",
            role="RECIPIENT",
            ml_kem_public_key=alice_kem_pk,
            ml_dsa_public_key=alice_dsa_pk
        )
        db.add(alice)
        keystore.save_user_keys(alice_id, alice_kem_sk, alice_dsa_sk)
        print("[OK] Created Demo Recipient: alice / alice123")

        # 3. Create Investigator
        investigator = db.query(User).filter(User.username == "investigator").first()
        if not investigator:
            print("Generating Post-Quantum Keys for Investigator (ML-KEM-768 & ML-DSA-65)...")
            inv_kem_pk, inv_kem_sk = generate_ml_kem_keypair()
            inv_dsa_pk, inv_dsa_sk = generate_ml_dsa_keypair()
            inv_id = "USER-INVESTIGATOR-01"

            investigator = User(
                id=inv_id,
                username="investigator",
                password_hash=hash_password("investigator123"),
                name="Investigation Officer",
                role="INVESTIGATOR",
                ml_kem_public_key=inv_kem_pk,
                ml_dsa_public_key=inv_dsa_pk
            )
            db.add(investigator)
            keystore.save_user_keys(inv_id, inv_kem_sk, inv_dsa_sk)
            print("[OK] Created Demo Investigator: investigator / investigator123")
        else:
            print("[OK] Investigator account already exists.")

        db.commit()
        print("--- SecureShare Database initialized and seeded successfully ---")

    except Exception as e:
        db.rollback()
        print(f"Error seeding database: {e}")
        raise e
    finally:
        db.close()

def ensure_seed_users():
    """Ensure all demo users exist without dropping existing tables."""
    Base.metadata.create_all(bind=engine)
    keystore = KeyStore(str(settings.KEYSTORE_PATH))
    db = SessionLocal()

    try:
        # Admin
        admin = db.query(User).filter(User.username == "admin").first()
        if not admin:
            admin_kem_pk, admin_kem_sk = generate_ml_kem_keypair()
            admin_dsa_pk, admin_dsa_sk = generate_ml_dsa_keypair()
            admin = User(
                id="USER-ADMIN-01",
                username="admin",
                password_hash=hash_password("admin123"),
                name="System Administrator",
                role="ADMIN",
                ml_kem_public_key=admin_kem_pk,
                ml_dsa_public_key=admin_dsa_pk
            )
            db.add(admin)
            keystore.save_user_keys(admin.id, admin_kem_sk, admin_dsa_sk)
            keystore.save_server_signing_key(admin_dsa_sk, admin_dsa_pk)
            print("[OK] Seeded Admin")

        # Alice
        alice = db.query(User).filter(User.username == "alice").first()
        if not alice:
            alice_kem_pk, alice_kem_sk = generate_ml_kem_keypair()
            alice_dsa_pk, alice_dsa_sk = generate_ml_dsa_keypair()
            alice = User(
                id="USER-ALICE-01",
                username="alice",
                password_hash=hash_password("alice123"),
                name="Alice",
                role="RECIPIENT",
                ml_kem_public_key=alice_kem_pk,
                ml_dsa_public_key=alice_dsa_pk
            )
            db.add(alice)
            keystore.save_user_keys(alice.id, alice_kem_sk, alice_dsa_sk)
            print("[OK] Seeded Alice")

        # Investigator
        investigator = db.query(User).filter(User.username == "investigator").first()
        if not investigator:
            inv_kem_pk, inv_kem_sk = generate_ml_kem_keypair()
            inv_dsa_pk, inv_dsa_sk = generate_ml_dsa_keypair()
            investigator = User(
                id="USER-INVESTIGATOR-01",
                username="investigator",
                password_hash=hash_password("investigator123"),
                name="Investigation Officer",
                role="INVESTIGATOR",
                ml_kem_public_key=inv_kem_pk,
                ml_dsa_public_key=inv_dsa_pk
            )
            db.add(investigator)
            keystore.save_user_keys(investigator.id, inv_kem_sk, inv_dsa_sk)
            print("[OK] Seeded Investigator")

        db.commit()
    except Exception as e:
        db.rollback()
        print(f"Error ensuring demo users: {e}")
    finally:
        db.close()

if __name__ == "__main__":
    ensure_seed_users()
