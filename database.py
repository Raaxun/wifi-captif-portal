import sqlite3
import bcrypt
import pyotp
import os
from dotenv import load_dotenv

load_dotenv()

def get_db():
    db_name = os.getenv('DB_NAME', 'captive_portal.db')
    conn = sqlite3.connect(db_name, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                login TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                totp_secret TEXT NOT NULL
            )
        ''')
        conn.commit()
    finally:
        conn.close()

def add_user(login, password):
    conn = get_db()
    try:
        cursor = conn.cursor()
        # Vérifie si le login existe déjà
        cursor.execute('SELECT id FROM users WHERE login = ?', (login,))
        if cursor.fetchone() is not None:
            raise ValueError(f"Le login '{login}' existe déjà.")

        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        totp_secret = pyotp.random_base32()
        cursor.execute('''
            INSERT INTO users (login, password_hash, totp_secret)
            VALUES (?, ?, ?)
        ''', (login, password_hash, totp_secret))
        conn.commit()
    finally:
        conn.close()

    # Génère l'URI pour le QR Code
    totp_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(
        name=login,
        issuer_name="Mon Portail Captif"
    )
    return totp_secret, totp_uri

def delete_user(login):
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM users WHERE login = ?', (login,))
        conn.commit()
    finally:
        conn.close()

def verify_user(login, password, totp_code):
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT password_hash, totp_secret FROM users WHERE login = ?
        ''', (login,))
        result = cursor.fetchone()
        if not result:
            return False
        stored_hash, totp_secret = result
        if not bcrypt.checkpw(password.encode('utf-8'), stored_hash):
            return False
        totp = pyotp.TOTP(totp_secret)
        return totp.verify(totp_code)
    finally:
        conn.close()
