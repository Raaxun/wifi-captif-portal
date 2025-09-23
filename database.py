import sqlite3
import bcrypt
import pyotp
import os
from dotenv import load_dotenv

load_dotenv()

def init_db(db_name=None):
    if db_name is None:
        db_name = os.getenv('DB_NAME', 'captive_portal.db')
    conn = sqlite3.connect(db_name, check_same_thread=False)  # Ajoute cette option
    conn.execute("PRAGMA foreign_keys = ON")
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
    return conn, cursor

def add_user(conn, cursor, login, password):
    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    totp_secret = pyotp.random_base32()
    cursor.execute('''
        INSERT INTO users (login, password_hash, totp_secret)
        VALUES (?, ?, ?)
    ''', (login, password_hash, totp_secret))
    conn.commit()
    return totp_secret

def verify_user(conn, cursor, login, password, totp_code):
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
