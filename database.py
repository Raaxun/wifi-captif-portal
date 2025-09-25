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
                totp_secret TEXT
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_id INTEGER NOT NULL,
                receiver_id INTEGER NOT NULL,
                content TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(sender_id) REFERENCES users(id),
                FOREIGN KEY(receiver_id) REFERENCES users(id)
            )
        ''')
        cursor.execute('SELECT id FROM users WHERE login = ?', ('admin',))
        if cursor.fetchone() is None:
            password_hash = bcrypt.hashpw(b'admin123', bcrypt.gensalt())
            cursor.execute('''
                INSERT INTO users (login, password_hash, totp_secret)
                VALUES (?, ?, NULL)
            ''', ('admin', password_hash))
            print("Utilisateur admin créé (sans TOTP).")
        conn.commit()
    finally:
        conn.close()

def add_user(login, password, totp_secret):
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute('SELECT id FROM users WHERE login = ?', (login,))
        if cursor.fetchone() is not None:
            raise ValueError(f"Le login '{login}' existe déjà.")
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        cursor.execute('''
            INSERT INTO users (login, password_hash, totp_secret)
            VALUES (?, ?, ?)
        ''', (login, password_hash, totp_secret))
        conn.commit()
    finally:
        conn.close()

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
        if not totp_secret:
            return False
        totp = pyotp.TOTP(totp_secret)
        return totp.verify(totp_code)
    finally:
        conn.close()

def get_user_id(login):
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute('SELECT id FROM users WHERE login = ?', (login,))
        result = cursor.fetchone()
        return result['id'] if result else None
    finally:
        conn.close()

def get_users_except(login):
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute('SELECT id, login FROM users WHERE login != ?', (login,))
        return cursor.fetchall()
    finally:
        conn.close()

def add_message(sender_id, receiver_id, content):
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO messages (sender_id, receiver_id, content)
            VALUES (?, ?, ?)
        ''', (sender_id, receiver_id, content))
        conn.commit()
    finally:
        conn.close()

def get_messages(user1_id, user2_id):
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT m.id, m.sender_id, m.receiver_id, m.content, m.timestamp, u.login as sender_login
            FROM messages m
            JOIN users u ON m.sender_id = u.id
            WHERE (m.sender_id = ? AND m.receiver_id = ?)
               OR (m.sender_id = ? AND m.receiver_id = ?)
            ORDER BY m.timestamp
        ''', (user1_id, user2_id, user2_id, user1_id))
        return cursor.fetchall()
    finally:
        conn.close()