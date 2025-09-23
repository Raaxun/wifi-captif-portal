from flask import Flask, request, render_template, redirect, url_for, session, g
import sqlite3
import bcrypt
import pyotp
import os
from dotenv import load_dotenv

load_dotenv()
app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db_name = os.getenv('DB_NAME', 'captive_portal.db')
        db = g._database = sqlite3.connect(db_name, check_same_thread=False)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    conn = get_db()
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

def verify_user(login, password, totp_code):
    conn = get_db()
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

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        login = request.form.get('login')
        password = request.form.get('password')
        totp_code = request.form.get('totp_code')
        if verify_user(login, password, totp_code):
            session['authenticated'] = True
            return redirect(url_for('success'))
        else:
            return render_template('login.html', error="Authentification échouée.")
    return render_template('login.html')

@app.route('/success')
def success():
    if not session.get('authenticated'):
        return redirect(url_for('login'))
    return "Authentification réussie ! Accès autorisé (simulé)."

if __name__ == '__main__':
    with app.app_context():
        init_db()
    app.run(debug=True)
