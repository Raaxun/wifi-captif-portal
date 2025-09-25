from flask import Flask, request, render_template, redirect, url_for, session, flash, jsonify
import os
import base64
import io
import qrcode
import bcrypt
import pyotp
import jwt
import datetime
from dotenv import load_dotenv
from database import *

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')
app.token = os.getenv('JWT_SECRET')
JWT_ALGORITHM = "HS256"
JWT_EXP_DELTA_SECONDS = 3600

def generate_token(username):
    payload = {
        "user": username,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(seconds=JWT_EXP_DELTA_SECONDS),
        "iat": datetime.datetime.utcnow()
    }
    return jwt.encode(payload, app.token, algorithm=JWT_ALGORITHM)

def verify_token(token):
    try:
        decoded = jwt.decode(token, app.token, algorithms=[JWT_ALGORITHM])
        return decoded
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

@app.route('/setup_admin_totp', methods=['GET', 'POST'])
def setup_admin_totp():
    if request.method == 'POST':
        return redirect(url_for('login'))

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT totp_secret FROM users WHERE login = ?', ('admin',))
    result = cursor.fetchone()
    cursor.close()

    if not result or not result['totp_secret']:
        totp_secret = pyotp.random_base32()
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE users SET totp_secret = ? WHERE login = ?
        ''', (totp_secret, 'admin'))
        conn.commit()
    else:
        totp_secret = result['totp_secret']

    totp_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(
        name='admin',
        issuer_name="Mon Portail Captif"
    )
    img = qrcode.make(totp_uri)
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    qr_code_data = buffer.getvalue()
    qr_code_b64 = f"data:image/png;base64,{base64.b64encode(qr_code_data).decode('utf-8')}"
    return render_template('setup_admin_totp.html', totp_secret=totp_secret, qr_code_b64=qr_code_b64)

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        login = request.form.get('login')
        password = request.form.get('password')
        totp_code = request.form.get('totp_code', '').strip()

        if login == 'admin' and password == 'admin123':
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute('SELECT totp_secret FROM users WHERE login = ?', ('admin',))
            result = cursor.fetchone()
            cursor.close()

            if not result or not result['totp_secret']:
                return redirect(url_for('setup_admin_totp'))

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT password_hash, totp_secret FROM users WHERE login = ?', (login,))
        result = cursor.fetchone()
        cursor.close()

        if not result:
            return render_template('login.html', error="Identifiant ou mot de passe incorrect.")

        stored_hash, totp_secret = result

        if not bcrypt.checkpw(password.encode('utf-8'), stored_hash):
            return render_template('login.html', error="Identifiant ou mot de passe incorrect.")

        if totp_secret and not pyotp.TOTP(totp_secret).verify(totp_code):
            return render_template('login.html', error="Code TOTP invalide.")

        token = generate_token(login)
        session['authenticated'] = True
        session['token'] = token
        session['login'] = login

        if login == 'admin':
            return redirect(url_for('admin'))
        else:
            return render_template('login_success.html', token=token)

    return render_template('login.html')

@app.route('/admin')
def admin():
    if not session.get('authenticated') or session.get('login') != 'admin':
        return redirect(url_for('login'))

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT id, login FROM users')
    users = cursor.fetchall()
    cursor.close()

    return render_template('admin.html', users=users)

@app.route('/admin/setup_user_totp', methods=['GET', 'POST'])
def setup_user_totp():
    if not session.get('authenticated') or session.get('login') != 'admin':
        return redirect(url_for('login'))

    if request.method == 'POST':
        login = request.form.get('login')
        password = request.form.get('password')
        if not login or not password:
            return render_template('admin.html', error="Login et mot de passe requis", success=None)

        totp_secret = pyotp.random_base32()
        totp_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(
            name=login,
            issuer_name="Mon Portail Captif"
        )

        session['temp_user'] = {
            'login': login,
            'password': password,
            'totp_secret': totp_secret
        }

        img = qrcode.make(totp_uri)
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        qr_code_data = buffer.getvalue()
        qr_code_b64 = f"data:image/png;base64,{base64.b64encode(qr_code_data).decode('utf-8')}"
        return render_template('setup_user_totp.html', login=login, totp_secret=totp_secret, qr_code_b64=qr_code_b64)

    return redirect(url_for('admin'))

@app.route('/admin/confirm_user_creation', methods=['POST'])
def confirm_user_creation():
    if not session.get('authenticated') or session.get('login') != 'admin':
        return redirect(url_for('login'))

    temp_user = session.get('temp_user')
    if not temp_user:
        return redirect(url_for('admin'))

    try:
        login = temp_user['login']
        password = temp_user['password']
        totp_secret = temp_user['totp_secret']

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT id FROM users WHERE login = ?', (login,))
        if cursor.fetchone() is not None:
            return render_template('admin.html', error=f"Le login '{login}' existe déjà.", success=None, users=get_users())

        add_user(login, password, totp_secret)
        session.pop('temp_user', None)
        return render_template('admin.html', success=f"Utilisateur {login} créé avec succès !", error=None, users=get_users())
    except Exception as e:
        return render_template('admin.html', error=f"Erreur: {str(e)}", success=None, users=get_users())

def get_users():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT id, login FROM users')
    users = cursor.fetchall()
    cursor.close()
    return users

@app.route('/admin/delete_user', methods=['POST'])
def admin_delete_user():
    if not session.get('authenticated') or session.get('login') != 'admin':
        return redirect(url_for('login'))

    login = request.form.get('login')
    if not login:
        return render_template('admin.html', error="Login requis pour la suppression", success=None, users=get_users())

    try:
        delete_user(login)
        return render_template('admin.html', success=f"Utilisateur {login} supprimé avec succès !", error=None, users=get_users())
    except Exception as e:
        return render_template('admin.html', error=str(e), success=None, users=get_users())

@app.route('/success')
def success():
    if not session.get('authenticated'):
        return redirect(url_for('login'))
    return "Authentification réussie ! Accès autorisé (simulé)."

@app.route('/test_db')
def test_db():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT 1')
    result = cursor.fetchone()
    cursor.close()
    return f"Test DB: {result[0]}"

@app.route('/list_users', methods=['GET'])
def list_users():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT id, login FROM users')
    results = cursor.fetchall()
    cursor.close()
    users = [{"id": row[0], "login": row[1]} for row in results]
    return jsonify(users)

@app.route('/logout')
def logout():
    session.clear()  # Réinitialise la session
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        init_db()
    app.run(debug=True)
