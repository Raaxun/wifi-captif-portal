from flask import Flask, request, render_template, redirect, url_for, session, flash, jsonify
import os
import base64
import io
import qrcode
import bcrypt
import pyotp
from dotenv import load_dotenv
from database import *
import jwt
import datetime


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

@app.route('/admin/create_user', methods=['GET', 'POST'])
def admin_create_user():

    if request.method == 'POST':
        if request.is_json:
            data = request.get_json()
            login = data.get('login')
            password = data.get('password')
        else:
            login = request.form.get('login')
            password = request.form.get('password')

        if not login or not password:
            return render_template('admin_create_user.html', error="Login et mot de passe requis")

        conn = get_db()
        try:
            cursor = conn.cursor()
            cursor.execute('SELECT id FROM users WHERE login = ?', (login,))
            if cursor.fetchone() is not None:
                return render_template('admin_create_user.html', error=f"Le login '{login}' existe déjà.")

            pybytePassword = bytes(str(password), 'utf-8')
            password_hash = bcrypt.hashpw(pybytePassword, bcrypt.gensalt())

            totp_secret = pyotp.random_base32()
            cursor.execute('''
                INSERT INTO users (login, password_hash, totp_secret)
                VALUES (?, ?, ?)
            ''', (login, password_hash, totp_secret))
            conn.commit()
        finally:
            conn.close()

        totp_uri = pyotp.TOTP(totp_secret).provisioning_uri(
            name=login,
            issuer_name="Mon Portail Captif"
        )
        img = qrcode.make(totp_uri)
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        qr_code_data = buffer.getvalue()
        qr_code_b64 = f"data:image/png;base64,{base64.b64encode(qr_code_data).decode('utf-8')}"

        return render_template(
            'user_created.html',
            login=login,
            totp_secret=totp_secret,
            qr_code_b64=qr_code_b64
        )

    return render_template('admin_create_user.html')

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        login = request.form.get('login')
        password = request.form.get('password')
        totp_code = request.form.get('totp_code')

        if verify_user(login, password, totp_code): 
            token = generate_token(login)

            session['authenticated'] = True
            session['token'] = token

            return render_template('login_success.html', token=token)

        return render_template('login.html', error="Authentification échouée.")

    return render_template('login.html')

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

@app.route('/get_user_id/<login>', methods=['GET'])
def get_user_id(login):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT id FROM users WHERE login = ?', (login,))
    result = cursor.fetchone()
    cursor.close()
    if result:
        return f"User ID for {login}: {result[0]}"
    return f"User {login} not found."

@app.route('/list_users', methods=['GET'])
def list_users():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT id, login FROM users')
    results = cursor.fetchall()
    cursor.close()
    users = [{"id": row[0], "login": row[1]} for row in results]
    return jsonify(users)

@app.route('/admin/delete_user', methods=['POST'])
def admin_delete_user():
    data = request.get_json()
    login = data.get('login')
    if not login:
        return jsonify({"error": "Login is required"}), 400
    try:
        delete_user(login)
        return jsonify({"message": f"User '{login}' deleted successfully."})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/create_user', methods=['GET'])
def create_user():
    return render_template('admin_create_user.html')


if __name__ == '__main__':
    with app.app_context():
        init_db()
    app.run(debug=True)
