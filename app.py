from flask import Flask, request, render_template, redirect, url_for, session, flash
import os
import base64
import io
import qrcode
import bcrypt
import pyotp
from dotenv import load_dotenv
from database import init_db, add_user, verify_user

load_dotenv()
app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')

@app.route('/admin/create_user', methods=['GET', 'POST'])
def admin_create_user():
    if request.method == 'POST':
        login = request.form.get('login')
        password = request.form.get('password')
        try:
            totp_secret, totp_uri = add_user(login, password)
            img = qrcode.make(totp_uri)
            buffer = io.BytesIO()
            img.save(buffer, format="PNG")
            qr_code_data = buffer.getvalue()
            qr_code_b64 = f"data:image/png;base64,{base64.b64encode(qr_code_data).decode('utf-8')}"
            return render_template('user_created.html',
                                 login=login,
                                 totp_secret=totp_secret,
                                 qr_code_b64=qr_code_b64)
        except ValueError as e:
            return render_template('admin_create_user.html', error=str(e))
    return render_template('admin_create_user.html')

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        login = request.form.get('login')
        password = request.form.get('password')
        totp_code = request.form.get('totp_code')
        if verify_user(login, password, totp_code):
            session['authenticated'] = True
            return redirect(url_for('success'))
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
