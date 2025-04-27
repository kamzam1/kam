#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
app.py: Flask app bao gồm
- Trang bảo mật (/)
- Trang đăng nhập (/login)
- Trang chat (/chat)
Thông tin user lưu trong users.json.
"""

import json
from functools import wraps
from flask import (
    Flask, render_template, request,
    redirect, url_for, session, flash
)
from werkzeug.security import (
    generate_password_hash, check_password_hash
)

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Khóa bí mật cho session :contentReference[oaicite:10]{index=10}
SECURITY_CODE = '123456'                # Mã bảo mật cố định

USERS_FILE = 'users.json'

def load_users():
    """Đọc và parse users.json"""
    try:
        with open(USERS_FILE, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

def save_users(users):
    """Ghi dữ liệu users vào users.json"""
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f, indent=2)

def security_required(f):
    """Decorator bảo vệ route cần nhập mã bảo mật"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('access_granted'):
            flash('Vui lòng nhập mã bảo mật.', 'warning')
            return redirect(url_for('security'))
        return f(*args, **kwargs)
    return decorated

def login_required(f):
    """Decorator bảo vệ route chỉ cho user đã login"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'username' not in session:
            flash('Bạn cần đăng nhập.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

@app.route('/', methods=['GET', 'POST'])
def security():
    """Trang nhập mã bảo mật"""
    if request.method == 'POST':
        if request.form.get('code') == SECURITY_CODE:
            session['access_granted'] = True
            return redirect(url_for('login'))
        flash('Mã bảo mật không đúng.', 'danger')
    return render_template('security.html')

@app.route('/login', methods=['GET', 'POST'])
@security_required
def login():
    """Trang đăng nhập"""
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        users = load_users()
        user = users.get(username)
        if user and check_password_hash(user['password_hash'], password):
            session['username'] = username
            flash(f'Chào mừng {username}!', 'success')
            return redirect(url_for('chat'))
        flash('Đăng nhập thất bại.', 'danger')
    return render_template('login.html')

@app.route('/chat')
@security_required
@login_required
def chat():
    """Trang chat"""
    return render_template('chat.html', username=session['username'])

@app.route('/logout')
def logout():
    """Đăng xuất"""
    session.clear()
    flash('Bạn đã đăng xuất.', 'info')
    return redirect(url_for('security'))

if __name__ == '__main__':
    app.run(debug=True)
