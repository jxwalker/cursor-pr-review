#!/usr/bin/env python3
"""Example code with multiple security vulnerabilities for demo"""

import os
import sqlite3
import subprocess
from flask import Flask, request, render_template_string

app = Flask(__name__)

# Issue 1: Hardcoded database credentials
DB_HOST = "localhost"
DB_USER = "admin"
DB_PASS = "password123"  # Hardcoded password
API_KEY = "sk-prod-1234567890abcdef"  # Hardcoded API key

# Issue 2: SQL Injection vulnerability
@app.route('/user/<user_id>')
def get_user(user_id):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Vulnerable to SQL injection
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    
    user = cursor.fetchone()
    return {'user': user}

# Issue 3: Command injection
@app.route('/ping')
def ping_host():
    host = request.args.get('host', 'localhost')
    
    # Vulnerable to command injection
    result = subprocess.run(f"ping -c 4 {host}", shell=True, capture_output=True)
    return result.stdout.decode()

# Issue 4: XSS vulnerability
@app.route('/greet')
def greet_user():
    name = request.args.get('name', 'Guest')
    
    # Vulnerable to XSS
    template = f"<h1>Hello, {name}!</h1>"
    return render_template_string(template)

# Issue 5: Path traversal
@app.route('/download')
def download_file():
    filename = request.args.get('file')
    
    # Vulnerable to path traversal
    with open(f"/var/data/{filename}", 'r') as f:
        return f.read()

# Issue 6: Weak crypto
def encrypt_password(password):
    # Using weak encryption
    import base64
    return base64.b64encode(password.encode()).decode()

# Issue 7: No authentication
@app.route('/admin')
def admin_panel():
    # No authentication check
    return "Admin panel - Delete all users"

# Issue 8-12: Multiple similar error handling issues
def process_data(data):
    try:
        result = parse_data(data)
    except:  # Bare except
        pass
    
    try:
        validate_data(data)
    except:  # Bare except
        pass
    
    try:
        save_data(data)
    except:  # Bare except
        pass
    
    try:
        notify_users(data)
    except:  # Bare except
        pass
    
    try:
        log_activity(data)
    except:  # Bare except
        pass

if __name__ == '__main__':
    app.run(debug=True)  # Debug mode in production