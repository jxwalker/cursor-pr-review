#!/usr/bin/env python3
"""Demo file to test AI review capabilities"""

import mysql.connector
import os
import subprocess

# Issue 1: Hardcoded database password
DB_PASSWORD = "supersecret123"

def get_user_data(user_id):
    """Get user from database - has SQL injection"""
    conn = mysql.connector.connect(
        host="localhost",
        user="root",
        password=DB_PASSWORD
    )
    
    cursor = conn.cursor()
    # Issue 2: SQL injection vulnerability
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    
    return cursor.fetchone()

def run_system_command(cmd):
    """Execute system command - has command injection"""
    # Issue 3: Command injection via shell=True
    result = subprocess.run(f"echo Running: {cmd}", shell=True)
    return result.returncode

def process_user_input(data):
    """Process data with poor error handling"""
    try:
        # Some processing
        result = int(data) * 2
        return result
    except:  # Issue 4: Bare except clause
        pass
    
    return None

def authenticate_user(username, password):
    """Authenticate with hardcoded bypass"""
    # Issue 5: Hardcoded admin bypass
    if username == "admin" and password == "admin":
        return True
    
    # Issue 6: Another SQL injection
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    # ... rest of auth logic
    
    return False

# Issue 7: Using eval (dangerous)
def calculate_expression(expr):
    """Calculate math expression"""
    return eval(expr)