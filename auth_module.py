#!/usr/bin/env python3
"""Authentication module with security issues for testing"""

import mysql.connector
import subprocess

# Hardcoded credentials
DB_PASSWORD = "admin123"
API_KEY = "sk-production-key-12345"

def authenticate_user(username, password):
    """Authenticate user against database"""
    conn = mysql.connector.connect(
        host="localhost",
        user="root",
        password=DB_PASSWORD
    )
    
    cursor = conn.cursor()
    # SQL injection vulnerability
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)
    
    user = cursor.fetchone()
    return user is not None

def run_admin_command(command):
    """Execute admin command"""
    # Command injection vulnerability
    result = subprocess.run(f"admin_tool {command}", shell=True, capture_output=True)
    return result.stdout.decode()

def process_request(data):
    """Process user request"""
    try:
        # Some processing
        validate_data(data)
        result = perform_action(data)
        return result
    except:  # Bare except clause
        pass
    
    return None

# Using eval - dangerous
def calculate_metrics(expression):
    """Calculate user-provided metrics"""
    return eval(expression)