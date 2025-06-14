#!/usr/bin/env python3
"""
Example code with security vulnerabilities for PR review testing.
This file intentionally contains issues to test the AI review system.
"""

import os
import subprocess
import sqlite3

# Security Issue 1: Hardcoded credentials
API_KEY = "sk-proj-abcd1234567890"
DATABASE_PASSWORD = "admin123"
AWS_SECRET = "AKIAIOSFODNN7EXAMPLE"

# Security Issue 2: SQL Injection vulnerability
def get_user_data(user_id):
    conn = sqlite3.connect('users.db')
    # Direct string formatting - SQL injection risk!
    query = f"SELECT * FROM users WHERE id = {user_id}"
    result = conn.execute(query)
    return result.fetchall()

# Security Issue 3: Command injection
def process_file(filename):
    # Dangerous - user input directly in shell command
    cmd = f"cat {filename} | grep sensitive"
    return subprocess.check_output(cmd, shell=True)

# Security Issue 4: Path traversal vulnerability
def read_file(user_input):
    # No validation - path traversal risk
    with open(f"/var/data/{user_input}", 'r') as f:
        return f.read()

# Code Quality Issue 1: Broad exception handling
def risky_operation():
    try:
        # Some complex operation
        result = 1 / 0
    except:  # Too broad!
        print("Something went wrong")
        return None

# Code Quality Issue 2: Missing error handling
def connect_to_api():
    response = requests.get("https://api.example.com/data")
    # No status check or error handling
    return response.json()

# Security Issue 5: Insecure random number generation
import random
def generate_token():
    # Not cryptographically secure
    return ''.join([str(random.randint(0, 9)) for _ in range(16)])

# Security Issue 6: Debug mode left enabled
DEBUG = True
if DEBUG:
    print("Running in debug mode with verbose logging")

# Security Issue 7: Eval usage
def calculate_expression(expr):
    # Dangerous eval usage
    return eval(expr)

if __name__ == "__main__":
    # Example usage that would trigger issues
    user_data = get_user_data("1 OR 1=1")  # SQL injection
    file_content = process_file("../../etc/passwd")  # Command injection