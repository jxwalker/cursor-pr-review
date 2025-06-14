#!/usr/bin/env python3
"""Example file with security issues for testing"""

import os
import mysql.connector

# Bad: Hardcoded credentials
DB_PASSWORD = "admin123"
API_KEY = "sk-live-1234567890abcdef"

def process_payment(user_id, amount):
    """Process a payment - has SQL injection vulnerability"""
    # Bad: SQL injection vulnerability
    query = f"UPDATE users SET balance = balance - {amount} WHERE id = {user_id}"
    
    # Bad: No error handling
    db = mysql.connector.connect(
        host="localhost",
        user="root", 
        password=DB_PASSWORD
    )
    cursor = db.cursor()
    cursor.execute(query)
    db.commit()
    
    return {"status": "success"}

def authenticate(username, password):
    """Authenticate user - multiple issues"""
    # Bad: SQL injection
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    
    try:
        # Execute query
        result = execute_query(query)
    except:  # Bad: Bare except
        pass
    
    # Bad: Hardcoded admin bypass
    if username == "admin" and password == "admin":
        return True
    
    return False

# Bad: Using eval (dangerous)
def calculate(expression):
    return eval(expression)