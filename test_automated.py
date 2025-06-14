#!/usr/bin/env python3
"""Test file for automated review"""

import os
import subprocess

# Issue 1: Hardcoded API key
API_KEY = "sk-test-1234567890abcdef"

def process_user_data(user_id):
    """Process user data from database"""
    # Issue 2: SQL injection vulnerability
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return query

def run_command(cmd):
    """Execute system command"""
    # Issue 3: Command injection risk
    subprocess.run(f"echo {cmd}", shell=True)
    
def handle_error():
    """Handle errors"""
    try:
        risky_operation()
    except:  # Issue 4: Bare except
        pass