#!/usr/bin/env python3
"""
COMPREHENSIVE TESTS FOR ENHANCED ISSUE ANALYZER

Tests for security detection, error handling analysis, and issue deduplication.
"""

import os
import sys
import tempfile
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(__file__))

from issue_analyzer import (
    SecurityDetector, ErrorHandlingDetector, IssueAggregator,
    EnhancedReviewAnalyzer, Issue, IssueLocation, IssueCategory,
    IssueSeverity
)

class TestIssueLocation:
    """Test IssueLocation data structure."""
    
    def test_issue_location_with_full_info(self):
        """Test IssueLocation with complete information."""
        location = IssueLocation("test.py", 42, 10)
        assert str(location) == "test.py:42"
        assert location.file_path == "test.py"
        assert location.line_number == 42
        assert location.column == 10
    
    def test_issue_location_with_partial_info(self):
        """Test IssueLocation with partial information."""
        location = IssueLocation("test.py")
        assert str(location) == "test.py"
        
        location = IssueLocation()
        assert str(location) == "unknown"

class TestIssue:
    """Test Issue data structure and ID generation."""
    
    def test_create_issue_id(self):
        """Test unique issue ID generation."""
        location = IssueLocation("test.py", 42)
        id1 = Issue.create_id(location, IssueCategory.SECURITY, "SQL injection")
        id2 = Issue.create_id(location, IssueCategory.SECURITY, "SQL injection")
        id3 = Issue.create_id(location, IssueCategory.ERROR_HANDLING, "SQL injection")
        
        # Same location and type should generate same ID
        assert id1 == id2
        # Different category should generate different ID
        assert id1 != id3
        assert len(id1) == 16  # SHA256 truncated to 16 chars
    
    def test_add_source(self):
        """Test adding sources to an issue."""
        location = IssueLocation("test.py", 42)
        issue = Issue(
            id="test_id",
            title="Test Issue",
            description="Test description",
            category=IssueCategory.SECURITY,
            severity=IssueSeverity.ERROR,
            location=location,
            remediation="Fix it",
            owasp_category="A03-Injection",
            confidence=0.9
        )
        
        issue.add_source("detector1")
        issue.add_source("detector2")
        issue.add_source("detector1")  # Duplicate
        
        assert issue.sources == ["detector1", "detector2"]

class TestSecurityDetector:
    """Test security pattern detection."""
    
    def setup_method(self):
        """Setup security detector."""
        self.detector = SecurityDetector()
    
    def test_sql_injection_detection(self):
        """Test SQL injection pattern detection."""
        code = '''
cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)
query = f"DELETE FROM items WHERE name = {item_name}"
cursor.execute("UPDATE " + table + " SET value = " + value)
        '''
        
        issues = self.detector.analyze_code(code, "test.py")
        
        # Should find 3 SQL injection issues
        sql_issues = [i for i in issues if 'injection' in i.description.lower()]
        assert len(sql_issues) >= 2
        
        # Check issue details
        for issue in sql_issues:
            assert issue.category == IssueCategory.SECURITY
            assert issue.severity == IssueSeverity.CRITICAL
            assert "SQL" in issue.title
            assert "parameterized queries" in issue.remediation
    
    def test_xss_vulnerability_detection(self):
        """Test XSS vulnerability detection."""
        code = '''
element.innerHTML = user_input + " some text";
document.write("Hello " + username);
eval("process_" + user_function + "()");
        '''
        
        issues = self.detector.analyze_code(code, "test.js")
        
        # Should find XSS vulnerabilities
        xss_issues = [i for i in issues if 'xss' in i.description.lower()]
        assert len(xss_issues) >= 2
        
        for issue in xss_issues:
            assert issue.category == IssueCategory.SECURITY
            assert "sanitize" in issue.remediation.lower() or "encoding" in issue.remediation.lower()
    
    def test_command_injection_detection(self):
        """Test command injection detection."""
        code = '''
subprocess.call("rm -rf " + user_path, shell=True)
os.system("wget " + url)
subprocess.run(["ls", directory + extra], shell=True)
        '''
        
        issues = self.detector.analyze_code(code, "test.py")
        
        # Should find command injection issues
        cmd_issues = [i for i in issues if 'command' in i.description.lower()]
        assert len(cmd_issues) >= 2
        
        for issue in cmd_issues:
            assert issue.category == IssueCategory.SECURITY
            assert "shell=False" in issue.remediation or "validate" in issue.remediation
    
    def test_hardcoded_secrets_detection(self):
        """Test hardcoded secrets detection."""
        code = '''
password = "super_secret_password123"
api_key = "sk-1234567890abcdef1234567890abcdef"
secret = "my_secret_token_value"
token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        '''
        
        issues = self.detector.analyze_code(code, "test.py")
        
        # Should find hardcoded secrets
        secret_issues = [i for i in issues if 'hardcoded' in i.description.lower()]
        assert len(secret_issues) >= 3
        
        for issue in secret_issues:
            assert issue.category == IssueCategory.SECURITY
            assert "environment" in issue.remediation.lower()
    
    def test_crypto_issues_detection(self):
        """Test cryptographic issues detection."""
        code = '''
import hashlib
hash = hashlib.md5(data)
digest = hashlib.sha1(password.encode())
random_value = random.random()
        '''
        
        issues = self.detector.analyze_code(code, "test.py")
        
        # Should find weak crypto usage
        crypto_issues = [i for i in issues if any(word in i.description.lower() 
                                                for word in ['md5', 'sha1', 'random'])]
        assert len(crypto_issues) >= 3
    
    def test_unsafe_functions_detection(self):
        """Test unsafe function detection."""
        code = '''
data = pickle.loads(user_data)
config = yaml.load(config_file)
exec(user_code)
result = eval(expression)
        '''
        
        issues = self.detector.analyze_code(code, "test.py")
        
        # Should find unsafe function usage
        unsafe_issues = [i for i in issues if any(word in i.description.lower() 
                                                 for word in ['pickle', 'yaml', 'exec', 'eval'])]
        assert len(unsafe_issues) >= 4

class TestErrorHandlingDetector:
    """Test error handling pattern detection."""
    
    def setup_method(self):
        """Setup error handling detector."""
        self.detector = ErrorHandlingDetector()
    
    def test_bare_except_detection(self):
        """Test bare except clause detection."""
        code = '''
try:
    risky_operation()
except:
    pass
        '''
        
        issues = self.detector.analyze_code(code, "test.py")
        
        # Should find bare except
        bare_except_issues = [i for i in issues if 'bare except' in i.description.lower()]
        assert len(bare_except_issues) >= 1
        
        issue = bare_except_issues[0]
        assert issue.category == IssueCategory.ERROR_HANDLING
        assert issue.severity == IssueSeverity.ERROR
        assert "specify exception types" in issue.remediation.lower()
    
    def test_ignored_exceptions_detection(self):
        """Test ignored exception detection."""
        code = '''
try:
    process_data()
except ValueError:
    pass
    
try:
    connect_to_server()
except ConnectionError:
    continue
        '''
        
        issues = self.detector.analyze_code(code, "test.py")
        
        # Should find ignored exceptions
        ignored_issues = [i for i in issues if 'ignored' in i.description.lower()]
        assert len(ignored_issues) >= 2
    
    def test_missing_logging_detection(self):
        """Test missing error logging detection."""
        code = '''
try:
    critical_operation()
except ImportError:
    print("Error occurred")
        '''
        
        issues = self.detector.analyze_code(code, "test.py")
        
        # Should find missing logging
        logging_issues = [i for i in issues if 'logging' in i.description.lower()]
        assert len(logging_issues) >= 1
        
        issue = logging_issues[0]
        assert "logging.error" in issue.remediation
    
    def test_exception_without_message(self):
        """Test exception raised without message."""
        code = '''
if invalid_data:
    raise ValueError()
raise CustomError()
        '''
        
        issues = self.detector.analyze_code(code, "test.py")
        
        # Should find exceptions without messages
        message_issues = [i for i in issues if 'without message' in i.description.lower()]
        assert len(message_issues) >= 2

class TestIssueAggregator:
    """Test issue aggregation and deduplication."""
    
    def setup_method(self):
        """Setup issue aggregator."""
        self.aggregator = IssueAggregator()
    
    def test_add_unique_issues(self):
        """Test adding unique issues."""
        location1 = IssueLocation("test.py", 10)
        location2 = IssueLocation("test.py", 20)
        
        issue1 = Issue(
            id=Issue.create_id(location1, IssueCategory.SECURITY, "SQL injection"),
            title="SQL injection",
            description="SQL injection found",
            category=IssueCategory.SECURITY,
            severity=IssueSeverity.CRITICAL,
            location=location1,
            remediation="Use parameterized queries"
        )
        
        issue2 = Issue(
            id=Issue.create_id(location2, IssueCategory.ERROR_HANDLING, "Bare except"),
            title="Bare except",
            description="Bare except found",
            category=IssueCategory.ERROR_HANDLING,
            severity=IssueSeverity.ERROR,
            location=location2,
            remediation="Specify exception types"
        )
        
        self.aggregator.add_issues([issue1, issue2], "detector1")
        
        assert len(self.aggregator.issues) == 2
        assert issue1.sources == ["detector1"]
        assert issue2.sources == ["detector1"]
    
    def test_merge_duplicate_issues(self):
        """Test merging duplicate issues from different sources."""
        location = IssueLocation("test.py", 10)
        
        # Same issue detected by two different sources
        issue1 = Issue(
            id=Issue.create_id(location, IssueCategory.SECURITY, "SQL injection"),
            title="SQL injection",
            description="SQL injection found by detector1",
            category=IssueCategory.SECURITY,
            severity=IssueSeverity.CRITICAL,
            location=location,
            remediation="Use parameterized queries"
        )
        
        issue2 = Issue(
            id=Issue.create_id(location, IssueCategory.SECURITY, "SQL injection"),
            title="SQL injection",
            description="SQL injection found by detector2",
            category=IssueCategory.SECURITY,
            severity=IssueSeverity.CRITICAL,
            location=location,
            remediation="Use parameterized queries"
        )
        
        self.aggregator.add_issues([issue1], "detector1")
        self.aggregator.add_issues([issue2], "detector2")
        
        # Should have only one issue with both sources
        assert len(self.aggregator.issues) == 1
        merged_issue = list(self.aggregator.issues.values())[0]
        assert "detector1" in merged_issue.sources
        assert "detector2" in merged_issue.sources
        assert "detector2" in merged_issue.description
    
    def test_get_issues_by_category(self):
        """Test categorizing issues."""
        location = IssueLocation("test.py", 10)
        
        security_issue = Issue(
            id=Issue.create_id(location, IssueCategory.SECURITY, "test"),
            title="Security Issue",
            description="Test security issue",
            category=IssueCategory.SECURITY,
            severity=IssueSeverity.CRITICAL,
            location=location,
            remediation="Fix security"
        )
        
        error_issue = Issue(
            id=Issue.create_id(location, IssueCategory.ERROR_HANDLING, "test"),
            title="Error Issue",
            description="Test error issue",
            category=IssueCategory.ERROR_HANDLING,
            severity=IssueSeverity.ERROR,
            location=location,
            remediation="Fix error handling"
        )
        
        self.aggregator.add_issues([security_issue, error_issue], "test")
        
        categorized = self.aggregator.get_issues_by_category()
        
        assert len(categorized[IssueCategory.SECURITY]) == 1
        assert len(categorized[IssueCategory.ERROR_HANDLING]) == 1
        assert len(categorized[IssueCategory.PERFORMANCE]) == 0

class TestEnhancedReviewAnalyzer:
    """Test the complete enhanced review analyzer."""
    
    def setup_method(self):
        """Setup enhanced analyzer."""
        self.analyzer = EnhancedReviewAnalyzer()
    
    def test_analyze_diff_with_security_issues(self):
        """Test analyzing diff with security issues."""
        diff = '''
+++ b/auth.py
@@ -10,3 +10,6 @@
+def authenticate(username, password):
+    query = "SELECT * FROM users WHERE username = '%s' AND password = '%s'" % (username, password)
+    cursor.execute(query)
+    return cursor.fetchone()
        '''
        
        report = self.analyzer.analyze_diff(diff, "auth.py")
        
        assert report['summary']['total_issues'] > 0
        assert report['summary']['security_issues'] > 0
        
        security_section = report['sections']['security']
        assert security_section['count'] > 0
        
        # Should find SQL injection
        issues = security_section['issues']
        sql_issue = next((i for i in issues if 'sql' in i['description'].lower()), None)
        assert sql_issue is not None
        assert sql_issue['severity'] == 'critical'
    
    def test_analyze_diff_with_error_handling_issues(self):
        """Test analyzing diff with error handling issues."""
        diff = '''
+++ b/processor.py
@@ -5,2 +5,8 @@
+try:
+    process_data()
+except:
+    pass
+
+try:
+    connect()
+except ConnectionError:
+    continue
        '''
        
        report = self.analyzer.analyze_diff(diff, "processor.py")
        
        assert report['summary']['error_handling_issues'] > 0
        
        error_section = report['sections']['error_handling']
        assert error_section['count'] > 0
        
        # Should find bare except and ignored exception
        issues = error_section['issues']
        assert len(issues) >= 2
    
    def test_integrate_external_issues(self):
        """Test integrating issues from CodeRabbit and GitHub AI."""
        # First analyze some code
        diff = '''
+++ b/test.py
@@ -1,0 +1,2 @@
+password = "hardcoded_secret123"
+eval(user_input)
        '''
        
        self.analyzer.analyze_diff(diff, "test.py")
        
        # Mock CodeRabbit comments
        coderabbit_comments = [
            {
                'id': 1,
                'body': 'Security vulnerability: hardcoded password detected',
                'path': 'test.py',
                'line': 1,
                'user': {'login': 'coderabbitai'}
            },
            {
                'id': 2,
                'body': 'Performance issue: consider caching this result',
                'path': 'test.py',
                'line': 5,
                'user': {'login': 'coderabbitai'}
            }
        ]
        
        # Mock GitHub AI issues
        github_ai_issues = [
            {
                'body': 'Error handling: missing try-catch around eval',
                'path': 'test.py',
                'line': 2
            }
        ]
        
        # Integrate external issues
        self.analyzer.integrate_external_issues(coderabbit_comments, github_ai_issues)
        
        # Generate final report
        report = self.analyzer._generate_structured_report()
        
        # Should have issues from multiple sources
        assert report['summary']['total_issues'] > 0
        
        # Check source attribution
        attribution = report['source_attribution']
        assert 'coderabbit' in attribution
        assert 'github_ai' in attribution
        assert 'security_detector' in attribution or 'error_handling_detector' in attribution
    
    def test_empty_diff_analysis(self):
        """Test analyzing empty diff."""
        diff = ""
        
        report = self.analyzer.analyze_diff(diff)
        
        assert report['summary']['total_issues'] == 0
        assert report['sections']['security']['count'] == 0
        assert report['sections']['error_handling']['count'] == 0
    
    def test_parse_coderabbit_comment(self):
        """Test parsing CodeRabbit comments."""
        comment = {
            'id': 1,
            'body': 'Security vulnerability: potential SQL injection in query construction',
            'path': 'database.py',
            'line': 25,
            'user': {'login': 'coderabbitai'}
        }
        
        issue = self.analyzer._parse_coderabbit_comment(comment)
        
        assert issue is not None
        assert issue.category == IssueCategory.SECURITY
        assert issue.severity == IssueSeverity.ERROR
        assert issue.location.file_path == 'database.py'
        assert issue.location.line_number == 25
        assert 'coderabbit' in issue.sources
    
    def test_parse_github_ai_issue(self):
        """Test parsing GitHub AI issues."""
        ai_issue = {
            'body': 'Error handling improvement needed: bare except clause should specify exception types',
            'path': 'handler.py',
            'line': 15
        }
        
        issue = self.analyzer._parse_github_ai_issue(ai_issue)
        
        assert issue is not None
        assert issue.category == IssueCategory.ERROR_HANDLING
        assert issue.severity == IssueSeverity.WARNING
        assert issue.location.file_path == 'handler.py'
        assert issue.location.line_number == 15
        assert 'github_ai' in issue.sources

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])