#!/usr/bin/env python3
"""
Enhanced review formatting for readable, actionable feedback
"""

from typing import Dict, Any, List, Optional
import re
import os


class EnhancedReviewFormatter:
    """Formats review feedback into readable, actionable output with AI IDE prompts."""
    
    def format_review(self, comments: List[Dict[str, Any]]) -> str:
        """Generate a clean, readable consolidated review."""
        organized = self._organize_feedback(comments)
        return self._generate_consolidated_review(organized)
    
    def _organize_feedback(self, comments: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Organize feedback from all sources into a structured format."""
        organized = {
            'production_blocking': [],
            'production_security': [],
            'production_warnings': [],
            'production_suggestions': [],
            'test_issues': [],
            'test_improvements': [],
            'example_code_issues': [],
            'documentation_issues': [],
            'coderabbit_feedback': [],
            'copilot_feedback': [],
            'codeql_feedback': [],
            'ai_insights': [],
            'total_issues': 0,
            'production_issues': 0,
            'test_issues_count': 0,
            'example_issues_count': 0
        }
        
        for comment in comments:
            body = comment.get('body', '').strip()
            if not body:
                continue
                
            organized['total_issues'] += 1
            item = self._extract_actionable_item(comment)
            
            # Classify by source and content
            if self._is_coderabbit_comment(body, comment):
                organized['coderabbit_feedback'].append(item)
            elif self._is_copilot_comment(body):
                organized['copilot_feedback'].append(item)
            elif self._is_codeql_comment(body):
                organized['codeql_feedback'].append(item)
            elif 'AI Analysis' in body:
                organized['ai_insights'].append(item)
            
            # Determine if this is test-related, example code, or production code
            is_test_file = self._is_test_file(item['location'])
            is_example_code = self._is_example_code_issue(body, item)
            
            if is_example_code:
                # Example/documentation code - informational only
                organized['example_issues_count'] += 1
                if 'formatter.py' in item['location'] or 'documentation' in item['location'].lower():
                    organized['documentation_issues'].append(item)
                else:
                    organized['example_code_issues'].append(item)
            elif is_test_file:
                # Test files - issues are not blocking for production
                organized['test_issues_count'] += 1
                if self._is_blocking_issue(body, comment) or self._is_security_issue(body):
                    organized['test_issues'].append(item)
                else:
                    organized['test_improvements'].append(item)
            else:
                # Production code - issues can be blocking
                organized['production_issues'] += 1
                if self._is_blocking_issue(body, comment):
                    organized['production_blocking'].append(item)
                elif self._is_security_issue(body):
                    organized['production_security'].append(item)
                elif self._is_warning(body, comment):
                    organized['production_warnings'].append(item)
                else:
                    organized['production_suggestions'].append(item)
        
        return organized
    
    def _is_coderabbit_comment(self, body: str, comment: Dict[str, Any]) -> bool:
        """Check if comment is from CodeRabbit."""
        return ('CodeRabbit' in body or 
                'coderabbit' in comment.get('sources', []) or
                comment.get('user') == 'coderabbitai' or
                comment.get('type') == 'actionable_comment' or
                '🐰' in body or
                'Actionable comments posted' in body)
    
    def _is_copilot_comment(self, body: str) -> bool:
        """Check if comment is from GitHub Copilot."""
        return 'Copilot' in body or 'copilot' in body.lower()
    
    def _is_codeql_comment(self, body: str) -> bool:
        """Check if comment is from CodeQL."""
        return 'CodeQL' in body or 'codeql' in body.lower()
    
    def _is_blocking_issue(self, body: str, comment: Dict[str, Any]) -> bool:
        """Check if this is a blocking issue."""
        severity = comment.get('severity', 'info')
        return (severity in ['critical', 'error'] or 
                'CRITICAL:' in body or 
                'ERROR:' in body or
                'SQL injection' in body or
                'security vulnerability' in body.lower())
    
    def _is_security_issue(self, body: str) -> bool:
        """Check if this is a security issue."""
        security_keywords = ['security', 'vulnerability', 'injection', 'xss', 'csrf', 
                           'hardcoded', 'credential', 'authentication', 'authorization']
        return any(keyword in body.lower() for keyword in security_keywords)
    
    def _is_warning(self, body: str, comment: Dict[str, Any]) -> bool:
        """Check if this is a warning level issue."""
        severity = comment.get('severity', 'info')
        return severity == 'warning' or 'WARNING:' in body
    
    def _is_test_file(self, location: str) -> bool:
        """Check if the issue is in a test file or documentation."""
        test_indicators = [
            'test_', '_test.py', '/test/', '/tests/', 
            'spec_', '_spec.py', '/spec/', '/specs/',
            'pytest', 'unittest', 'conftest.py',
            'test.py', 'tests.py', '_test_', 'test/',
            'demo.py', '_demo.py', 'example.py', '_example.py'
        ]
        
        # Documentation and example files
        doc_indicators = [
            'formatter.py', 'template', 'prompt', 'example', 'sample',
            'documentation', 'docs/', 'readme', 'guide'
        ]
        
        location_lower = location.lower()
        return (any(indicator in location_lower for indicator in test_indicators) or
                any(indicator in location_lower for indicator in doc_indicators))
    
    def _is_example_code_issue(self, body: str, item: Dict[str, str]) -> bool:
        """Check if this issue is in example/demo code and should be treated as informational."""
        body_lower = body.lower()
        
        # Check for explicit example code indicators
        example_indicators = [
            'example/demo code', 'example code', 'demo code',
            'in example code', 'example fix:', 'bad:', 'good:',
            'avoid:', 'don\'t:', 'vulnerable:', 'instead of:'
        ]
        
        if any(indicator in body_lower for indicator in example_indicators):
            return True
        
        # Check location for documentation files
        location = item.get('location', '').lower()
        doc_files = ['formatter.py', 'template', 'prompt', 'example', 'documentation']
        
        return any(doc_file in location for doc_file in doc_files)
    
    def _extract_actionable_item(self, comment: Dict[str, Any]) -> Dict[str, str]:
        """Extract actionable information from a comment."""
        body = comment.get('body', '').strip()
        
        # Extract file and line information
        location = self._extract_location(body)
        
        # Extract the main issue description
        issue_title = self._extract_issue_title(body)
        
        # Extract remediation if available
        remediation = self._extract_remediation(body)
        
        # Extract code snippet if available
        code_snippet = self._extract_code_snippet(body)
        
        # Extract category/type
        issue_type = self._extract_issue_type(body)
        
        return {
            'title': issue_title,
            'location': location,
            'remediation': remediation,
            'code_snippet': code_snippet,
            'type': issue_type,
            'severity': self._determine_severity(body, comment),
            'original_comment': body
        }
    
    def _extract_location(self, body: str) -> str:
        """Extract file and line location from comment."""
        # Look for various location patterns
        patterns = [
            r'📍\s*Location:\s*([^\n]+)',
            r'Location:\s*([^\n]+)',
            r'in\s+([a-zA-Z0-9_/.-]+\.py:\d+)',
            r'([a-zA-Z0-9_/.-]+\.py:\d+)',
            r'file\s+([a-zA-Z0-9_/.-]+)'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, body)
            if match:
                return match.group(1).strip()
        
        return "Unknown location"
    
    def _extract_issue_title(self, body: str) -> str:
        """Extract the main issue description."""
        # Try to get title from various formats
        lines = body.split('\n')
        first_line = lines[0] if lines else "Unnamed issue"
        
        # Clean up common prefixes and formatting
        title = first_line
        title = re.sub(r'^\*\*([^*]+)\*\*', r'\1', title)  # Remove bold
        title = re.sub(r'^(CRITICAL|ERROR|WARNING):\s*', '', title)  # Remove severity prefix
        title = re.sub(r'^Security:\s*', '', title)  # Remove type prefix
        title = re.sub(r'^Error Handling:\s*', '', title)  # Remove type prefix
        title = re.sub(r'^AI Analysis:\s*', '', title)  # Remove type prefix
        title = re.sub(r'^CodeRabbit:\s*', '', title)  # Remove source prefix
        
        return title.strip() or "Unnamed issue"
    
    def _extract_remediation(self, body: str) -> str:
        """Extract remediation advice from comment."""
        # Look for remediation patterns
        patterns = [
            r'🔧\s*Remediation:\s*([^\n]+)',
            r'Remediation:\s*([^\n]+)',
            r'Fix:\s*([^\n]+)',
            r'How to fix:\s*([^\n]+)',
            r'Solution:\s*([^\n]+)'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, body, re.IGNORECASE)
            if match:
                return match.group(1).strip()
        
        # Look for general improvement suggestions
        if 'Use' in body and ('instead' in body or 'rather than' in body):
            for line in body.split('\n'):
                if 'Use' in line and ('instead' in line or 'rather than' in line):
                    return line.strip()
        
        return "Review and address as appropriate"
    
    def _extract_code_snippet(self, body: str) -> str:
        """Extract code snippet from comment."""
        # Look for code blocks
        code_block_pattern = r'```[a-zA-Z]*\n(.*?)\n```'
        match = re.search(code_block_pattern, body, re.DOTALL)
        if match:
            return match.group(1).strip()
        
        # Look for inline code
        inline_code_pattern = r'`([^`]+)`'
        matches = re.findall(inline_code_pattern, body)
        if matches and len(matches[0]) > 10:  # Only longer code snippets
            return matches[0]
        
        return None
    
    def _extract_issue_type(self, body: str) -> str:
        """Extract the type/category of issue."""
        if 'SQL injection' in body or 'injection' in body.lower():
            return "SQL Injection"
        elif 'XSS' in body or 'cross-site' in body.lower():
            return "Cross-Site Scripting"
        elif 'hardcoded' in body.lower():
            return "Hardcoded Secrets"
        elif 'exception' in body.lower() or 'error handling' in body.lower():
            return "Error Handling"
        elif 'performance' in body.lower():
            return "Performance"
        elif 'security' in body.lower():
            return "Security"
        else:
            return "Code Quality"
    
    def _determine_severity(self, body: str, comment: Dict[str, Any]) -> str:
        """Determine severity level of issue."""
        severity = comment.get('severity', 'info')
        
        # Override based on content
        if any(word in body.lower() for word in ['critical', 'sql injection', 'security vulnerability']):
            return "critical"
        elif any(word in body.lower() for word in ['error', 'bug', 'hardcoded credential']):
            return "error"
        elif any(word in body.lower() for word in ['warning', 'potential issue']):
            return "warning"
        else:
            return severity
    
    def _generate_consolidated_review(self, organized: Dict[str, Any]) -> str:
        """Generate a clean, readable consolidated review."""
        output = []
        
        # Professional header with review mode
        output.append("# 🎯 AI Code Review")
        output.append("")
        
        # Get review mode from environment or default
        review_mode = os.environ.get('REVIEW_PROMPT_TYPE', 'default').upper()
        mode_descriptions = {
            'DEFAULT': 'Balanced review focusing on critical issues',
            'STRICT': 'Thorough analysis with zero tolerance',
            'LENIENT': 'Focus on major issues only', 
            'BRUTAL': 'Harsh, honest feedback with no sugar-coating',
            'SECURITY-FOCUSED': 'Security-first comprehensive analysis'
        }
        
        mode_desc = mode_descriptions.get(review_mode, 'Standard code review')
        output.append(f"**Review Mode:** `{review_mode}` - {mode_desc}")
        output.append("")
        
        # Quick status summary
        if organized['production_issues'] == 0:
            output.append("## ✅ Status: Ready to Merge")
            output.append("No blocking issues found in production code.")
        else:
            blocking_count = len(organized['production_blocking']) + len(organized['production_security'])
            if blocking_count > 0:
                output.append(f"## 🛑 Status: {blocking_count} Blocking Issues")
                output.append("Must fix before merging.")
            else:
                output.append("## ⚠️ Status: Minor Issues Found")
                output.append("Consider fixing before merge.")
        
        output.append("")
        output.append("---")
        output.append("")
        
        # Summary counts in a clean table format
        output.append("## 📊 Summary")
        output.append("")
        output.append("| Category | Count | Action Required |")
        output.append("|----------|-------|----------------|")
        
        if organized['production_blocking']:
            output.append(f"| 🚨 Critical Issues | {len(organized['production_blocking'])} | **Fix immediately** |")
        
        if organized['production_security']:
            output.append(f"| 🔒 Security Issues | {len(organized['production_security'])} | **Fix before merge** |")
            
        if organized['production_warnings']:
            output.append(f"| ⚠️ Warnings | {len(organized['production_warnings'])} | Consider fixing |")
            
        if organized['production_suggestions']:
            output.append(f"| 💡 Suggestions | {len(organized['production_suggestions'])} | Optional |")
        
        if organized['total_issues'] == 0:
            output.append("| ✅ No issues found | 0 | None |")
        
        output.append("")
        
        # Production Critical Issues Section
        if organized['production_blocking']:
            output.append("## 🚨 Critical Issues")
            output.append("*Must fix these before merging*")
            output.append("")
            
            for i, issue in enumerate(organized['production_blocking'][:5], 1):
                output.append(f"### {i}. {issue['title']}")
                output.append(f"📍 `{issue['location']}`")
                output.append("")
                
                # Simple, clear problem statement
                output.append("**Problem:**")
                output.append(f"> {issue.get('description', issue['title'])}")
                output.append("")
                
                # Show the problematic code if available
                if issue.get('code_snippet'):
                    output.append("**Your code:**")
                    output.append("```python")
                    output.append(issue['code_snippet'])
                    output.append("```")
                    output.append("")
                
                # Clear, actionable fix
                output.append("**Quick fix:**")
                output.append(f"> {issue['remediation']}")
                output.append("")
                
                # Add copy-paste IDE prompt in a collapsible section
                output.append("<details>")
                output.append("<summary>🤖 <b>Copy this to your AI IDE</b></summary>")
                output.append("")
                output.append("```")
                output.append(self._generate_simple_fix_prompt(issue))
                output.append("```")
                output.append("</details>")
                output.append("")
                output.append("---")
                output.append("")
        
        # Production Security Issues Section
        if organized['production_security']:
            output.append("## 🔒 Security Issues")
            output.append("*Fix before merging to protect your users*")
            output.append("")
            
            for i, issue in enumerate(organized['production_security'][:3], 1):
                output.append(f"### {i}. {issue['title']}")
                output.append(f"📍 `{issue['location']}`")
                
                # Add OWASP category if available
                owasp = self._extract_owasp_category(issue)
                if owasp:
                    output.append(f"🛡️ OWASP: {owasp}")
                
                output.append("")
                output.append("**Quick fix:**")
                output.append(f"> {issue['remediation']}")
                output.append("")
                
                if issue.get('code_snippet'):
                    output.append("<details>")
                    output.append("<summary>View problematic code</summary>")
                    output.append("")
                    output.append("```python")
                    output.append(issue['code_snippet'])
                    output.append("```")
                    output.append("</details>")
                    output.append("")
                
                output.append("---")
                output.append("")
        
        # Other issues (warnings and suggestions)
        other_issues = organized['production_warnings'] + organized['production_suggestions']
        if other_issues:
            output.append("## 💡 Other Suggestions")
            output.append("*Nice to fix but not blocking*")
            output.append("")
            
            # Show up to 5 other issues in a compact format
            for i, issue in enumerate(other_issues[:5], 1):
                output.append(f"**{i}.** {issue['title']} - `{issue['location']}`")
                output.append(f"   > {issue['remediation']}")
                output.append("")
            
            if len(other_issues) > 5:
                output.append(f"*Plus {len(other_issues) - 5} more suggestions...*")
                output.append("")
        
        
        
        # Clean footer
        output.append("---")
        output.append("")
        output.append("### 💡 Tips")
        output.append("- Focus on critical and security issues first")
        output.append("- Use the AI IDE prompts for quick fixes")
        output.append("- Test your changes after fixing")
        output.append("")
        output.append(f"*Powered by Cursor PR Review • Review mode: {review_mode}*")
        
        return '\n'.join(output)
    
    def _generate_simple_fix_prompt(self, issue: Dict[str, str]) -> str:
        """Generate a simple, vibe-coder friendly fix prompt."""
        location = issue.get('location', 'the file').replace('b/', '')
        title = issue.get('title', 'the issue')
        
        # Very simple, direct prompts based on issue type
        if 'SQL' in title or 'injection' in title.lower():
            return f"""Fix SQL injection in {location}

The query uses string formatting which is unsafe.
Replace with parameterized queries.

Example:
# Instead of: f"SELECT * FROM users WHERE id = {{user_id}}"
# Use: "SELECT * FROM users WHERE id = %s", (user_id,)"""
        
        elif 'hardcoded' in title.lower() or 'secret' in title.lower():
            return f"""Remove hardcoded secret in {location}

Move the hardcoded value to an environment variable.

Example:
# Instead of: api_key = "sk-123456"
# Use: api_key = os.getenv('API_KEY')"""
        
        elif 'error' in title.lower() or 'exception' in title.lower():
            return f"""Fix error handling in {location}

Add proper exception handling and logging.

Example:
# Instead of: except: pass
# Use: except SpecificError as e:
#          logger.error(f"Failed: {{e}}")"""
        
        else:
            return f"""Fix: {title} in {location}

{issue.get('remediation', 'Apply the recommended fix')}"""
    
    def _extract_owasp_category(self, issue: Dict[str, Any]) -> Optional[str]:
        """Extract OWASP category from issue."""
        # Check direct field
        if issue.get('owasp_category'):
            return issue['owasp_category']
        
        # Check in description
        desc = issue.get('description', '') + issue.get('body', '')
        owasp_match = re.search(r'(A\d{2}-[A-Za-z-]+)', desc)
        if owasp_match:
            return owasp_match.group(1)
        
        return None
    
    def _generate_ai_ide_prompt(self, issue: Dict[str, str]) -> str:
        """Generate an AI IDE prompt for fixing a specific issue."""
        location = issue['location'].replace('b/', '').replace('a/', '')
        
        # Create specific prompts based on issue type
        if issue['type'] == "SQL Injection":
            return f"""Fix SQL injection vulnerability in {location}:

Replace string formatting/concatenation with parameterized queries.
Current issue: {issue['title']}

Steps:
1. Find the SQL query construction
2. Replace % formatting or + concatenation with parameterized queries
3. Use cursor.execute(query, params) instead of cursor.execute(query % params)
4. Ensure all user inputs are properly escaped

Example fix:
# Bad: cursor.execute("SELECT * FROM users WHERE id = '%s'" % user_id)
# Good: cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))"""

        elif issue['type'] == "Hardcoded Secrets":
            return f"""Remove hardcoded secrets in {location}:

Replace hardcoded credentials with environment variables.
Current issue: {issue['title']}

Steps:
1. Identify the hardcoded secret/credential
2. Move it to environment variable
3. Add os.getenv() to load from environment
4. Update any deployment scripts to set the environment variable

Example fix:
# Bad: api_key = "sk-1234567890abcdef"
# Good: api_key = os.getenv('OPENAI_API_KEY')"""

        elif issue['type'] == "Error Handling":
            return f"""Improve error handling in {location}:

Fix exception handling issues.
Current issue: {issue['title']}

Steps:
1. Replace bare except: with specific exception types
2. Add proper logging for caught exceptions
3. Ensure exceptions are not silently ignored
4. Add appropriate error messages

Example fix:
# Bad: except: pass
# Good: except (ValueError, KeyError) as e: logger.error(f"Processing failed: {{e}}")"""

        else:
            return f"""Fix issue in {location}:

Issue: {issue['title']}
Required Fix: {issue['remediation']}

Steps:
1. Locate the problematic code in {location}
2. Apply the recommended fix: {issue['remediation']}
3. Test that the fix resolves the issue
4. Ensure no new issues are introduced"""
    
    def _generate_test_improvement_prompt(self, issue: Dict[str, str]) -> str:
        """Generate an AI IDE prompt for improving test code."""
        location = issue['location'].replace('b/', '').replace('a/', '')
        
        # Create specific prompts for test improvements
        if "SQL injection" in issue['title'] or "injection" in issue['title'].lower():
            return f"""Improve test security in {location}:

This test contains potentially unsafe patterns that should be improved for test reliability.
Issue: {issue['title']}

Steps:
1. Review the test for secure coding practices
2. Use proper test data instead of potentially harmful examples
3. Ensure tests don't introduce real security vulnerabilities
4. Use mocked/stubbed data for security testing

Note: This is test code, so it won't block production deployment."""

        elif "hardcoded" in issue['title'].lower():
            return f"""Remove hardcoded values in test {location}:

Tests should use configurable test data instead of hardcoded values.
Issue: {issue['title']}

Steps:
1. Replace hardcoded test values with test configuration
2. Use fixtures or test factories for test data
3. Consider using pytest fixtures or unittest setUp methods
4. Make tests more maintainable and reusable

Note: This improves test quality but doesn't block production."""

        elif "error handling" in issue['title'].lower() or "except" in issue['title'].lower():
            return f"""Improve error handling in test {location}:

Test code should demonstrate proper error handling patterns.
Issue: {issue['title']}

Steps:
1. Fix exception handling in test code
2. Use specific exception types instead of bare except
3. Add proper assertions for error conditions
4. Ensure tests properly validate error scenarios

Note: This improves test reliability but doesn't block production."""

        else:
            return f"""Improve test code quality in {location}:

Issue: {issue['title']}
Fix: {issue['remediation']}

Steps:
1. Locate the issue in the test file
2. Apply the recommended improvement
3. Ensure tests still pass after the fix
4. Consider if this improves overall test quality

Note: This is test code improvement - not blocking for production deployment."""