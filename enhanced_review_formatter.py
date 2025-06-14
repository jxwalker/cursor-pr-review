#!/usr/bin/env python3
"""
Enhanced review formatting for readable, actionable feedback
"""

from typing import Dict, Any, List
import re


class EnhancedReviewFormatter:
    """Formats review feedback into readable, actionable output with AI IDE prompts."""
    
    def format_review(self, comments: List[Dict[str, Any]]) -> str:
        """Generate a clean, readable consolidated review."""
        organized = self._organize_feedback(comments)
        return self._generate_consolidated_review(organized)
    
    def _organize_feedback(self, comments: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Organize feedback from all sources into a structured format."""
        organized = {
            'blocking_issues': [],
            'security_issues': [],
            'warnings': [],
            'suggestions': [],
            'coderabbit_feedback': [],
            'copilot_feedback': [],
            'codeql_feedback': [],
            'ai_insights': [],
            'total_issues': 0
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
            
            # Classify by severity and type
            if self._is_blocking_issue(body, comment):
                organized['blocking_issues'].append(item)
            elif self._is_security_issue(body):
                organized['security_issues'].append(item)
            elif self._is_warning(body, comment):
                organized['warnings'].append(item)
            else:
                organized['suggestions'].append(item)
        
        return organized
    
    def _is_coderabbit_comment(self, body: str, comment: Dict[str, Any]) -> bool:
        """Check if comment is from CodeRabbit."""
        return ('CodeRabbit' in body or 
                'coderabbit' in comment.get('sources', []) or
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
        
        # Header
        output.append("# 🤖 AI-Powered Code Review Summary")
        output.append("")
        output.append(f"**Total Issues Found:** {organized['total_issues']}")
        output.append("")
        
        # Executive Summary
        blocking_count = len(organized['blocking_issues'])
        security_count = len(organized['security_issues'])
        warning_count = len(organized['warnings'])
        
        if blocking_count > 0:
            output.append("## 🚨 Action Required")
            output.append(f"**{blocking_count} critical issue(s) must be resolved before merging.**")
            if security_count > 0:
                output.append(f"**{security_count} security issue(s) require immediate attention.**")
        else:
            output.append("## ✅ Ready to Merge")
            output.append("No critical issues found! Review suggestions below for improvements.")
        output.append("")
        
        # Critical Issues Section
        if organized['blocking_issues']:
            output.append("## 🛑 Critical Issues (Must Fix)")
            output.append("")
            for i, issue in enumerate(organized['blocking_issues'][:5], 1):
                output.append(f"### {i}. {issue['title']}")
                output.append(f"**📍 Location:** `{issue['location']}`")
                output.append(f"**🎯 Type:** {issue['type']}")
                output.append(f"**🔧 Fix:** {issue['remediation']}")
                if issue['code_snippet']:
                    output.append("**📝 Current Code:**")
                    output.append(f"```")
                    output.append(issue['code_snippet'])
                    output.append("```")
                output.append("")
        
        # Security Issues Section
        if organized['security_issues']:
            output.append("## 🔒 Security Issues")
            output.append("")
            for i, issue in enumerate(organized['security_issues'][:3], 1):
                output.append(f"**{i}. {issue['title']}**")
                output.append(f"- **Location:** `{issue['location']}`")
                output.append(f"- **Fix:** {issue['remediation']}")
                output.append("")
        
        # Tool-Specific Feedback
        if organized['coderabbit_feedback']:
            output.append("## 🐰 CodeRabbit Findings")
            output.append("")
            for issue in organized['coderabbit_feedback'][:3]:
                output.append(f"- **{issue['title']}** - {issue['remediation']}")
            output.append("")
        
        # AI IDE Prompts Section - THIS IS THE KEY PART!
        output.append("## 🤖 AI IDE Fix Prompts")
        output.append("")
        output.append("**Copy these prompts into your AI IDE (Cursor, GitHub Copilot, etc.) to automatically fix issues:**")
        output.append("")
        
        # Generate specific prompts for critical issues
        if organized['blocking_issues']:
            output.append("### 🚨 Critical Issue Fixes")
            for i, issue in enumerate(organized['blocking_issues'][:3], 1):
                prompt = self._generate_ai_ide_prompt(issue)
                output.append(f"**{i}. {issue['title']}**")
                output.append("```")
                output.append(prompt)
                output.append("```")
                output.append("")
        
        # Generate prompts for security issues
        if organized['security_issues']:
            output.append("### 🔒 Security Fix Prompts")
            for i, issue in enumerate(organized['security_issues'][:2], 1):
                prompt = self._generate_ai_ide_prompt(issue)
                output.append(f"**{i}. {issue['title']}**")
                output.append("```")
                output.append(prompt)
                output.append("```")
                output.append("")
        
        # Improvement Suggestions
        if organized['warnings'] or organized['suggestions']:
            output.append("## 💡 Improvement Suggestions")
            output.append("")
            all_suggestions = organized['warnings'] + organized['suggestions']
            for i, issue in enumerate(all_suggestions[:5], 1):
                output.append(f"{i}. **{issue['title']}** - {issue['remediation']}")
            output.append("")
        
        # Summary of sources
        sources = []
        if organized['coderabbit_feedback']:
            sources.append("🐰 CodeRabbit")
        if organized['codeql_feedback']:
            sources.append("🔍 CodeQL")
        if organized['copilot_feedback']:
            sources.append("🤖 Copilot")
        if organized['ai_insights']:
            sources.append("🧠 Custom AI Analysis")
        
        if sources:
            output.append("---")
            output.append(f"*Analysis by: {', '.join(sources)} and integrated security detectors*")
        
        return '\n'.join(output)
    
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