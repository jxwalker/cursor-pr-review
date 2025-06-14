#!/usr/bin/env python3
"""
ENHANCED ISSUE DETECTION AND ANALYSIS SYSTEM

Implements the self-improvement recommendations for better security detection,
error handling analysis, and issue deduplication.
"""

import re
import hashlib
import logging
from typing import Dict, Any, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger('cursor_pr_review')

class IssueSeverity(Enum):
    """Issue severity levels."""
    CRITICAL = "critical"
    ERROR = "error" 
    WARNING = "warning"
    SUGGESTION = "suggestion"
    INFO = "info"

class IssueCategory(Enum):
    """Issue categories for organized reporting."""
    SECURITY = "security"
    ERROR_HANDLING = "error_handling"
    PERFORMANCE = "performance"
    CODE_QUALITY = "code_quality"
    TESTING = "testing"
    OTHER = "other"

@dataclass
class IssueLocation:
    """Represents the location of an issue in code."""
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    column: Optional[int] = None
    
    def __str__(self) -> str:
        if self.file_path and self.line_number:
            return f"{self.file_path}:{self.line_number}"
        elif self.file_path:
            return self.file_path
        return "unknown"

@dataclass
class Issue:
    """Represents a single code review issue with enhanced metadata."""
    id: str
    title: str
    description: str
    category: IssueCategory
    severity: IssueSeverity
    location: IssueLocation
    remediation: str
    sources: List[str] = field(default_factory=list)  # Which tools found this issue
    code_snippet: Optional[str] = None
    root_cause: Optional[str] = None
    owasp_category: Optional[str] = None  # OWASP Top 10 mapping
    confidence: float = 1.0  # Confidence level (0.0-1.0)
    
    @classmethod
    def create_id(cls, location: IssueLocation, category: IssueCategory, title: str) -> str:
        """Create unique issue ID based on location and type."""
        key_parts = [
            location.file_path or "unknown",
            str(location.line_number or 0),
            category.value,
            title.lower().replace(" ", "_")[:50]
        ]
        key = "|".join(key_parts)
        return hashlib.sha256(key.encode()).hexdigest()[:16]
    
    def add_source(self, source: str) -> None:
        """Add a source that detected this issue."""
        if source not in self.sources:
            self.sources.append(source)

class SecurityDetector:
    """Enhanced security pattern detection with OWASP Top 10 mapping."""
    
    def __init__(self):
        # OWASP Top 10 2021 mapping
        self.owasp_mapping = {
            'sql_injection': 'A03-Injection',
            'xss_vulnerability': 'A03-Injection', 
            'command_injection': 'A03-Injection',
            'hardcoded_secrets': 'A02-Cryptographic-Failures',
            'crypto_issues': 'A02-Cryptographic-Failures',
            'unsafe_functions': 'A06-Vulnerable-Components',
            'access_control': 'A01-Broken-Access-Control',
            'auth_failures': 'A07-Authentication-Failures',
            'logging_failures': 'A09-Logging-Monitoring-Failures',
            'ssrf': 'A10-Server-Side-Request-Forgery',
            'insecure_design': 'A04-Insecure-Design',
            'security_misconfiguration': 'A05-Security-Misconfiguration',
            'integrity_failures': 'A08-Software-Data-Integrity-Failures'
        }
        
        self.patterns = {
            # Input validation issues
            'sql_injection': [
                (r'\.?execute\s*\([^)]*%[^)]*\)', 'Potential SQL injection via string formatting'),
                (r'\.?execute\s*\(\s*f["\']', 'Potential SQL injection via f-string'),
                (r'["\'][^"]*(SELECT|INSERT|UPDATE|DELETE)[^"]*["\'][^%]*%', 'SQL query string formatting vulnerability'),
                (r'["\'][^"]*(SELECT|INSERT|UPDATE|DELETE)[^"]*"\s*\+', 'SQL query concatenation detected'),
                (r'\.?execute\s*\([^)]*\+[^)]*\)', 'SQL injection via string concatenation'),
            ],
            'xss_vulnerability': [
                (r'innerHTML\s*=\s*[^;]*\+', 'Potential XSS via innerHTML concatenation'),
                (r'document\.write\s*\([^)]*\+', 'Potential XSS via document.write'),
                (r'eval\s*\([^)]*user', 'Dangerous eval with user input'),
            ],
            'command_injection': [
                (r'subprocess\.(call|run|Popen)\s*\([^)]*\+', 'Command injection via subprocess'),
                (r'os\.system\s*\([^)]*\+', 'Command injection via os.system'),
                (r'shell=True.*\+', 'Shell injection in subprocess call'),
            ],
            'hardcoded_secrets': [
                (r'password\s*=\s*["\'][^"\']{8,}["\']', 'Hardcoded password detected'),
                (r'api[_-]?key\s*=\s*["\'][^"\']{20,}["\']', 'Hardcoded API key detected'),
                (r'secret\s*=\s*["\'][^"\']{16,}["\']', 'Hardcoded secret detected'),
                (r'token\s*=\s*["\'][^"\']{20,}["\']', 'Hardcoded token detected'),
            ],
            'crypto_issues': [
                (r'md5\s*\(', 'Weak MD5 hash function used'),
                (r'sha1\s*\(', 'Weak SHA1 hash function used'),
                (r'random\.random\(\)', 'Non-cryptographic random function for security'),
            ],
            'unsafe_functions': [
                (r'pickle\.loads?\s*\(', 'Unsafe pickle deserialization'),
                (r'yaml\.load\s*\([^)]*(?<!safe_load)', 'Unsafe YAML loading'),
                (r'exec\s*\(', 'Dangerous exec() function'),
                (r'eval\s*\(', 'Dangerous eval() function'),
            ]
        }
    
    def analyze_code(self, content: str, file_path: str = None) -> List[Issue]:
        """Analyze code for security issues."""
        issues = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            for category, patterns in self.patterns.items():
                for pattern, description in patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        location = IssueLocation(file_path, line_num)
                        
                        # Check if this is likely a false positive (example/demo code)
                        is_example = self._is_example_code(line, lines, line_num)
                        
                        # Adjust severity and confidence for examples
                        if is_example:
                            severity = IssueSeverity.INFO
                            confidence = 0.3
                            adjusted_description = f"Example/demo code with {description.lower()}"
                        else:
                            severity = IssueSeverity.CRITICAL if 'injection' in category else IssueSeverity.ERROR
                            confidence = 0.9 if 'injection' in category else 0.8
                            adjusted_description = description
                        
                        issue = Issue(
                            id=Issue.create_id(location, IssueCategory.SECURITY, adjusted_description),
                            title=f"Security: {adjusted_description}",
                            description=f"{adjusted_description} on line {line_num}",
                            category=IssueCategory.SECURITY,
                            severity=severity,
                            location=location,
                            remediation=self._get_remediation(category),
                            code_snippet=line.strip(),
                            root_cause=f"Use of potentially unsafe pattern: {category}" + (" (in example code)" if is_example else ""),
                            sources=["security_detector"],
                            owasp_category=self.owasp_mapping.get(category, "Security-General"),
                            confidence=confidence
                        )
                        issues.append(issue)
        
        return issues
    
    def _is_example_code(self, line: str, lines: List[str], line_num: int) -> bool:
        """Check if this line is likely example/demo code that shouldn't be flagged as critical."""
        line_lower = line.lower().strip()
        
        # Check for explicit comment indicators on the same line or nearby
        if line_num > 0:
            prev_line = lines[line_num - 2] if line_num > 1 else ""
            prev_line_lower = prev_line.lower().strip()
        else:
            prev_line_lower = ""
        
        # Very specific example code indicators
        explicit_example_indicators = [
            '# bad:', '# wrong:', '# avoid:', '# example:', '# demo:', 
            '# don\'t:', '# never:', '# vulnerable:', '# incorrect:',
            'bad =', 'wrong =', 'example =', 'demo =', 'vulnerable_code =',
            '# this is bad', '# this is wrong', '# this is vulnerable'
        ]
        
        # Check current line and previous line for explicit indicators
        if (any(indicator in line_lower for indicator in explicit_example_indicators) or
            any(indicator in prev_line_lower for indicator in explicit_example_indicators)):
            return True
        
        # Check for specific function contexts that indicate example code
        context_start = max(0, line_num - 5)
        context_end = min(len(lines), line_num + 2)
        context_lines = lines[context_start:context_end]
        
        context_text = ' '.join(context_lines).lower()
        context_indicators = [
            'def _generate_ai_ide_prompt', 'def _generate_test_improvement_prompt',
            'example fix:', 'steps:\n1.', 'fix:\n#',
            'def test_', 'test case', 'assert detect_', 'vulnerable code'
        ]
        
        return any(indicator in context_text for indicator in context_indicators)
    
    def _get_remediation(self, category: str) -> str:
        """Get specific remediation advice for security issues."""
        remediations = {
            'sql_injection': 'Use parameterized queries or prepared statements',
            'xss_vulnerability': 'Sanitize user input and use proper encoding',
            'command_injection': 'Use subprocess with shell=False and validate inputs',
            'hardcoded_secrets': 'Move secrets to environment variables or secret management',
            'crypto_issues': 'Use strong cryptographic functions (SHA-256, bcrypt)',
            'unsafe_functions': 'Use safe alternatives (safe_load for YAML, avoid exec/eval)'
        }
        return remediations.get(category, 'Follow security best practices')

class ErrorHandlingDetector:
    """Enhanced error handling pattern detection."""
    
    def __init__(self):
        self.patterns = [
            (r'except\s*:', 'Bare except clause without exception type'),
            (r'except\s+\w+.*:(?!.*log)', 'Exception caught without logging'),
            (r'raise\s+\w+\(\)\s*$', 'Exception raised without message'),
        ]
    
    def analyze_code(self, content: str, file_path: str = None) -> List[Issue]:
        """Analyze code for error handling issues."""
        issues = []
        lines = content.split('\n')
        
        # Check line by line for simple patterns
        for line_num, line in enumerate(lines, 1):
            for pattern, description in self.patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    location = IssueLocation(file_path, line_num)
                    
                    severity = IssueSeverity.ERROR if 'bare except' in description.lower() else IssueSeverity.WARNING
                    
                    issue = Issue(
                        id=Issue.create_id(location, IssueCategory.ERROR_HANDLING, description),
                        title=f"Error Handling: {description}",
                        description=f"{description} on line {line_num}",
                        category=IssueCategory.ERROR_HANDLING,
                        severity=severity,
                        location=location,
                        remediation=self._get_remediation(description.lower()),
                        code_snippet=line.strip(),
                        root_cause=f"Poor error handling practice: {description.lower()}",
                        sources=["error_handling_detector"]
                    )
                    issues.append(issue)
        
        # Check for multiline patterns (like except + pass)
        multiline_patterns = [
            (r'except\s+\w+.*:\s*\n\s*pass', 'Exception caught and ignored'),
            (r'except\s+\w+.*:\s*\n\s*continue', 'Exception silently ignored in loop'),
        ]
        
        for pattern, description in multiline_patterns:
            for match in re.finditer(pattern, content, re.MULTILINE):
                # Find line number of the match
                line_num = content[:match.start()].count('\n') + 1
                location = IssueLocation(file_path, line_num)
                
                issue = Issue(
                    id=Issue.create_id(location, IssueCategory.ERROR_HANDLING, description),
                    title=f"Error Handling: {description}",
                    description=f"{description} on line {line_num}",
                    category=IssueCategory.ERROR_HANDLING,
                    severity=IssueSeverity.WARNING,
                    location=location,
                    remediation=self._get_remediation(description.lower()),
                    code_snippet=match.group().strip(),
                    root_cause=f"Poor error handling practice: {description.lower()}",
                    sources=["error_handling_detector"]
                )
                issues.append(issue)
        
        return issues
    
    def _get_remediation(self, description: str) -> str:
        """Get specific remediation advice for error handling issues."""
        if 'bare except' in description:
            return 'Specify exception types: except ValueError, TypeError:'
        elif 'ignored' in description:
            return 'Add proper error logging and/or re-raise the exception'
        elif 'without logging' in description:
            return 'Add logging.error() or logger.exception() to track errors'
        elif 'without message' in description:
            return 'Include descriptive error message: raise ValueError("specific error")'
        return 'Follow proper error handling practices'

class IssueAggregator:
    """Aggregates and deduplicates issues from multiple sources with gap analysis."""
    
    def __init__(self):
        self.issues: Dict[str, Issue] = {}
        self.source_stats: Dict[str, int] = {}
        self.duplicates_found: List[Dict[str, str]] = []
        self.similarity_threshold = 0.7  # Threshold for considering issues as duplicates
    
    def add_issues(self, issues: List[Issue], source: str) -> None:
        """Add issues from a specific source, merging duplicates with enhanced tracking."""
        self.source_stats[source] = len(issues)
        
        for issue in issues:
            # First try exact ID match
            existing = self.issues.get(issue.id)
            
            # If no exact match, look for similar issues
            if not existing:
                existing = self._find_similar_issue(issue)
            
            if existing:
                # Track duplicate for gap analysis
                self.duplicates_found.append({
                    'id': existing.id,
                    'original_source': existing.sources[0] if existing.sources else 'unknown',
                    'duplicate_source': source,
                    'location': str(issue.location)
                })
                
                # Merge with existing issue - improve confidence if multiple tools agree
                existing.add_source(source)
                existing.confidence = min(1.0, existing.confidence + 0.1)
                
                # Enhance description with source attribution
                if source not in existing.description:
                    existing.description += f" (confirmed by {source})"
                
                # Merge titles if they're different but similar
                if issue.title != existing.title and source not in existing.title:
                    existing.title = f"{existing.title} / {issue.title}"
            else:
                # New issue - potential gap in other tools
                issue.add_source(source)
                self.issues[issue.id] = issue
    
    def _find_similar_issue(self, new_issue: Issue) -> Optional[Issue]:
        """Find an existing issue that's similar to the new one."""
        for existing_id, existing_issue in self.issues.items():
            # Check if issues are at the same location and same category
            if (existing_issue.location.file_path == new_issue.location.file_path and
                existing_issue.location.line_number == new_issue.location.line_number and
                existing_issue.category == new_issue.category):
                return existing_issue
            
            # Check for similar issues based on type and location proximity
            if (existing_issue.location.file_path == new_issue.location.file_path and
                existing_issue.category == new_issue.category):
                
                # Check line proximity (within 2 lines)
                if (existing_issue.location.line_number and new_issue.location.line_number and
                    abs(existing_issue.location.line_number - new_issue.location.line_number) <= 2):
                    
                    # Check title similarity
                    if self._are_titles_similar(existing_issue.title, new_issue.title):
                        return existing_issue
        
        return None
    
    def _are_titles_similar(self, title1: str, title2: str) -> bool:
        """Check if two issue titles are similar enough to be considered duplicates."""
        # Normalize titles
        t1_lower = title1.lower()
        t2_lower = title2.lower()
        
        # Check for common issue patterns
        common_patterns = [
            ('sql injection', 'sql injection'),
            ('bare except', 'bare except'),
            ('hardcoded', 'hardcoded'),
            ('api key', 'api key'),
            ('exception', 'exception'),
            ('error handling', 'error handling'),
            ('security', 'security'),
            ('vulnerability', 'vulnerability')
        ]
        
        for pattern1, pattern2 in common_patterns:
            if (pattern1 in t1_lower and pattern2 in t2_lower) or \
               (pattern2 in t1_lower and pattern1 in t2_lower):
                return True
        
        # Check word overlap
        words1 = set(t1_lower.split())
        words2 = set(t2_lower.split())
        
        # Remove common words
        stop_words = {'the', 'a', 'an', 'in', 'on', 'at', 'to', 'for', 'of', 'with', 'by', 'from', 'is', 'are', 'was', 'were'}
        words1 = words1 - stop_words
        words2 = words2 - stop_words
        
        if not words1 or not words2:
            return False
        
        # Calculate Jaccard similarity
        intersection = len(words1.intersection(words2))
        union = len(words1.union(words2))
        
        if union == 0:
            return False
        
        similarity = intersection / union
        return similarity >= self.similarity_threshold
    
    def get_gap_analysis(self) -> Dict[str, Any]:
        """Analyze gaps between different detection tools."""
        total_sources = len(self.source_stats)
        if total_sources < 2:
            return {'message': 'Need multiple sources for gap analysis'}
        
        # Find issues detected by only one tool
        single_source_issues = []
        multi_source_issues = []
        
        for issue in self.issues.values():
            if len(issue.sources) == 1:
                single_source_issues.append({
                    'id': issue.id,
                    'location': str(issue.location),
                    'source': issue.sources[0],
                    'category': issue.category.value,
                    'severity': issue.severity.value,
                    'title': issue.title
                })
            else:
                multi_source_issues.append({
                    'id': issue.id,
                    'location': str(issue.location),
                    'sources': issue.sources,
                    'confidence': issue.confidence
                })
        
        return {
            'source_stats': self.source_stats,
            'duplicates_found': len(self.duplicates_found),
            'single_source_issues': single_source_issues,
            'multi_source_issues': multi_source_issues,
            'coverage_gaps': len(single_source_issues),
            'consensus_issues': len(multi_source_issues)
        }
    
    def get_issues_by_category(self) -> Dict[IssueCategory, List[Issue]]:
        """Get issues organized by category."""
        categorized = {}
        for category in IssueCategory:
            categorized[category] = [
                issue for issue in self.issues.values() 
                if issue.category == category
            ]
            # Sort by severity
            categorized[category].sort(key=lambda x: list(IssueSeverity).index(x.severity))
        return categorized
    
    def get_all_issues(self) -> List[Issue]:
        """Get all issues sorted by severity."""
        all_issues = list(self.issues.values())
        all_issues.sort(key=lambda x: list(IssueSeverity).index(x.severity))
        return all_issues

class EnhancedReviewAnalyzer:
    """Main analyzer that coordinates all detection and produces structured output."""
    
    def __init__(self):
        self.security_detector = SecurityDetector()
        self.error_detector = ErrorHandlingDetector()
        self.aggregator = IssueAggregator()
    
    def analyze_diff(self, diff_content: str, file_path: str = None) -> Dict[str, Any]:
        """Analyze code diff and return structured review."""
        # Extract added lines (starting with +)
        added_lines = []
        current_file = file_path
        
        for line in diff_content.split('\n'):
            if line.startswith('+++'):
                # Extract filename from diff header
                current_file = line[4:].strip() if not file_path else file_path
            elif line.startswith('+') and not line.startswith('+++') and not line.startswith('@@'):
                added_lines.append(line[1:])  # Remove the + prefix
        
        added_content = '\n'.join(added_lines)
        
        # If no added content, return empty report
        if not added_content.strip():
            return {
                'summary': {'total_issues': 0, 'security_issues': 0, 'error_handling_issues': 0, 'other_issues': 0},
                'sections': {
                    'security': {'title': 'Security Issues', 'count': 0, 'issues': [], 'message': '✅ No security issues found'},
                    'error_handling': {'title': 'Error Handling Issues', 'count': 0, 'issues': [], 'message': '✅ No error handling issues found'},
                    'other': {'title': 'Other Issues', 'count': 0, 'issues': [], 'message': '✅ No other issues found'}
                },
                'source_attribution': {}
            }
        
        # Run all detectors
        security_issues = self.security_detector.analyze_code(added_content, current_file)
        error_issues = self.error_detector.analyze_code(added_content, current_file)
        
        # Aggregate issues
        self.aggregator = IssueAggregator()  # Reset for this analysis
        self.aggregator.add_issues(security_issues, "security_detector")
        self.aggregator.add_issues(error_issues, "error_handling_detector")
        
        return self._generate_structured_report()
    
    def integrate_external_issues(self, coderabbit_comments: List[Dict], github_ai_issues: List[Dict]) -> None:
        """Integrate issues from external tools (CodeRabbit, GitHub AI)."""
        # Process CodeRabbit comments
        for comment in coderabbit_comments:
            issue = self._parse_coderabbit_comment(comment)
            if issue:
                self.aggregator.add_issues([issue], "coderabbit")
        
        # Process GitHub AI issues
        for ai_issue in github_ai_issues:
            issue = self._parse_github_ai_issue(ai_issue)
            if issue:
                self.aggregator.add_issues([issue], "github_ai")
    
    def _parse_coderabbit_comment(self, comment: Dict) -> Optional[Issue]:
        """Parse CodeRabbit comment into our Issue format."""
        body = comment.get('body', '')
        if not body:
            return None
        
        # Determine category based on content
        category = IssueCategory.OTHER
        severity = IssueSeverity.INFO
        
        body_lower = body.lower()
        if any(word in body_lower for word in ['security', 'vulnerability', 'injection', 'xss']):
            category = IssueCategory.SECURITY
            severity = IssueSeverity.ERROR
        elif any(word in body_lower for word in ['error', 'exception', 'handling']):
            category = IssueCategory.ERROR_HANDLING
            severity = IssueSeverity.WARNING
        elif any(word in body_lower for word in ['performance', 'slow', 'memory']):
            category = IssueCategory.PERFORMANCE
            severity = IssueSeverity.WARNING
        
        location = IssueLocation(
            file_path=comment.get('path'),
            line_number=comment.get('line')
        )
        
        return Issue(
            id=Issue.create_id(location, category, body[:50]),
            title=f"CodeRabbit: {body.split('.')[0][:100]}",
            description=body,
            category=category,
            severity=severity,
            location=location,
            remediation="Follow CodeRabbit's suggestions",
            sources=["coderabbit"]
        )
    
    def _parse_github_ai_issue(self, ai_issue: Dict) -> Optional[Issue]:
        """Parse GitHub AI issue into our Issue format."""
        # Similar parsing logic for GitHub AI issues
        body = ai_issue.get('body', ai_issue.get('message', ''))
        if not body:
            return None
        
        category = IssueCategory.OTHER
        severity = IssueSeverity.INFO
        
        # Determine category and severity from AI issue content
        body_lower = body.lower()
        if any(word in body_lower for word in ['security', 'vulnerability']):
            category = IssueCategory.SECURITY
            severity = IssueSeverity.ERROR
        elif any(word in body_lower for word in ['error', 'exception']):
            category = IssueCategory.ERROR_HANDLING
            severity = IssueSeverity.WARNING
        
        location = IssueLocation(
            file_path=ai_issue.get('path'),
            line_number=ai_issue.get('line')
        )
        
        return Issue(
            id=Issue.create_id(location, category, body[:50]),
            title=f"GitHub AI: {body.split('.')[0][:100]}",
            description=body,
            category=category,
            severity=severity,
            location=location,
            remediation="Address GitHub AI recommendations",
            sources=["github_ai"]
        )
    
    def _generate_structured_report(self) -> Dict[str, Any]:
        """Generate structured review report with 3 main sections, OWASP mapping, and gap analysis."""
        categorized = self.aggregator.get_issues_by_category()
        gap_analysis = self.aggregator.get_gap_analysis()
        
        # Build the structured report
        report = {
            'summary': {
                'total_issues': len(self.aggregator.get_all_issues()),
                'security_issues': len(categorized[IssueCategory.SECURITY]),
                'error_handling_issues': len(categorized[IssueCategory.ERROR_HANDLING]),
                'other_issues': len(categorized[IssueCategory.PERFORMANCE]) + 
                              len(categorized[IssueCategory.CODE_QUALITY]) + 
                              len(categorized[IssueCategory.TESTING]) + 
                              len(categorized[IssueCategory.OTHER]),
                'owasp_categories': self._get_owasp_summary(categorized[IssueCategory.SECURITY]),
                'confidence_avg': self._calculate_avg_confidence()
            },
            'sections': {
                'security': self._format_security_section(categorized[IssueCategory.SECURITY]),
                'error_handling': self._format_issues_section(categorized[IssueCategory.ERROR_HANDLING], "Error Handling Issues"),
                'other': self._format_other_issues_section(categorized)
            },
            'source_attribution': self._generate_source_attribution(),
            'gap_analysis': gap_analysis
        }
        
        return report
    
    def _get_owasp_summary(self, security_issues: List[Issue]) -> Dict[str, int]:
        """Generate summary of OWASP Top 10 categories found."""
        owasp_counts = {}
        for issue in security_issues:
            if issue.owasp_category:
                owasp_counts[issue.owasp_category] = owasp_counts.get(issue.owasp_category, 0) + 1
        return owasp_counts
    
    def _calculate_avg_confidence(self) -> float:
        """Calculate average confidence score across all issues."""
        issues = self.aggregator.get_all_issues()
        if not issues:
            return 0.0
        return sum(issue.confidence for issue in issues) / len(issues)
    
    def _format_security_section(self, security_issues: List[Issue]) -> Dict[str, Any]:
        """Format security section with OWASP mapping."""
        if not security_issues:
            return {
                'title': 'Security Issues',
                'count': 0,
                'issues': [],
                'message': '✅ No security issues found',
                'owasp_summary': {}
            }
        
        formatted_issues = []
        for issue in security_issues:
            formatted_issue = {
                'id': issue.id,
                'title': issue.title,
                'description': issue.description,
                'severity': issue.severity.value,
                'location': str(issue.location),
                'remediation': issue.remediation,
                'root_cause': issue.root_cause,
                'sources': issue.sources,
                'code_snippet': issue.code_snippet,
                'owasp_category': issue.owasp_category,
                'confidence': issue.confidence
            }
            formatted_issues.append(formatted_issue)
        
        return {
            'title': 'Security Issues',
            'count': len(security_issues),
            'issues': formatted_issues,
            'owasp_summary': self._get_owasp_summary(security_issues)
        }
    
    def _format_issues_section(self, issues: List[Issue], section_title: str) -> Dict[str, Any]:
        """Format a section of issues with detailed information."""
        if not issues:
            return {
                'title': section_title,
                'count': 0,
                'issues': [],
                'message': f"✅ No {section_title.lower()} found"
            }
        
        formatted_issues = []
        for issue in issues:
            formatted_issues.append({
                'id': issue.id,
                'title': issue.title,
                'description': issue.description,
                'severity': issue.severity.value,
                'location': str(issue.location),
                'remediation': issue.remediation,
                'root_cause': issue.root_cause,
                'sources': issue.sources,
                'code_snippet': issue.code_snippet
            })
        
        return {
            'title': section_title,
            'count': len(issues),
            'issues': formatted_issues
        }
    
    def _format_other_issues_section(self, categorized: Dict[IssueCategory, List[Issue]]) -> Dict[str, Any]:
        """Format the 'Other Issues' section combining multiple categories."""
        other_issues = []
        for category in [IssueCategory.PERFORMANCE, IssueCategory.CODE_QUALITY, 
                        IssueCategory.TESTING, IssueCategory.OTHER]:
            other_issues.extend(categorized[category])
        
        return self._format_issues_section(other_issues, "Other Issues")
    
    def _generate_source_attribution(self) -> Dict[str, int]:
        """Generate attribution showing which sources found how many issues."""
        attribution = {}
        for issue in self.aggregator.get_all_issues():
            for source in issue.sources:
                attribution[source] = attribution.get(source, 0) + 1
        return attribution