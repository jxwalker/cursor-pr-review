#!/usr/bin/env python3
"""
CURSOR PR REVIEW

"""

import os
import sys
import json
import logging
import subprocess
import time
from pathlib import Path
from typing import Dict, Any, Optional, List, Union
from dataclasses import dataclass, asdict

import requests
import yaml
from functools import wraps

# Import new prompt management system
try:
    from prompt_manager import PromptManager
    from prompt_cli import PromptCLI
    PROMPT_MANAGER_AVAILABLE = True
except ImportError:
    PROMPT_MANAGER_AVAILABLE = False
    logger.warning("Advanced prompt management not available")

# Import enhanced issue analysis system
try:
    from issue_analyzer import EnhancedReviewAnalyzer, Issue, IssueCategory, IssueSeverity
    ENHANCED_ANALYSIS_AVAILABLE = True
except ImportError:
    ENHANCED_ANALYSIS_AVAILABLE = False
    logger.warning("Enhanced issue analysis not available")

# Production logging 
def setup_logging(verbose: bool = False) -> logging.Logger:
    """Setup production logging with proper levels."""
    log_dir = Path.home() / '.cursor-pr-review'
    log_dir.mkdir(exist_ok=True)
    
    level = logging.DEBUG if verbose else logging.INFO
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    
    logger = logging.getLogger('cursor_pr_review')
    logger.setLevel(level)
    logger.handlers.clear()  # Prevent duplicate handlers
    
    # Console handler
    console = logging.StreamHandler()
    console.setFormatter(formatter)
    logger.addHandler(console)
    
    # File handler
    file_handler = logging.FileHandler(log_dir / 'review.log')
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    
    return logger

logger = setup_logging()

# Retry decorator for API calls
def retry_on_failure(max_retries: int = 3, delay: float = 1.0):
    """Decorator to retry API calls on failure."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            last_exception = None
            if max_retries < 1:
                raise ValueError("max_retries must be >= 1")
            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except (requests.exceptions.RequestException, APIError) as e:
                    last_exception = e
                    if attempt < max_retries - 1:
                        wait_time = delay * (2 ** attempt)  # Exponential backoff
                        logger.warning(f"API call failed (attempt {attempt + 1}/{max_retries}), retrying in {wait_time}s: {e}")
                        time.sleep(wait_time)
                    else:
                        logger.error(f"API call failed after {max_retries} attempts: {e}")
            if last_exception is not None:
                raise last_exception
            else:
                raise RuntimeError("No exception captured in retry_on_failure")
        return wrapper
    return decorator

# 100% consistent exception hierarchy
class ReviewError(Exception):
    """Base exception with helpful error messages."""
    def __init__(self, message: str, fix_hint: str = None):
        self.message = message
        self.fix_hint = fix_hint
        super().__init__(self.message)
    
    def __str__(self):
        if self.fix_hint:
            return f"{self.message}\n\n💡 FIX: {self.fix_hint}"
        return self.message

class ConfigError(ReviewError):
    """Configuration errors."""
    pass

class APIError(ReviewError):
    """API communication errors."""
    pass

class SecurityError(ReviewError):
    """Security validation errors."""
    pass

# Type-safe configuration
@dataclass
class ReviewConfig:
    """Complete configuration with validation."""
    github_token: str
    ai_provider: str  # 'openai' or 'anthropic'
    ai_key: str
    ai_model: str
    repo: str
    use_coderabbit: bool = True  # Default to True since we're now using it properly
    coderabbit_threshold: str = "medium"  # 'low', 'medium', 'high'
    coderabbit_auto_approve: bool = False
    review_strictness: str = "balanced"  # 'strict', 'balanced', 'lenient'
    auto_request_changes: bool = True  # Automatically request changes for critical issues
    prompt_type: str = "default"  # Type of prompt to use: default, strict, lenient, security-focused, custom
    prompt_template: str = ""  # Will be loaded dynamically based on prompt_type
    
    def validate(self) -> None:
        """Validate all configuration values."""
        if len(self.github_token) < 20:
            raise SecurityError(
                "GitHub token too short", 
                "Get a valid token at https://github.com/settings/tokens"
            )
        if len(self.ai_key) < 20:
            raise SecurityError(
                f"{self.ai_provider} API key too short",
                f"Get a valid key from {self.ai_provider} console"
            )
        if '/' not in self.repo:
            raise ConfigError(
                "Invalid repository format",
                "Use format 'owner/repo' (e.g. 'microsoft/vscode')"
            )
        if self.ai_provider not in ['openai', 'anthropic']:
            raise ConfigError(
                f"Unsupported AI provider: {self.ai_provider}",
                "Use 'openai' or 'anthropic'"
            )
        if self.coderabbit_threshold not in ['low', 'medium', 'high']:
            raise ConfigError(
                f"Invalid CodeRabbit threshold: {self.coderabbit_threshold}",
                "Use 'low', 'medium', or 'high'"
            )
        if self.review_strictness not in ['strict', 'balanced', 'lenient']:
            raise ConfigError(
                f"Invalid review strictness: {self.review_strictness}",
                "Use 'strict', 'balanced', or 'lenient'"
            )
        if self.prompt_type not in get_available_prompts():
            logger.warning(f"Prompt type '{self.prompt_type}' not available, will use default")

# Prompt management
def get_available_prompts() -> List[str]:
    """Get list of available prompt templates."""
    prompts_dir = Path('prompts')
    if not prompts_dir.exists():
        return ['default']
    
    prompt_files = list(prompts_dir.glob('*.txt'))
    return [f.stem for f in prompt_files] + ['custom']

def load_prompt_template(prompt_name: str) -> str:
    """Load prompt template from file or advanced prompt manager."""
    # Try advanced prompt manager first
    if PROMPT_MANAGER_AVAILABLE:
        try:
            manager = PromptManager()
            prompt_metadata = manager.get_prompt(prompt_name)
            if prompt_metadata and prompt_metadata.is_active:
                return prompt_metadata.get_current_content()
        except Exception as e:
            logger.warning(f"Failed to load from prompt manager: {e}")
    
    # Fallback to legacy system
    if prompt_name == 'custom':
        config_dir = Path.home() / '.cursor-pr-review'
        custom_file = config_dir / 'custom_prompt.txt'
        if custom_file.exists():
            try:
                return custom_file.read_text(encoding='utf-8').strip()
            except OSError as e:
                logger.warning(f"Failed to load custom prompt: {e}")
                return get_default_prompt()
        else:
            return get_default_prompt()
    
    prompt_file = Path('prompts') / f'{prompt_name}.txt'
    if prompt_file.exists():
        try:
            return prompt_file.read_text(encoding='utf-8').strip()
        except OSError as e:
            logger.warning(f"Failed to load prompt '{prompt_name}': {e}")
            return get_default_prompt()
    
    logger.warning(f"Prompt '{prompt_name}' not found, using default")
    return get_default_prompt()

def get_default_prompt() -> str:
    """Get the enhanced default prompt template based on self-improvement recommendations."""
    return """Thoroughly scan for security vulnerabilities, explicitly listing OWASP Top 10 issues if found. Clearly flag all error handling concerns, including missing, inadequate, or incorrect try-except blocks and improper error propagation. When security or error handling issues are found, cite the affected function and line number. If security or error handling issues were already raised by another tool (e.g., CodeRabbit, GitHub AI), de-duplicate your response by referencing the original finding, NOT repeating the explanation.

## 1. SECURITY ISSUES
Conduct comprehensive OWASP Top 10 security analysis:
- **A01: Broken Access Control** - Authorization bypass, privilege escalation
- **A02: Cryptographic Failures** - Weak encryption, exposed sensitive data
- **A03: Injection** - SQL, NoSQL, OS command, LDAP injection
- **A04: Insecure Design** - Missing security controls, threat modeling gaps
- **A05: Security Misconfiguration** - Default configs, incomplete setups
- **A06: Vulnerable Components** - Outdated libraries, known vulnerabilities
- **A07: Authentication Failures** - Weak authentication, session management
- **A08: Software Integrity Failures** - Unsigned updates, insecure CI/CD
- **A09: Logging/Monitoring Failures** - Insufficient logging, delayed detection
- **A10: Server-Side Request Forgery** - SSRF vulnerabilities

Additional security checks:
- Input validation issues (SQL injection, XSS, command injection)
- Hardcoded secrets and credentials
- Unsafe function usage (eval, exec, pickle.loads)
- Cryptographic weaknesses

For each security issue:
- **Root Cause**: Explain what makes this vulnerable
- **Location**: Specify file and line number (e.g., auth.py:42)
- **OWASP Category**: Map to relevant OWASP Top 10 item
- **Impact**: Describe potential exploitation
- **Remediation**: Provide specific fix instructions
- **Severity**: Rate as CRITICAL/ERROR/WARNING
- **Sources**: List all tools that detected this issue

## 2. ERROR HANDLING ISSUES
Systematically analyze error handling patterns:
- Bare except clauses without exception types
- Exceptions caught and ignored silently (except + pass/continue)
- Missing error logging in exception handlers
- Improper exception propagation
- Missing validation for external inputs
- Inadequate error recovery mechanisms

For each error handling issue:
- **Root Cause**: Why this is problematic
- **Location**: File and line number (e.g., processor.py:156)
- **Remediation**: How to improve error handling
- **Severity**: Rate as ERROR/WARNING/SUGGESTION
- **Sources**: List all tools that detected this issue

## 3. OTHER ISSUES
Cover remaining code quality concerns:
- Performance bottlenecks and inefficient algorithms
- Code maintainability and readability issues
- Missing or inadequate test coverage
- Architectural or design pattern violations
- Documentation gaps

## DEDUPLICATION AND SOURCE ATTRIBUTION
Before flagging an issue, check if the same file/line/function was already flagged by GitHub AI/CodeRabbit for the same issue type:
- If duplicate found: Reference original tool's warning, don't repeat explanation
- If enhancement possible: Add "Building on CodeRabbit's finding..." with additional context
- For each reported issue, append source attribution: `Sources: [CodeRabbit, GitHubAI, OurTool]`
- In summary, list each unique issue once with all detecting sources

## GAP ANALYSIS
Explicitly identify gaps between tools:
- Issues found by our analysis but missed by CodeRabbit/GitHub AI
- Issues mentioned by other tools but with unclear context (provide clarification)
- Mismatches in issue counts between tools (investigate discrepancies)

## FORMATTING REQUIREMENTS
- Use clear headings for each section
- Provide specific file:line references
- Include code snippets when relevant
- Prioritize issues by severity
- Give actionable remediation steps
- Always include source attribution

If no issues are found in a section, state: "✅ No [category] issues detected"
"""

def save_custom_prompt(prompt_content: str) -> None:
    """Save custom prompt template."""
    config_dir = Path.home() / '.cursor-pr-review'
    config_dir.mkdir(exist_ok=True)
    
    custom_file = config_dir / 'custom_prompt.txt'
    try:
        custom_file.write_text(prompt_content, encoding='utf-8')
        os.chmod(custom_file, 0o600)
        logger.info(f"Custom prompt saved to {custom_file}")
    except OSError as e:
        raise ConfigError(f"Failed to save custom prompt: {e}", "Check permissions")

def list_prompts() -> None:
    """List available prompt templates with descriptions."""
    prompts = get_available_prompts()
    
    print("\n📝 Available Prompt Templates:")
    print("=" * 50)
    
    descriptions = {
        'default': 'Balanced review focusing on security, bugs, performance, and quality',
        'strict': 'Thorough analysis with zero tolerance for any issues',
        'lenient': 'Focus on critical issues only, practical and constructive',
        'security-focused': 'Comprehensive security-first analysis',
        'custom': 'Your personalized prompt template'
    }
    
    for prompt in prompts:
        desc = descriptions.get(prompt, 'User-defined prompt template')
        status = "✅" if prompt == 'custom' and (Path.home() / '.cursor-pr-review' / 'custom_prompt.txt').exists() else "📄"
        print(f"  {status} {prompt:<20} - {desc}")
    
    print("\n💡 Use: python cursor_pr_review.py edit-prompt <name> to customize")
    print("💡 Use: python cursor_pr_review.py view-prompt <name> to preview")

def view_prompt(prompt_name: str) -> None:
    """View a specific prompt template."""
    prompt_content = load_prompt_template(prompt_name)
    
    print(f"\n📝 Prompt Template: {prompt_name}")
    print("=" * 60)
    print(prompt_content)
    print("=" * 60)
    print(f"\n💡 Length: {len(prompt_content)} characters")

def edit_prompt_interactive() -> None:
    """Interactive prompt editing."""
    print("\n✏️  Custom Prompt Editor")
    print("=" * 40)
    
    # Show current custom prompt if exists
    config_dir = Path.home() / '.cursor-pr-review'
    custom_file = config_dir / 'custom_prompt.txt'
    
    if custom_file.exists():
        current_prompt = load_prompt_template('custom')
        print("\n📄 Current custom prompt:")
        print("-" * 40)
        print(current_prompt[:200] + "..." if len(current_prompt) > 200 else current_prompt)
        print("-" * 40)
        
        if input("\nEdit existing prompt? (y/n): ").strip().lower() != 'y':
            return
    
    print("\n📝 Enter your custom prompt (press Ctrl+D when done, Ctrl+C to cancel):")
    print("💡 Tip: Include placeholders for severity levels and specific guidance")
    print("-" * 60)
    
    lines = []
    try:
        while True:
            try:
                line = input()
                lines.append(line)
            except EOFError:
                break
    except KeyboardInterrupt:
        print("\n❌ Edit cancelled")
        return
    
    prompt_content = '\n'.join(lines).strip()
    
    if not prompt_content:
        print("❌ Empty prompt not saved")
        return
    
    # Validate prompt
    if len(prompt_content) < 50:
        print("⚠️  Warning: Prompt seems very short. Continue anyway? (y/n): ", end="")
        if input().strip().lower() != 'y':
            return
    
    try:
        save_custom_prompt(prompt_content)
        print(f"\n✅ Custom prompt saved! ({len(prompt_content)} characters)")
        print("💡 Use 'custom' as prompt type in your configuration")
    except Exception as e:
        print(f"❌ Failed to save prompt: {e}")

# Configuration persistence
def load_config() -> Optional[ReviewConfig]:
    """Load configuration from file."""
    config_file = Path.home() / '.cursor-pr-review' / 'config.json'
    
    if not config_file.exists():
        return None
    
    try:
        with open(config_file) as f:
            data = json.load(f)
        
        config = ReviewConfig(**data)
        config.validate()
        return config
        
    except (json.JSONDecodeError, TypeError, KeyError) as e:
        raise ConfigError(
            f"Invalid configuration: {e}",
            f"Delete {config_file} and run setup again"
        )

def save_config(config: ReviewConfig) -> None:
    """Save configuration securely."""
    config_dir = Path.home() / '.cursor-pr-review'
    config_dir.mkdir(exist_ok=True)
    
    config_file = config_dir / 'config.json'
    
    try:
        with open(config_file, 'w') as f:
            json.dump(asdict(config), f, indent=2)
        
        os.chmod(config_file, 0o600)
        logger.info(f"Configuration saved to {config_file}")
        
    except OSError as e:
        raise ConfigError(f"Failed to save config: {e}", "Check permissions")

# Standardized API client
class APIClient:
    """Unified API client for all services."""
    
    def __init__(self, config: ReviewConfig):
        self.config = config
        self.session = requests.Session()
        self.session.timeout = 30
    
    @retry_on_failure(max_retries=3, delay=1.0)
    def validate_github_token(self) -> Dict[str, Any]:
        """Validate GitHub token with proper error handling."""
        try:
            response = self.session.get(
                "https://api.github.com/user",
                headers={"Authorization": f"token {self.config.github_token}"}
            )
            response.raise_for_status()
            user_data = response.json()
            logger.info(f"GitHub token valid for user: {user_data.get('login')}")
            return user_data
            
        except requests.exceptions.HTTPError as e:
            if e.response and e.response.status_code == 401:
                raise APIError(
                    "Invalid GitHub token",
                    "Get a new token at https://github.com/settings/tokens"
                )
            raise APIError(f"GitHub API error: {e}") from e
        except requests.exceptions.RequestException as e:
            raise APIError(f"GitHub API connection failed: {e}", "Check internet connection") from e
    
    def validate_ai_key(self) -> Dict[str, Any]:
        """Validate AI API key with provider-specific logic."""
        if self.config.ai_provider == 'openai':
            return self._validate_openai()
        elif self.config.ai_provider == 'anthropic':
            return self._validate_anthropic()
        else:
            raise ConfigError(f"Unknown provider: {self.config.ai_provider}")
    
    def _validate_openai(self) -> Dict[str, Any]:
        """Validate OpenAI API key."""
        try:
            response = self.session.get(
                "https://api.openai.com/v1/models",
                headers={"Authorization": f"Bearer {self.config.ai_key}"},
                timeout=30
            )
            response.raise_for_status()
            return response.json()
            
        except requests.exceptions.HTTPError as e:
            if e.response and e.response.status_code == 401:
                raise APIError(
                    "Invalid OpenAI API key",
                    "Get a key at https://platform.openai.com/api-keys"
                ) from e
            raise APIError(f"OpenAI API error: {e}") from e
        except requests.exceptions.RequestException as e:
            raise APIError(f"OpenAI API connection failed: {e}", "Check internet connection") from e
    
    def _validate_anthropic(self) -> Dict[str, Any]:
        """Validate Anthropic API key."""
        try:
            response = self.session.get(
                "https://api.anthropic.com/v1/models",
                headers={
                    "x-api-key": self.config.ai_key,
                    "anthropic-version": "2023-06-01"
                },
                timeout=30
            )
            response.raise_for_status()
            return response.json()
            
        except requests.exceptions.HTTPError as e:
            if e.response and e.response.status_code == 401:
                raise APIError(
                    "Invalid Anthropic API key", 
                    "Get a key at https://console.anthropic.com"
                ) from e
            raise APIError(f"Anthropic API error: {e}") from e
        except requests.exceptions.RequestException as e:
            raise APIError(f"Anthropic API connection failed: {e}", "Check internet connection") from e

    @retry_on_failure(max_retries=3, delay=1.0)
    def get_pr_details(self, repo: str, pr_number: str) -> Dict[str, Any]:
        """Get PR details from GitHub API."""
        try:
            response = self.session.get(
                f"https://api.github.com/repos/{repo}/pulls/{pr_number}",
                headers={"Authorization": f"token {self.config.github_token}"},
                timeout=30
            )
            response.raise_for_status()
            return response.json()

        except requests.exceptions.RequestException as e:
            raise APIError(f"Failed to get PR details: {e}") from e

    @retry_on_failure(max_retries=3, delay=1.0)
    def get_pr_diff(self, repo: str, pr_number: str) -> str:
        """Get PR diff from GitHub API."""
        try:
            response = self.session.get(
                f"https://api.github.com/repos/{repo}/pulls/{pr_number}",
                headers={
                    "Authorization": f"token {self.config.github_token}",
                    "Accept": "application/vnd.github.v3.diff"
                },
                timeout=30
            )
            response.raise_for_status()
            return response.text

        except requests.exceptions.RequestException as e:
            raise APIError(f"Failed to get PR diff: {e}") from e

    def analyze_code_with_ai(self, diff: str, prompt_template: str, coderabbit_comments: List[Dict[str, Any]] = None, github_ai_prompt: str = None) -> List[Dict[str, Any]]:
        """Analyze code diff using enhanced AI analysis with structured output."""
        # Use enhanced analysis if available
        if ENHANCED_ANALYSIS_AVAILABLE:
            return self._analyze_with_enhanced_system(diff, prompt_template, coderabbit_comments, github_ai_prompt)
        
        # Fallback to original analysis
        if self.config.ai_provider == 'openai':
            return self._analyze_with_openai(diff, prompt_template, coderabbit_comments, github_ai_prompt)
        elif self.config.ai_provider == 'anthropic':
            return self._analyze_with_anthropic(diff, prompt_template, coderabbit_comments, github_ai_prompt)
        else:
            raise ConfigError(f"Unknown AI provider: {self.config.ai_provider}")
    
    def _analyze_with_enhanced_system(self, diff: str, prompt_template: str, coderabbit_comments: List[Dict[str, Any]] = None, github_ai_prompt: str = None) -> List[Dict[str, Any]]:
        """Enhanced analysis using the new issue analyzer system."""
        try:
            analyzer = EnhancedReviewAnalyzer()
            
            # Analyze the diff with enhanced detectors
            analysis_report = analyzer.analyze_diff(diff)
            
            # Integrate external tool findings
            if coderabbit_comments:
                github_ai_issues = []
                if github_ai_prompt:
                    # Parse GitHub AI prompt into issues format
                    github_ai_issues = [{'body': github_ai_prompt, 'path': None, 'line': None}]
                
                analyzer.integrate_external_issues(coderabbit_comments, github_ai_issues)
                analysis_report = analyzer._generate_structured_report()
            
            # Run AI analysis with enhanced prompt
            ai_comments = []
            if self.config.ai_provider == 'openai':
                ai_comments = self._analyze_with_openai(diff, prompt_template, coderabbit_comments, github_ai_prompt)
            elif self.config.ai_provider == 'anthropic':
                ai_comments = self._analyze_with_anthropic(diff, prompt_template, coderabbit_comments, github_ai_prompt)
            
            # Combine enhanced detection with AI analysis
            return self._merge_analysis_results(analysis_report, ai_comments)
        
        except Exception as e:
            logger.warning(f"Enhanced analysis failed, falling back to standard analysis: {e}")
            # Fallback to standard analysis
            if self.config.ai_provider == 'openai':
                return self._analyze_with_openai(diff, prompt_template, coderabbit_comments, github_ai_prompt)
            elif self.config.ai_provider == 'anthropic':
                return self._analyze_with_anthropic(diff, prompt_template, coderabbit_comments, github_ai_prompt)
            else:
                return []
    
    def _merge_analysis_results(self, enhanced_report: Dict[str, Any], ai_comments: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Merge enhanced detection results with AI analysis."""
        merged_comments = []
        
        # Add structured report as primary comment
        if enhanced_report['summary']['total_issues'] > 0:
            structured_comment = self._format_structured_report(enhanced_report)
            merged_comments.append({
                'body': structured_comment,
                'severity': 'info',
                'path': None,
                'line': None
            })
        
        # Add AI comments as supplementary analysis
        for comment in ai_comments:
            # Avoid duplicate structured reports
            if 'Enhanced Code Analysis Results' not in comment.get('body', ''):
                comment['body'] = f"**AI Analysis**: {comment['body']}"
                merged_comments.append(comment)
        
        return merged_comments
    
    def _format_structured_report(self, report: Dict[str, Any]) -> str:
        """Format the structured analysis report for display with OWASP mapping and gap analysis."""
        output = ["## 🔍 Enhanced Code Analysis Results"]
        output.append("")
        
        summary = report['summary']
        output.append(f"**Summary**: {summary['total_issues']} total issues found")
        output.append(f"• 🔒 Security: {summary['security_issues']} issues")
        output.append(f"• ⚠️ Error Handling: {summary['error_handling_issues']} issues")
        output.append(f"• 📋 Other: {summary['other_issues']} issues")
        
        # Add OWASP summary if available
        if summary.get('owasp_categories'):
            output.append(f"• 🛡️ OWASP Categories: {len(summary['owasp_categories'])} types found")
        
        # Add confidence score
        if 'confidence_avg' in summary:
            confidence_pct = int(summary['confidence_avg'] * 100)
            output.append(f"• 📊 Confidence: {confidence_pct}%")
        
        output.append("")
        
        # Format each section
        for section_name, section_data in report['sections'].items():
            if section_data['count'] > 0:
                output.append(f"### {section_data['title']}")
                output.append("")
                
                # Add OWASP summary for security section
                if section_name == 'security' and section_data.get('owasp_summary'):
                    output.append("**OWASP Top 10 Categories:**")
                    for owasp_cat, count in section_data['owasp_summary'].items():
                        output.append(f"• {owasp_cat}: {count} issue{'s' if count != 1 else ''}")
                    output.append("")
                
                for issue in section_data['issues']:
                    output.append(f"**{issue['severity'].upper()}**: {issue['title']}")
                    output.append(f"📍 Location: {issue['location']}")
                    output.append(f"📝 Description: {issue['description']}")
                    output.append(f"🔧 Remediation: {issue['remediation']}")
                    
                    # Add OWASP category for security issues
                    if issue.get('owasp_category'):
                        output.append(f"🛡️ OWASP: {issue['owasp_category']}")
                    
                    # Add confidence score
                    if issue.get('confidence'):
                        confidence_pct = int(issue['confidence'] * 100)
                        output.append(f"📊 Confidence: {confidence_pct}%")
                    
                    if issue['sources']:
                        sources_str = ", ".join(issue['sources'])
                        output.append(f"🔍 Detected by: {sources_str}")
                    
                    if issue['code_snippet']:
                        output.append(f"```\n{issue['code_snippet']}\n```")
                    
                    output.append("")
            else:
                output.append(f"### {section_data['title']}")
                output.append(section_data.get('message', f"✅ No issues found"))
                output.append("")
        
        # Add gap analysis
        if report.get('gap_analysis') and 'source_stats' in report['gap_analysis']:
            gap = report['gap_analysis']
            output.append("### 🔍 Gap Analysis")
            output.append(f"• **Coverage gaps**: {gap.get('coverage_gaps', 0)} issues found by only one tool")
            output.append(f"• **Consensus issues**: {gap.get('consensus_issues', 0)} issues confirmed by multiple tools")
            output.append(f"• **Duplicates prevented**: {gap.get('duplicates_found', 0)}")
            
            if gap.get('single_source_issues'):
                output.append("\n**Tool-specific findings:**")
                for unique_issue in gap['single_source_issues'][:3]:  # Show top 3
                    output.append(f"• {unique_issue['source']}: {unique_issue['title']} ({unique_issue['location']})")
            output.append("")
        
        # Add source attribution
        if report.get('source_attribution'):
            output.append("### 📊 Analysis Attribution")
            for source, count in report['source_attribution'].items():
                output.append(f"• {source}: {count} issues")
            output.append("")
        
        return "\n".join(output)

    @retry_on_failure(max_retries=3, delay=2.0)
    def _analyze_with_openai(self, diff: str, prompt_template: str, coderabbit_comments: List[Dict[str, Any]] = None, github_ai_prompt: str = None) -> List[Dict[str, Any]]:
        """Analyze code using OpenAI, incorporating all available context."""
        try:
            # Build enhanced prompt with all available context
            prompt = f"{prompt_template}\n\nCode diff:\n{diff}"

            # Add GitHub AI agent prompt if available
            if github_ai_prompt:
                prompt += "\n\n## GitHub AI Agent Analysis\n"
                prompt += "GitHub has generated the following AI-friendly summary of this PR:\n\n"
                prompt += f"{github_ai_prompt}\n"
                prompt += "\nPlease consider this context in your analysis.\n"

            # Add CodeRabbit context if available
            if coderabbit_comments and self.config.use_coderabbit:
                prompt += "\n\n## CodeRabbit Analysis Results\n"
                prompt += "CodeRabbit has already reviewed this PR. Please consider their feedback and provide additional insights:\n\n"

                for i, comment in enumerate(coderabbit_comments[:5], 1):  # Limit to 5 most relevant
                    comment_text = comment.get('body', '').strip()
                    if comment_text:
                        file_info = ""
                        if comment.get('path'):
                            file_info = f" (in {comment['path']}"
                            if comment.get('line'):
                                file_info += f" line {comment['line']}"
                            file_info += ")"

                        prompt += f"{i}. CodeRabbit{file_info}: {comment_text}\n"

                prompt += "\nPlease:\n"
                prompt += "- Build upon CodeRabbit's analysis\n"
                prompt += "- Identify any issues CodeRabbit may have missed\n"
                prompt += "- Provide additional security, performance, or architectural insights\n"
                prompt += "- Avoid duplicating CodeRabbit's exact findings unless you have additional context\n"

            # Add comprehensive analysis instructions
            if github_ai_prompt or coderabbit_comments:
                prompt += "\n\n## Comprehensive Analysis Request\n"
                prompt += "Given the above context, please provide a thorough analysis that:\n"
                prompt += "- Addresses any specific issues mentioned in the GitHub AI prompt\n"
                prompt += "- Complements existing CodeRabbit feedback\n"
                prompt += "- Identifies patterns or architectural concerns\n"
                prompt += "- Suggests improvements for code maintainability and reliability\n"

            response = self.session.post(
                "https://api.openai.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {self.config.ai_key}"},
                json={
                    "model": self.config.ai_model,
                    "messages": [{"role": "user", "content": prompt}],
                    "max_tokens": 1500  # Increased for more comprehensive analysis
                }
            )
            response.raise_for_status()

            result = response.json()
            analysis = result['choices'][0]['message']['content']

            # Parse analysis into review comments
            return self._parse_ai_analysis(analysis)

        except requests.exceptions.RequestException as e:
            raise APIError(f"OpenAI analysis failed: {e}") from e

    @retry_on_failure(max_retries=3, delay=2.0)
    def _analyze_with_anthropic(self, diff: str, prompt_template: str, coderabbit_comments: List[Dict[str, Any]] = None, github_ai_prompt: str = None) -> List[Dict[str, Any]]:
        """Analyze code using Anthropic, incorporating all available context."""
        try:
            # Build enhanced prompt with all available context
            prompt = f"{prompt_template}\n\nCode diff:\n{diff}"

            # Add GitHub AI agent prompt if available
            if github_ai_prompt:
                prompt += "\n\n## GitHub AI Agent Analysis\n"
                prompt += "GitHub has generated the following AI-friendly summary of this PR:\n\n"
                prompt += f"{github_ai_prompt}\n"
                prompt += "\nPlease consider this context in your analysis.\n"

            # Add CodeRabbit context if available
            if coderabbit_comments and self.config.use_coderabbit:
                prompt += "\n\n## CodeRabbit Analysis Results\n"
                prompt += "CodeRabbit has already reviewed this PR. Please consider their feedback and provide additional insights:\n\n"

                for i, comment in enumerate(coderabbit_comments[:5], 1):  # Limit to 5 most relevant
                    comment_text = comment.get('body', '').strip()
                    if comment_text:
                        file_info = ""
                        if comment.get('path'):
                            file_info = f" (in {comment['path']}"
                            if comment.get('line'):
                                file_info += f" line {comment['line']}"
                            file_info += ")"

                        prompt += f"{i}. CodeRabbit{file_info}: {comment_text}\n"

                prompt += "\nPlease:\n"
                prompt += "- Build upon CodeRabbit's analysis\n"
                prompt += "- Identify any issues CodeRabbit may have missed\n"
                prompt += "- Provide additional security, performance, or architectural insights\n"
                prompt += "- Avoid duplicating CodeRabbit's exact findings unless you have additional context\n"

            # Add comprehensive analysis instructions
            if github_ai_prompt or coderabbit_comments:
                prompt += "\n\n## Comprehensive Analysis Request\n"
                prompt += "Given the above context, please provide a thorough analysis that:\n"
                prompt += "- Addresses any specific issues mentioned in the GitHub AI prompt\n"
                prompt += "- Complements existing CodeRabbit feedback\n"
                prompt += "- Identifies patterns or architectural concerns\n"
                prompt += "- Suggests improvements for code maintainability and reliability\n"

            response = self.session.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": self.config.ai_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json"
                },
                json={
                    "model": self.config.ai_model,
                    "max_tokens": 1500,  # Increased for more comprehensive analysis
                    "messages": [{"role": "user", "content": prompt}]
                }
            )
            response.raise_for_status()

            result = response.json()
            analysis = result['content'][0]['text']

            # Parse analysis into review comments
            return self._parse_ai_analysis(analysis)

        except requests.exceptions.RequestException as e:
            raise APIError(f"Anthropic analysis failed: {e}") from e

    def _parse_ai_analysis(self, analysis: str) -> List[Dict[str, Any]]:
        """Parse AI analysis into structured review comments."""
        comments = []

        # Enhanced parsing - look for various types of issues
        lines = analysis.split('\n')
        current_comment = ""
        severity = "info"

        for line in lines:
            line = line.strip()
            if not line:
                if current_comment:
                    comments.append({
                        'body': current_comment.strip(),
                        'severity': severity,
                        'path': None,
                        'line': None
                    })
                    current_comment = ""
                    severity = "info"
                continue

            # Detect severity levels
            if any(word in line.lower() for word in ['critical', 'severe', 'security', 'vulnerability']):
                severity = "critical"
            elif any(word in line.lower() for word in ['error', 'bug', 'issue', 'problem']):
                severity = "error"
            elif any(word in line.lower() for word in ['warning', 'potential', 'consider']):
                severity = "warning"
            elif any(word in line.lower() for word in ['suggestion', 'improve', 'optimize']):
                severity = "suggestion"

            # Look for actionable feedback
            if any(keyword in line.lower() for keyword in [
                'issue', 'problem', 'bug', 'error', 'warning', 'critical',
                'security', 'vulnerability', 'consider', 'suggestion',
                'improve', 'optimize', 'refactor', 'performance'
            ]):
                if current_comment:
                    current_comment += " " + line
                else:
                    current_comment = line

        # Add final comment if exists
        if current_comment:
            comments.append({
                'body': current_comment.strip(),
                'severity': severity,
                'path': None,
                'line': None
            })

        return comments

    @retry_on_failure(max_retries=3, delay=1.0)
    def get_github_ai_prompt(self, repo: str, pr_number: str) -> str:
        """Extract GitHub's AI agent prompt from PR description or comments."""
        try:
            response = self.session.get(
                f"https://api.github.com/repos/{repo}/pulls/{pr_number}",
                headers={"Authorization": f"token {self.config.github_token}"},
                timeout=30
            )
            response.raise_for_status()
            pr_data = response.json()
            pr_body = pr_data.get('body', '')
            ai_prompt = self._extract_ai_prompt_from_text(pr_body)
            if not ai_prompt:
                response = self.session.get(
                    f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments",
                    headers={"Authorization": f"token {self.config.github_token}"},
                    timeout=30
                )
                response.raise_for_status()
                comments = response.json()
                for comment in comments:
                    comment_body = comment.get('body', '')
                    ai_prompt = self._extract_ai_prompt_from_text(comment_body)
                    if ai_prompt:
                        break
            if ai_prompt:
                logger.info(f"Found GitHub AI agent prompt ({len(ai_prompt)} chars)")
                return ai_prompt
            else:
                logger.info("No GitHub AI agent prompt found")
                return ""
        except requests.exceptions.RequestException as e:
            logger.warning(f"Failed to get GitHub AI prompt: {e}")
            return ""

    def _extract_ai_prompt_from_text(self, text: str) -> str:
        """Extract AI agent prompt from GitHub text."""
        if not text:
            return ""

        # Look for the AI agent prompt section
        ai_prompt_markers = [
            "🤖 Prompt for AI Agents",
            "Prompt for AI Agents",
            "🤖 **Prompt for AI Agents**",
            "## 🤖 Prompt for AI Agents",
            "### 🤖 Prompt for AI Agents"
        ]

        text_lower = text.lower()
        for marker in ai_prompt_markers:
            marker_lower = marker.lower()
            if marker_lower in text_lower:
                # Find the start of the AI prompt section
                start_idx = text_lower.find(marker_lower)
                if start_idx != -1:
                    # Extract from marker to end or next major section
                    prompt_start = start_idx + len(marker)
                    remaining_text = text[prompt_start:]

                    # Look for end markers (next section or end of text)
                    end_markers = ['\n##', '\n###', '\n---', '\n\n---']
                    end_idx = len(remaining_text)

                    for end_marker in end_markers:
                        marker_pos = remaining_text.find(end_marker)
                        if marker_pos != -1 and marker_pos < end_idx:
                            end_idx = marker_pos

                    ai_prompt = remaining_text[:end_idx].strip()
                    if ai_prompt:
                        return ai_prompt

        return ""

    @retry_on_failure(max_retries=3, delay=1.0)
    def get_coderabbit_comments(self, repo: str, pr_number: str) -> List[Dict[str, Any]]:
        """Get CodeRabbit comments from the PR."""
        try:
            response = self.session.get(
                f"https://api.github.com/repos/{repo}/pulls/{pr_number}/reviews",
                headers={"Authorization": f"token {self.config.github_token}"},
                timeout=30
            )
            response.raise_for_status()
            reviews = response.json()
            coderabbit_comments = []
            for review in reviews:
                user = review.get('user', {})
                if (user.get('login', '').lower() in ['coderabbitai', 'coderabbit'] or
                    user.get('type', '').lower() == 'bot' and 'coderabbit' in user.get('login', '').lower()):
                    coderabbit_comments.append({
                        'id': review['id'],
                        'body': review.get('body', ''),
                        'state': review.get('state', ''),
                        'submitted_at': review.get('submitted_at', ''),
                        'user': user.get('login', 'coderabbit')
                    })
            response = self.session.get(
                f"https://api.github.com/repos/{repo}/pulls/{pr_number}/comments",
                headers={"Authorization": f"token {self.config.github_token}"},
                timeout=30
            )
            response.raise_for_status()
            line_comments = response.json()
            for comment in line_comments:
                user = comment.get('user', {})
                if (user.get('login', '').lower() in ['coderabbitai', 'coderabbit'] or
                    user.get('type', '').lower() == 'bot' and 'coderabbit' in user.get('login', '').lower()):
                    coderabbit_comments.append({
                        'id': comment['id'],
                        'body': comment.get('body', ''),
                        'path': comment.get('path', ''),
                        'line': comment.get('line', ''),
                        'created_at': comment.get('created_at', ''),
                        'user': user.get('login', 'coderabbit'),
                        'type': 'line_comment'
                    })
            logger.info(f"Found {len(coderabbit_comments)} CodeRabbit comments")
            return coderabbit_comments
        except requests.exceptions.RequestException as e:
            logger.warning(f"Failed to get CodeRabbit comments: {e}")
            return []

    @retry_on_failure(max_retries=3, delay=1.0)
    def post_pr_review(self, repo: str, pr_number: str, comments: List[Dict[str, Any]]) -> None:
        """Post review comments to GitHub PR with clean, actionable output."""
        try:
            # Group comments by severity
            severity_groups = {
                'critical': [],
                'error': [],
                'warning': [],
                'suggestion': [],
                'info': []
            }
            for comment in comments:
                severity = comment.get('severity', 'info')
                body = comment.get('body', '').strip()
                # Only include non-empty, unique issues
                if body and body not in [c['body'] for c in severity_groups[severity]]:
                    severity_groups[severity].append(comment)

            # Build summary checklist
            summary = "## 🚦 PR Review Summary\n\n"
            summary += "**What to fix before merging:**\n"
            blocking = severity_groups['critical'] + severity_groups['error']
            if blocking:
                for c in blocking:
                    summary += f"- [ ] {c['body'].splitlines()[0]}\n"
            else:
                summary += "- [x] No blocking issues found!\n"
            summary += "\n**What to improve later:**\n"
            for c in severity_groups['warning'] + severity_groups['suggestion']:
                summary += f"- [ ] {c['body'].splitlines()[0]}\n"
            if not (severity_groups['warning'] or severity_groups['suggestion']):
                summary += "- [x] No suggestions or warnings!\n"

            # Build detailed issues section
            details = ""
            severity_icons = {
                'critical': '🚨',
                'error': '❌',
                'warning': '⚠️',
                'suggestion': '💡',
                'info': 'ℹ️'
            }
            for severity, group_comments in severity_groups.items():
                if group_comments:
                    icon = severity_icons.get(severity, 'ℹ️')
                    details += f"\n### {icon} {severity.title()} Issues\n"
                    for i, comment in enumerate(group_comments, 1):
                        body = comment['body'].strip()
                        suggestion = comment.get('suggestion', 'Please address as appropriate.')
                        details += f"\n**{i}. {body}**\n"
                        details += f"- **How to fix:** {suggestion}\n"

            # Build copy-paste instructions for the agent
            instructions = "---\n## 🤖 Copy-paste instructions for your agent\n\n"
            if blocking:
                instructions += "**Please address the following blocking issues before merging:**\n"
                for c in blocking:
                    instructions += f"- {c['body'].splitlines()[0]}\n"
            else:
                instructions += "No blocking issues. You may merge after reviewing suggestions.\n"
            if severity_groups['warning'] or severity_groups['suggestion']:
                instructions += "\n**Suggestions for improvement:**\n"
                for c in severity_groups['warning'] + severity_groups['suggestion']:
                    instructions += f"- {c['body'].splitlines()[0]}\n"

            # Compose the full review body
            review_body = summary + details + "\n" + instructions

            # Log the review body for debugging
            logger.info(f"Review body to be posted:\n{review_body}")

            # Always use 'COMMENT' for now to avoid 422 errors
            event = "COMMENT"

            response = self.session.post(
                f"https://api.github.com/repos/{repo}/pulls/{pr_number}/reviews",
                headers={"Authorization": f"token {self.config.github_token}"},
                json={
                    "body": review_body,
                    "event": event
                }
            )
            response.raise_for_status()
            logger.info(f"Review posted successfully with {len(comments)} comments (event: {event})")

        except requests.exceptions.RequestException as e:
            raise APIError(f"Failed to post review: {e}") from e

# YAML generation (not string templates)
def create_github_workflow(config: ReviewConfig) -> Dict[str, Any]:
    """Generate workflow using proper YAML structure."""
    env_key = "OPENAI_API_KEY" if config.ai_provider == "openai" else "ANTHROPIC_API_KEY"
    workflow = {
        'name': 'AI PR Review',
        'on': {
            'pull_request': {
                'types': ['opened', 'synchronize', 'reopened']
            }
        },
        'permissions': {
            'contents': 'read',
            'pull-requests': 'write'
        },
        'jobs': {
            'coderabbit-review': {
                'name': 'CodeRabbit Review',
                'runs-on': 'ubuntu-latest',
                'steps': [
                    {
                        'name': 'CodeRabbit Review',
                        'uses': 'coderabbitai/coderabbit-action@v2',
                        'with': {
                            'github-token': '${{ secrets.GITHUB_TOKEN }}'
                        }
                    }
                ]
            },
            'ai-review': {
                'name': 'Custom AI Code Review',
                'runs-on': 'ubuntu-latest',
                'needs': ['coderabbit-review'],
                'steps': [
                    {
                        'name': 'Checkout code',
                        'uses': 'actions/checkout@v4'
                    },
                    {
                        'name': 'Setup Python',
                        'uses': 'actions/setup-python@v4',
                        'with': {
                            'python-version': '3.11'
                        }
                    },
                    {
                        'name': 'Install dependencies',
                        'run': 'pip install requests pyyaml'
                    },
                    {
                        'name': 'Run AI Review',
                        'env': {
                            'GITHUB_TOKEN': '${{ secrets.GITHUB_TOKEN }}',
                            env_key: f'${{ secrets.{env_key} }}'
                        },
                        'run': f'python cursor_pr_review.py review-pr {config.repo} ${{{{ github.event.pull_request.number }}}}'
                    }
                ]
            }
        }
    }
    return workflow

def save_github_workflow(config: ReviewConfig) -> None:
    """Save workflow using proper YAML library."""
    workflow_dir = Path('.github/workflows')
    workflow_dir.mkdir(parents=True, exist_ok=True)
    
    workflow = create_github_workflow(config)
    workflow_file = workflow_dir / 'ai-review.yml'
    
    try:
        with open(workflow_file, 'w') as f:
            yaml.dump(workflow, f, default_flow_style=False, sort_keys=False)
        
        logger.info(f"GitHub workflow saved to {workflow_file}")
        
    except OSError as e:
        raise ConfigError(f"Failed to save workflow: {e}", "Check permissions")

# CodeRabbit integration
def create_coderabbit_config(config: ReviewConfig) -> Dict[str, Any]:
    """Generate CodeRabbit configuration using proper YAML structure."""
    coderabbit_config = {
        'version': 2,
        'reviews': {
            'request_changes_threshold': config.coderabbit_threshold,
            'approve_threshold': 'low',
            'auto_review': {
                'enabled': True,
                'drafts': False,
                'base_branches': ['main', 'master']
            },
            'auto_approve': {
                'enabled': config.coderabbit_auto_approve,
                'threshold': config.coderabbit_threshold
            },
            'path_filters': {
                'ignore': ['*.md', 'LICENSE', '*.txt']
            }
        },
        'model': {
            'provider': config.ai_provider,
            'name': config.ai_model
        }
    }
    
    # Add language-specific settings
    coderabbit_config['languages'] = {
        'python': {
            'reviewers': ['ai'],
            'threshold': config.coderabbit_threshold
        },
        'javascript': {
            'reviewers': ['ai'],
            'threshold': config.coderabbit_threshold
        }
    }
    
    return coderabbit_config

def save_coderabbit_config(config: ReviewConfig) -> None:
    """Save CodeRabbit configuration file."""
    coderabbit_config = create_coderabbit_config(config)
    
    try:
        with open('.coderabbit.yaml', 'w') as f:
            yaml.dump(coderabbit_config, f, default_flow_style=False, sort_keys=False)
        
        logger.info("CodeRabbit configuration saved to .coderabbit.yaml")
        
    except OSError as e:
        raise ConfigError(f"Failed to save CodeRabbit config: {e}", "Check permissions")

# Single-responsibility setup functions 
def prompt_github_token() -> str:
    """Get GitHub token from user."""
    token = input("GitHub token: ").strip()
    if not token:
        raise ConfigError("GitHub token required", "Get token at github.com/settings/tokens")
    return token

def prompt_ai_provider() -> str:
    """Get AI provider choice."""
    logger.info("Choose AI provider: 1) OpenAI  2) Anthropic")
    choice = input("Choice (1-2): ").strip()
    if choice == "1":
        return "openai"
    elif choice == "2":
        return "anthropic"
    else:
        raise ConfigError("Invalid choice", "Enter 1 or 2")

def prompt_ai_key(provider: str) -> str:
    """Get AI API key."""
    key = input(f"{provider.title()} API key: ").strip()
    if not key:
        raise ConfigError(f"{provider} key required", f"Get key from {provider} console")
    return key

def get_repository_name() -> str:
    """Get repository name from git or user input."""
    try:
        output = subprocess.check_output(['git', 'remote', 'get-url', 'origin'], text=True).strip()
        if 'github.com' in output:
            if output.startswith('git@'):
                repo = output.split(':')[1].replace('.git', '')
            else:
                repo = '/'.join(output.split('/')[-2:]).replace('.git', '')
            
            confirm = input(f"Repository '{repo}' (y/n): ").strip().lower()
            if confirm == 'y':
                return repo
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
    
    repo = input("Repository (owner/name): ").strip()
    if not repo:
        raise ConfigError("Repository required", "Enter format 'owner/name'")
    return repo

def choose_ai_model(client: APIClient) -> str:
    """Get available models and let user choose."""
    models_data = client.validate_ai_key()
    
    if client.config.ai_provider == 'openai':
        # Filter for modern text generation models, exclude legacy expensive and unwanted types
        excluded_keywords = [
            'audio', 'image', 'tts', 'realtime', 'whisper', 'dall-e', 'legacy', 'deprecated',
            'gpt-4-turbo', 'gpt-4-0', 'gpt-4-1106', 'gpt-4-0613', 'gpt-4-0314',  # Legacy GPT-4 variants
            'gpt-3.5-turbo', 'gpt-3.5', 'text-davinci', 'text-curie', 'text-babbage', 'text-ada'  # Legacy models
        ]
        models = []
        for m in models_data['data']:
            model_id = m['id'].lower()
            if 'gpt' in model_id:
                # Exclude models with unwanted keywords
                if not any(keyword in model_id for keyword in excluded_keywords):
                    models.append(m)

        models = sorted(models, key=lambda x: x.get('created', 0), reverse=True)[:5]
    else:
        models = models_data.get('data', [])[:5]
    
    logger.info("Available models:")
    for i, model in enumerate(models, 1):
        logger.info(f"{i}. {model['id']}")
    
    choice = input(f"Choice (1-{len(models)}): ").strip()
    try:
        idx = int(choice) - 1
        if 0 <= idx < len(models):
            return models[idx]['id']
    except ValueError:
        pass
    
    return models[0]['id']

def prompt_coderabbit_setup() -> tuple[str, bool]:
    """Setup CodeRabbit integration."""
    logger.info("CodeRabbit Configuration")
    
    threshold = input("CodeRabbit review threshold (low/medium/high) [medium]: ").strip().lower()
    if not threshold:
        threshold = "medium"
    
    if threshold not in ['low', 'medium', 'high']:
        raise ConfigError(f"Invalid threshold: {threshold}", "Use 'low', 'medium', or 'high'")
    
    auto_approve = input("Enable auto-approve for minor issues? (y/n) [n]: ").strip().lower() == 'y'
    
    return threshold, auto_approve

def prompt_review_settings() -> tuple[str, bool, str]:
    """Setup AI review strictness settings and prompt type."""
    logger.info("AI Review Configuration")

    strictness = input("Review strictness (strict/balanced/lenient) [balanced]: ").strip().lower()
    if not strictness:
        strictness = "balanced"

    if strictness not in ['strict', 'balanced', 'lenient']:
        raise ConfigError(f"Invalid strictness: {strictness}", "Use 'strict', 'balanced', or 'lenient'")

    auto_request = input("Auto-request changes for issues? (y/n) [y]: ").strip().lower()
    auto_request_changes = auto_request != 'n'

    # Prompt type selection
    logger.info("\nPrompt Template Selection:")
    available_prompts = get_available_prompts()
    for i, prompt in enumerate(available_prompts, 1):
        desc = {
            'default': 'Balanced review focusing on security, bugs, performance, and quality',
            'strict': 'Thorough analysis with zero tolerance for any issues',
            'lenient': 'Focus on critical issues only, practical and constructive',
            'security-focused': 'Comprehensive security-first analysis',
            'custom': 'Your personalized prompt template'
        }.get(prompt, 'User-defined prompt template')
        logger.info(f"  {i}. {prompt} - {desc}")
    
    choice = input(f"Choose prompt template (1-{len(available_prompts)}) [1]: ").strip()
    if not choice:
        choice = "1"
    
    try:
        idx = int(choice) - 1
        if 0 <= idx < len(available_prompts):
            prompt_type = available_prompts[idx]
        else:
            logger.warning("Invalid choice, using default")
            prompt_type = "default"
    except ValueError:
        logger.warning("Invalid choice, using default")
        prompt_type = "default"

    logger.info(f"Review strictness: {strictness}")
    logger.info(f"Auto-request changes: {'Yes' if auto_request_changes else 'No'}")
    logger.info(f"Prompt template: {prompt_type}")

    return strictness, auto_request_changes, prompt_type

def self_improve_from_own_prs(config: ReviewConfig) -> None:
    """Analyze our own PRs to extract improvement insights."""
    logger.info("🔄 Starting self-improvement analysis from own PRs")

    try:
        client = APIClient(config)

        # Get recent PRs from our own repository
        response = client.session.get(
            f"https://api.github.com/repos/{config.repo}/pulls",
            headers={"Authorization": f"token {config.github_token}"},
            params={"state": "all", "per_page": 10, "sort": "updated"},
            timeout=30
        )
        response.raise_for_status()
        prs = response.json()

        logger.info(f"Found {len(prs)} recent PRs to analyze for improvement insights")

        improvement_insights = []

        for pr in prs[:5]:  # Analyze last 5 PRs
            pr_number = pr['number']
            logger.info(f"Analyzing PR #{pr_number}: {pr['title']}")

            # Get GitHub AI prompt
            github_ai_prompt = client.get_github_ai_prompt(config.repo, str(pr_number))

            # Get CodeRabbit comments
            coderabbit_comments = client.get_coderabbit_comments(config.repo, str(pr_number))

            # Load the appropriate prompt template
            if not config.prompt_template:
                config.prompt_template = load_prompt_template(config.prompt_type)
            
            # Get our own AI review comments
            our_reviews = []
            try:
                response = client.session.get(
                    f"https://api.github.com/repos/{config.repo}/pulls/{pr_number}/reviews",
                    headers={"Authorization": f"token {config.github_token}"},
                    timeout=30
                )
                response.raise_for_status()
                reviews = response.json()

                for review in reviews:
                    if "🤖 **AI Code Review Results**" in review.get('body', ''):
                        our_reviews.append(review['body'])
            except Exception:
                pass

            # Compile insights
            if github_ai_prompt or coderabbit_comments or our_reviews:
                insight = {
                    'pr_number': pr_number,
                    'title': pr['title'],
                    'github_ai_prompt': github_ai_prompt,
                    'coderabbit_count': len(coderabbit_comments),
                    'our_review_count': len(our_reviews),
                    'patterns': []
                }

                # Extract patterns from GitHub AI prompts
                if github_ai_prompt:
                    insight['patterns'].append(f"GitHub AI identified: {github_ai_prompt[:100]}...")

                # Extract patterns from CodeRabbit
                if coderabbit_comments:
                    common_issues = {}
                    for comment in coderabbit_comments:
                        body = comment.get('body', '').lower()
                        if 'security' in body:
                            common_issues['security'] = common_issues.get('security', 0) + 1
                        if 'performance' in body:
                            common_issues['performance'] = common_issues.get('performance', 0) + 1
                        if 'error handling' in body:
                            common_issues['error_handling'] = common_issues.get('error_handling', 0) + 1

                    for issue_type, count in common_issues.items():
                        insight['patterns'].append(f"CodeRabbit found {count} {issue_type} issues")

                improvement_insights.append(insight)

        # Generate improvement recommendations
        logger.info("🎯 Generating improvement recommendations...")

        all_patterns = []
        for insight in improvement_insights:
            all_patterns.extend(insight['patterns'])

        # Analyze patterns with AI
        if all_patterns:
            pattern_analysis = "\n".join(all_patterns)
            improvement_prompt = f"""
            Based on the following patterns from our recent PRs and reviews, provide ACTIONABLE improvements to our AI code review tool.

            PATTERNS FOUND:
            {pattern_analysis}

            Please provide your response in this EXACT format:

            ## IMMEDIATE ACTIONABLE IMPROVEMENTS

            ### 1. PROMPT ENHANCEMENTS
            [Specific text to add to our AI prompts, ready to copy-paste]

            ### 2. DETECTION IMPROVEMENTS
            [Specific issues to add to our detection logic, with examples]

            ### 3. INTEGRATION FIXES
            [Specific changes to reduce duplication between GitHub AI, CodeRabbit, and our analysis]

            ## IMPLEMENTATION INSTRUCTIONS

            ### FOR DEVELOPERS:
            [Step-by-step instructions to implement these improvements]

            ### FOR GPT PROMPTS:
            [Exact prompt text improvements to copy into our code]

            Focus on SPECIFIC, IMPLEMENTABLE changes, not general suggestions.
            """

            recommendations = client.analyze_code_with_ai("", improvement_prompt)

            # Format output in a user-friendly way
            print("\n" + "="*80)
            print("🔄 SELF-IMPROVEMENT ANALYSIS RESULTS")
            print("="*80)

            print(f"\n🎯 ANALYSIS SUMMARY:")
            print(f"   • PRs analyzed: {len(improvement_insights)}")
            print(f"   • Patterns found: {len(all_patterns)}")
            print(f"   • Recommendations generated: {len(recommendations)}")

            print(f"\n🎯 ACTIONABLE RECOMMENDATIONS:")
            print("-"*80)

            for rec in recommendations:
                recommendation_text = rec.get('body', '')
                if recommendation_text:
                    # Clean up the recommendation text
                    lines = recommendation_text.split('\n')
                    for line in lines:
                        if line.strip():
                            print(line)

            print("\n" + "="*80)
            print("💡 NEXT STEPS:")
            print("1. Review the prompt enhancements above")
            print("2. Copy-paste the improved prompts into cursor_pr_review.py")
            print("3. Implement the detection improvements")
            print("4. Test with a new PR review")
            print("5. Run self-improve again to measure improvement")
            print("="*80)

        else:
            print("\n📊 No patterns found in recent PRs to analyze.")
            print("💡 Try creating more PRs with GitHub AI prompts and CodeRabbit reviews.")

        logger.info("✅ Self-improvement analysis complete!")

    except Exception as e:
        logger.error(f"Self-improvement analysis failed: {e}", exc_info=True)
        raise

def review_pr(config: ReviewConfig, repo: str, pr_number: str) -> None:
    """Review a specific PR using AI, incorporating CodeRabbit feedback."""
    logger.info(f"Starting AI review for PR #{pr_number} in {repo}")

    try:
        # Initialize API client
        client = APIClient(config)

        # Get PR details from GitHub
        pr_data = client.get_pr_details(repo, pr_number)
        logger.info(f"Reviewing PR: {pr_data['title']}")

        # Get PR diff
        pr_diff = client.get_pr_diff(repo, pr_number)

        # Get GitHub AI agent prompt
        logger.info("Fetching GitHub AI agent prompt...")
        github_ai_prompt = client.get_github_ai_prompt(repo, pr_number)

        # Get CodeRabbit comments if enabled
        coderabbit_comments = []
        if config.use_coderabbit:
            logger.info("Fetching CodeRabbit comments...")
            coderabbit_comments = client.get_coderabbit_comments(repo, pr_number)
            if coderabbit_comments:
                logger.info(f"Found {len(coderabbit_comments)} CodeRabbit comments to incorporate")
            else:
                logger.info("No CodeRabbit comments found - proceeding with standalone AI analysis")

        # Analyze with AI, incorporating all available context
        client._last_coderabbit_count = len(coderabbit_comments)  # Track for review posting
        client._last_github_ai_prompt = bool(github_ai_prompt)  # Track for review posting
        review_comments = client.analyze_code_with_ai(pr_diff, config.prompt_template, coderabbit_comments, github_ai_prompt)

        # Post review comments
        if review_comments:
            client.post_pr_review(repo, pr_number, review_comments)
            logger.info(f"Posted {len(review_comments)} review comments")
            if coderabbit_comments:
                logger.info("Review incorporates CodeRabbit analysis for comprehensive coverage")
        else:
            logger.info("No additional issues found beyond CodeRabbit analysis - PR looks good!")

    except Exception as e:
        logger.error(f"PR review failed: {e}", exc_info=True)
        raise

def setup() -> None:
    """Complete setup using single-responsibility functions."""
    logger.info("Starting Cursor PR Review setup")
    
    try:
        # Gather all configuration
        github_token = prompt_github_token()
        ai_provider = prompt_ai_provider()
        ai_key = prompt_ai_key(ai_provider)
        repo = get_repository_name()
        
        # CodeRabbit is now integrated properly
        coderabbit_threshold, coderabbit_auto_approve = prompt_coderabbit_setup()

        # AI Review settings
        review_strictness, auto_request_changes, prompt_type = prompt_review_settings()

        # Create and validate config
        config = ReviewConfig(
            github_token=github_token,
            ai_provider=ai_provider,
            ai_key=ai_key,
            ai_model="",  # Will be set below
            repo=repo,
            use_coderabbit=True,
            coderabbit_threshold=coderabbit_threshold,
            coderabbit_auto_approve=coderabbit_auto_approve,
            review_strictness=review_strictness,
            auto_request_changes=auto_request_changes,
            prompt_type=prompt_type
        )
        
        # Validate tokens and get model
        client = APIClient(config)
        client.validate_github_token()
        config.ai_model = choose_ai_model(client)
        
        # Save everything
        save_config(config)
        save_github_workflow(config)
        save_coderabbit_config(config)
        
        logger.info("Setup completed successfully")
        
    except KeyboardInterrupt:
        logger.info("Setup cancelled")
        raise
    except (ConfigError, APIError, SecurityError):
        raise
    except Exception as e:
        logger.error(f"Setup failed: {e}", exc_info=True)
        raise ConfigError(f"Setup error: {e}", "Check logs for details")

def main():
    """Main entry point with complete error handling."""
    try:
        if len(sys.argv) == 1:
            # Use logger, NOT print
            logger.info("Cursor PR Review - Production Ready")
            logger.info("Usage:")
            logger.info("  python cursor_pr_review.py setup")
            logger.info("  python cursor_pr_review.py review-pr owner/repo 123")
            logger.info("  python cursor_pr_review.py list-prompts")
            logger.info("  python cursor_pr_review.py view-prompt <name>")
            logger.info("  python cursor_pr_review.py edit-prompt [custom]")
            logger.info("  python cursor_pr_review.py self-improve")
            logger.info("")
            logger.info("Advanced Prompt Management:")
            logger.info("  python cursor_pr_review.py prompt list [--type TYPE] [--language LANG]")
            logger.info("  python cursor_pr_review.py prompt view <id> [version]")
            logger.info("  python cursor_pr_review.py prompt create")
            logger.info("  python cursor_pr_review.py prompt edit <id>")
            logger.info("  python cursor_pr_review.py prompt delete <id>")
            logger.info("  python cursor_pr_review.py prompt history <id>")
            logger.info("  python cursor_pr_review.py prompt rollback <id> <version>")
            logger.info("  python cursor_pr_review.py prompt diff <id> <v1> <v2>")
            logger.info("  python cursor_pr_review.py prompt set-default <type> <lang> <id>")
            return
        
        command = sys.argv[1]
        
        if command == "setup":
            setup()
        elif command == "review-pr":
            if len(sys.argv) < 4:
                raise ConfigError("Usage: review-pr owner/repo PR_NUMBER")

            repo = sys.argv[2]
            pr_number = sys.argv[3]

            # Load configuration
            config = load_config()
            if not config:
                raise ConfigError("No configuration found", "Run setup first")

            # Perform PR review
            review_pr(config, repo, pr_number)

        elif command == "self-improve":
            # Analyze our own repository for self-improvement
            config = load_config()
            if not config:
                raise ConfigError("No configuration found", "Run setup first")

            self_improve_from_own_prs(config)
        elif command == "list-prompts":
            list_prompts()
        elif command == "view-prompt":
            if len(sys.argv) < 3:
                raise ConfigError("Usage: view-prompt <prompt-name>")
            view_prompt(sys.argv[2])
        elif command == "edit-prompt":
            if len(sys.argv) < 3:
                # Interactive mode
                edit_prompt_interactive()
            else:
                prompt_name = sys.argv[2]
                if prompt_name == 'custom':
                    edit_prompt_interactive()
                else:
                    raise ConfigError(f"Cannot edit built-in prompt '{prompt_name}'", "Use 'edit-prompt custom' or 'edit-prompt' for interactive mode")
        
        # Advanced prompt management commands
        elif command == "prompt":
            if not PROMPT_MANAGER_AVAILABLE:
                raise ConfigError("Advanced prompt management not available", "Check prompt_manager.py and prompt_cli.py")
            
            if len(sys.argv) < 3:
                raise ConfigError("Usage: prompt <subcommand> [args...]")
            
            subcommand = sys.argv[2]
            cli = PromptCLI()
            
            if subcommand == "list":
                # prompt list [--type TYPE] [--language LANG] [--include-inactive]
                prompt_type = None
                language = None
                include_inactive = False
                
                i = 3
                while i < len(sys.argv):
                    if sys.argv[i] == "--type" and i + 1 < len(sys.argv):
                        prompt_type = sys.argv[i + 1]
                        i += 2
                    elif sys.argv[i] == "--language" and i + 1 < len(sys.argv):
                        language = sys.argv[i + 1]
                        i += 2
                    elif sys.argv[i] == "--include-inactive":
                        include_inactive = True
                        i += 1
                    else:
                        i += 1
                
                cli.list_prompts(prompt_type, language, include_inactive)
            
            elif subcommand == "view":
                if len(sys.argv) < 4:
                    raise ConfigError("Usage: prompt view <id> [version]")
                prompt_id = sys.argv[3]
                version = int(sys.argv[4]) if len(sys.argv) > 4 else None
                cli.view_prompt(prompt_id, version)
            
            elif subcommand == "create":
                cli.create_prompt()
            
            elif subcommand == "edit":
                if len(sys.argv) < 4:
                    raise ConfigError("Usage: prompt edit <id>")
                prompt_id = sys.argv[3]
                cli.edit_prompt(prompt_id)
            
            elif subcommand == "delete":
                if len(sys.argv) < 4:
                    raise ConfigError("Usage: prompt delete <id>")
                prompt_id = sys.argv[3]
                cli.delete_prompt(prompt_id)
            
            elif subcommand == "history":
                if len(sys.argv) < 4:
                    raise ConfigError("Usage: prompt history <id>")
                prompt_id = sys.argv[3]
                cli.show_history(prompt_id)
            
            elif subcommand == "rollback":
                if len(sys.argv) < 5:
                    raise ConfigError("Usage: prompt rollback <id> <version>")
                prompt_id = sys.argv[3]
                version = int(sys.argv[4])
                cli.rollback_prompt(prompt_id, version)
            
            elif subcommand == "diff":
                if len(sys.argv) < 6:
                    raise ConfigError("Usage: prompt diff <id> <version1> <version2>")
                prompt_id = sys.argv[3]
                version1 = int(sys.argv[4])
                version2 = int(sys.argv[5])
                cli.show_diff(prompt_id, version1, version2)
            
            elif subcommand == "set-default":
                if len(sys.argv) < 6:
                    raise ConfigError("Usage: prompt set-default <type> <language> <id>")
                prompt_type = sys.argv[3]
                language = sys.argv[4]
                prompt_id = sys.argv[5]
                cli.set_default(prompt_type, language, prompt_id)
            
            else:
                raise ConfigError(f"Unknown prompt subcommand: {subcommand}", 
                    "Use: list, view, create, edit, delete, history, rollback, diff, set-default")
        
        else:
            raise ConfigError(f"Unknown command: {command}", "Use 'setup', 'review-pr', 'list-prompts', 'view-prompt', 'edit-prompt', or 'prompt'")
    
    except KeyboardInterrupt:
        logger.info("Interrupted")
        sys.exit(130)
    except (ConfigError, APIError, SecurityError) as e:
        logger.error(str(e))
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()
