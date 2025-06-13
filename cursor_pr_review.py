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
            raise last_exception
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
    prompt_template: str = """Please review this code diff carefully and provide detailed feedback. Focus on:

1. **Security Issues**: Look for potential vulnerabilities, unsafe operations, or security anti-patterns
2. **Bugs & Logic Errors**: Identify potential runtime errors, logic flaws, or edge cases
3. **Performance Issues**: Spot inefficient algorithms, memory leaks, or performance bottlenecks
4. **Code Quality**: Check for maintainability, readability, and adherence to best practices
5. **Testing**: Suggest areas that need better test coverage

For each issue found, please:
- Clearly describe the problem
- Explain the potential impact
- Suggest a specific solution or improvement
- Indicate the severity level (critical/error/warning/suggestion)

If no significant issues are found, provide positive feedback and any minor suggestions for improvement."""
    
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
                headers={"Authorization": f"Bearer {self.config.ai_key}"}
            )
            response.raise_for_status()
            return response.json()
            
        except requests.exceptions.HTTPError as e:
            if e.response and e.response.status_code == 401:
                raise APIError(
                    "Invalid OpenAI API key",
                    "Get a key at https://platform.openai.com/api-keys"
                )
            raise APIError(f"OpenAI API error: {e}") from e
    
    def _validate_anthropic(self) -> Dict[str, Any]:
        """Validate Anthropic API key."""
        try:
            response = self.session.get(
                "https://api.anthropic.com/v1/models",
                headers={
                    "x-api-key": self.config.ai_key,
                    "anthropic-version": "2023-06-01"
                }
            )
            response.raise_for_status()
            return response.json()
            
        except requests.exceptions.HTTPError as e:
            if e.response and e.response.status_code == 401:
                raise APIError(
                    "Invalid Anthropic API key", 
                    "Get a key at https://console.anthropic.com"
                )
            raise APIError(f"Anthropic API error: {e}") from e

    @retry_on_failure(max_retries=3, delay=1.0)
    def get_pr_details(self, repo: str, pr_number: str) -> Dict[str, Any]:
        """Get PR details from GitHub API."""
        try:
            response = self.session.get(
                f"https://api.github.com/repos/{repo}/pulls/{pr_number}",
                headers={"Authorization": f"token {self.config.github_token}"}
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
                }
            )
            response.raise_for_status()
            return response.text

        except requests.exceptions.RequestException as e:
            raise APIError(f"Failed to get PR diff: {e}") from e

    def analyze_code_with_ai(self, diff: str, prompt_template: str, coderabbit_comments: List[Dict[str, Any]] = None, github_ai_prompt: str = None) -> List[Dict[str, Any]]:
        """Analyze code diff using AI and return review comments, incorporating all available context."""
        if self.config.ai_provider == 'openai':
            return self._analyze_with_openai(diff, prompt_template, coderabbit_comments, github_ai_prompt)
        elif self.config.ai_provider == 'anthropic':
            return self._analyze_with_anthropic(diff, prompt_template, coderabbit_comments, github_ai_prompt)
        else:
            raise ConfigError(f"Unknown AI provider: {self.config.ai_provider}")

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
            # Get PR details to check description
            response = self.session.get(
                f"https://api.github.com/repos/{repo}/pulls/{pr_number}",
                headers={"Authorization": f"token {self.config.github_token}"}
            )
            response.raise_for_status()
            pr_data = response.json()

            # Look for AI prompt in PR description
            pr_body = pr_data.get('body', '')
            ai_prompt = self._extract_ai_prompt_from_text(pr_body)

            if not ai_prompt:
                # Check PR comments for AI prompts
                response = self.session.get(
                    f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments",
                    headers={"Authorization": f"token {self.config.github_token}"}
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
            # Get all review comments on the PR
            response = self.session.get(
                f"https://api.github.com/repos/{repo}/pulls/{pr_number}/reviews",
                headers={"Authorization": f"token {self.config.github_token}"}
            )
            response.raise_for_status()
            reviews = response.json()

            # Filter for CodeRabbit reviews
            coderabbit_comments = []
            for review in reviews:
                user = review.get('user', {})
                # CodeRabbit typically uses 'coderabbitai' as username or has 'bot' in the type
                if (user.get('login', '').lower() in ['coderabbitai', 'coderabbit'] or
                    user.get('type', '').lower() == 'bot' and 'coderabbit' in user.get('login', '').lower()):

                    coderabbit_comments.append({
                        'id': review['id'],
                        'body': review.get('body', ''),
                        'state': review.get('state', ''),
                        'submitted_at': review.get('submitted_at', ''),
                        'user': user.get('login', 'coderabbit')
                    })

            # Also get individual review comments (line-specific comments)
            response = self.session.get(
                f"https://api.github.com/repos/{repo}/pulls/{pr_number}/comments",
                headers={"Authorization": f"token {self.config.github_token}"}
            )
            response.raise_for_status()
            line_comments = response.json()

            # Filter line comments from CodeRabbit
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
            return []  # Continue without CodeRabbit comments if fetch fails

    @retry_on_failure(max_retries=3, delay=1.0)
    def post_pr_review(self, repo: str, pr_number: str, comments: List[Dict[str, Any]]) -> None:
        """Post review comments to GitHub PR."""
        try:
            # Create a structured review comment with severity levels
            review_body = "🤖 **AI Code Review Results**\n\n"

            # Add integration notes if applicable
            integration_notes = []
            if hasattr(self, '_last_github_ai_prompt') and self._last_github_ai_prompt:
                integration_notes.append("GitHub AI agent prompt")
            if hasattr(self, '_last_coderabbit_count') and self._last_coderabbit_count > 0:
                integration_notes.append(f"{self._last_coderabbit_count} CodeRabbit comments")

            if integration_notes:
                review_body += f"*This analysis incorporates and builds upon: {', '.join(integration_notes)} for comprehensive coverage.*\n\n"

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
                severity_groups[severity].append(comment)

            # Add severity sections
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
                    review_body += f"\n## {icon} {severity.title()} Issues\n\n"
                    for i, comment in enumerate(group_comments, 1):
                        review_body += f"{i}. {comment['body']}\n"

            # Determine review event based on severity and configuration
            has_critical = bool(severity_groups['critical'])
            has_errors = bool(severity_groups['error'])
            has_warnings = bool(severity_groups['warning'])

            # Apply strictness settings
            should_request_changes = False
            if self.config.auto_request_changes:
                if self.config.review_strictness == "strict":
                    should_request_changes = has_critical or has_errors or has_warnings
                elif self.config.review_strictness == "balanced":
                    should_request_changes = has_critical or has_errors
                elif self.config.review_strictness == "lenient":
                    should_request_changes = has_critical

            if should_request_changes:
                event = "REQUEST_CHANGES"
                review_body += "\n---\n⚠️ **This PR has issues that should be addressed before merging.**"
            else:
                event = "COMMENT"
                if has_critical or has_errors:
                    review_body += "\n---\n⚠️ **Issues found but not blocking merge based on current settings.**"
                else:
                    review_body += "\n---\n✅ **No critical issues found. Consider addressing suggestions for code quality.**"

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
    
    # Proper YAML structure - no string templates
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
                'needs': ['coderabbit-review'],  # Run after CodeRabbit completes
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
                            env_key: f'${{{{ secrets.{env_key} }}}}'
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
            'request_changes_threshold': 'medium',
            'approve_threshold': 'low',
            'auto_review': {
                'enabled': True,
                'drafts': False,
                'base_branches': ['main', 'master']
            },
            'auto_approve': {
                'enabled': False,
                'threshold': 'low'
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
            'threshold': 'medium'
        },
        'javascript': {
            'reviewers': ['ai'],
            'threshold': 'medium'
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
        models = [m for m in models_data['data'] if 'gpt' in m['id'].lower()]
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

def prompt_review_settings() -> tuple[str, bool]:
    """Setup AI review strictness settings."""
    logger.info("AI Review Configuration")

    strictness = input("Review strictness (strict/balanced/lenient) [balanced]: ").strip().lower()
    if not strictness:
        strictness = "balanced"

    if strictness not in ['strict', 'balanced', 'lenient']:
        raise ConfigError(f"Invalid strictness: {strictness}", "Use 'strict', 'balanced', or 'lenient'")

    auto_request = input("Auto-request changes for issues? (y/n) [y]: ").strip().lower()
    auto_request_changes = auto_request != 'n'

    logger.info(f"Review strictness: {strictness}")
    logger.info(f"Auto-request changes: {'Yes' if auto_request_changes else 'No'}")

    return strictness, auto_request_changes

def self_improve_from_own_prs(config: ReviewConfig) -> None:
    """Analyze our own PRs to extract improvement insights."""
    logger.info("🔄 Starting self-improvement analysis from own PRs")

    try:
        client = APIClient(config)

        # Get recent PRs from our own repository
        response = client.session.get(
            f"https://api.github.com/repos/{config.repo}/pulls",
            headers={"Authorization": f"token {config.github_token}"},
            params={"state": "all", "per_page": 10, "sort": "updated"}
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

            # Get our own AI review comments
            our_reviews = []
            try:
                response = client.session.get(
                    f"https://api.github.com/repos/{config.repo}/pulls/{pr_number}/reviews",
                    headers={"Authorization": f"token {config.github_token}"}
                )
                response.raise_for_status()
                reviews = response.json()

                for review in reviews:
                    if "🤖 **AI Code Review Results**" in review.get('body', ''):
                        our_reviews.append(review['body'])
            except:
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
            Based on the following patterns from our recent PRs and reviews, suggest specific improvements to our AI code review tool:

            {pattern_analysis}

            Please provide:
            1. Common issues that our tool should better detect
            2. Improvements to our prompts or analysis logic
            3. New features that would address recurring problems
            4. Better integration opportunities with GitHub/CodeRabbit
            """

            recommendations = client.analyze_code_with_ai("", improvement_prompt)

            logger.info("📋 Self-Improvement Recommendations:")
            for i, rec in enumerate(recommendations, 1):
                logger.info(f"{i}. {rec.get('body', '')}")

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
        review_strictness, auto_request_changes = prompt_review_settings()

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
            auto_request_changes=auto_request_changes
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
            logger.info("Cursor PR Review - Finally Production Ready")
            logger.info("Usage:")
            logger.info("  python cursor_pr_review_final.py setup")
            logger.info("  python cursor_pr_review_final.py review-pr owner/repo 123")
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
        else:
            raise ConfigError(f"Unknown command: {command}", "Use 'setup' or 'review-pr'")
    
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
