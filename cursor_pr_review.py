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
import re
from pathlib import Path
from typing import Dict, Any, Optional, List, Union, Tuple
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

# Import enhanced issue analysis system
try:
    from issue_analyzer import EnhancedReviewAnalyzer, Issue, IssueCategory, IssueSeverity, IssueLocation
    ENHANCED_ANALYSIS_AVAILABLE = True
except ImportError:
    ENHANCED_ANALYSIS_AVAILABLE = False

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

# Log import availability
if not PROMPT_MANAGER_AVAILABLE:
    logger.debug("Advanced prompt management not available")
if not ENHANCED_ANALYSIS_AVAILABLE:
    logger.debug("Enhanced issue analysis not available")

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
    built_in_prompts = ['default', 'strict', 'lenient', 'security-focused', 'brutal']
    
    prompts_dir = Path('prompts')
    if not prompts_dir.exists():
        return built_in_prompts + ['custom']
    
    prompt_files = list(prompts_dir.glob('*.txt'))
    file_prompts = [f.stem for f in prompt_files]
    
    # Combine built-in and file-based prompts, avoiding duplicates
    all_prompts = built_in_prompts.copy()
    for fp in file_prompts:
        if fp not in all_prompts:
            all_prompts.append(fp)
    
    all_prompts.append('custom')
    return all_prompts

def load_prompt_template(prompt_name: str) -> str:
    """Load prompt template from file or advanced prompt manager."""
    # Handle built-in prompts directly
    if prompt_name == 'default':
        return get_default_prompt()
    elif prompt_name == 'strict':
        return get_strict_prompt()
    elif prompt_name == 'lenient':
        return get_lenient_prompt()
    elif prompt_name == 'security-focused':
        return get_security_focused_prompt()
    elif prompt_name == 'brutal':
        return get_brutal_prompt()
    
    # Try advanced prompt manager for custom prompts
    if PROMPT_MANAGER_AVAILABLE:
        try:
            manager = PromptManager()
            prompt_metadata = manager.get_prompt(prompt_name)
            if prompt_metadata and prompt_metadata.is_active:
                content = prompt_metadata.get_current_content()
                if content:  # Only return if we got actual content
                    return content
        except (AttributeError, KeyError, ValueError, OSError) as e:
            logger.debug(f"Prompt manager lookup failed (will use fallback): {e}")
    
    # Fallback to file system
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
    
    # Try loading from prompts directory
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
    return """You are an expert code reviewer. Review code for security vulnerabilities, ensuring OWASP Top 10 compliance. Identify and explicitly describe ALL error-handling paths, including edge cases. Analyze code for potential performance bottlenecks with specific metrics. Avoid duplicating issues already flagged by CodeRabbit, GitHub AI, or other tools - instead reference and build upon them. List distinct issues only once per category in your summary.

## CRITICAL INSTRUCTIONS
1. **ENSURE OWASP TOP 10 COMPLIANCE** - Every security finding must map to OWASP categories
2. **IDENTIFY ALL ERROR PATHS** - Explicitly trace and describe every error-handling scenario
3. **PERFORMANCE ANALYSIS** - Quantify bottlenecks (e.g., O(n²) complexity, unnecessary I/O)
4. **NO DUPLICATES** - If CodeRabbit/GitHub AI found it, reference don't repeat
5. **UNIQUE ISSUES ONLY** - Each issue appears exactly once in the summary

## 1. SECURITY VULNERABILITIES (OWASP Top 10 Compliance)
Review for security vulnerabilities, ENSURING every finding maps to OWASP Top 10:
- **A01: Broken Access Control** - Authorization bypass, privilege escalation, path traversal
- **A02: Cryptographic Failures** - Weak encryption, exposed sensitive data, insecure random
- **A03: Injection** - SQL, NoSQL, OS command, LDAP, XPath, XML injection
- **A04: Insecure Design** - Missing security controls, threat modeling gaps, unsafe patterns
- **A05: Security Misconfiguration** - Default configs, verbose errors, missing headers
- **A06: Vulnerable Components** - Outdated libraries, known CVEs, unpatched dependencies
- **A07: Authentication Failures** - Weak passwords, session fixation, timing attacks
- **A08: Software Integrity Failures** - Unsigned code, insecure deserialization, CI/CD risks
- **A09: Logging/Monitoring Failures** - Missing audit logs, PII in logs, inadequate alerting
- **A10: Server-Side Request Forgery** - SSRF, DNS rebinding, internal network access

Additional security checks:
- Input validation flaws (length, type, format, range)
- Hardcoded secrets, API keys, passwords
- Unsafe functions (eval, exec, pickle, yaml.load)
- Race conditions and TOCTOU vulnerabilities
- Cryptographic weaknesses (weak algorithms, bad randomness)

For each security issue provide:
- **OWASP Category**: Which OWASP Top 10 item (REQUIRED)
- **Location**: Exact file:line (e.g., auth.py:42)
- **Vulnerability**: Specific security flaw
- **Attack Vector**: How it could be exploited
- **Impact**: Damage if exploited (data breach, privilege escalation, etc.)
- **Remediation**: Exact code fix or mitigation
- **Severity**: CRITICAL/HIGH/MEDIUM/LOW
- **Detection Source**: [OurAnalysis] or [CodeRabbit+OurAnalysis] etc.

## 2. ERROR HANDLING ANALYSIS (All Paths)
Identify and EXPLICITLY DESCRIBE every error-handling path:
- Uncaught exceptions and error propagation chains
- Bare except clauses (except: without specific exception)
- Silent failures (except: pass/continue without logging)
- Missing error handling for external calls (API, DB, file I/O)
- Incomplete error recovery (partial state changes)
- Error information disclosure (stack traces to users)
- Missing input validation before processing

For each error-handling issue:
- **Error Path**: Trace the complete error flow (function A → B → C)
- **Location**: File:line where error handling is missing/inadequate
- **Scenario**: What triggers this error path
- **Current Behavior**: What happens now (crash, silent fail, corruption)
- **Risk**: Impact of unhandled error (data loss, security, UX)
- **Fix**: Specific error handling code to add
- **Severity**: HIGH/MEDIUM/LOW
- **Detection Source**: [OurAnalysis] or reference existing finding

## 3. PERFORMANCE BOTTLENECKS (With Metrics)
Analyze code for performance issues with SPECIFIC METRICS:
- Algorithm complexity (specify Big-O notation)
- Database queries in loops (N+1 problems)
- Unnecessary I/O operations (file reads, network calls)
- Memory leaks and excessive allocations
- Blocking operations in async code
- Inefficient data structures
- Missing caching opportunities

For each performance issue:
- **Bottleneck Type**: Category of performance issue
- **Location**: File:line with the issue
- **Current Performance**: Estimated complexity/impact (e.g., O(n²), 1000 DB queries)
- **Optimal Performance**: What it should be (e.g., O(n log n), 1 query)
- **Impact**: User-facing latency, resource usage
- **Solution**: Specific optimization with code
- **Severity**: HIGH/MEDIUM/LOW based on impact
- **Detection Source**: [OurAnalysis] or reference

## 4. OTHER CODE QUALITY ISSUES
Additional concerns not covered above:
- Code maintainability and readability
- Missing or inadequate test coverage
- Architectural anti-patterns
- Documentation gaps
- Dead code and unused imports

## DEDUPLICATION RULES
**CRITICAL**: Avoid duplicating findings from other tools:
1. If CodeRabbit/GitHub AI already found the issue:
   - Write: "CodeRabbit identified [issue] at [location]. Additionally, ..."
   - Add ONLY new insights or context
2. If multiple tools found the same issue:
   - Write: "Multiple tools detected [issue]: CodeRabbit (security), GitHub AI (performance)"
   - Consolidate into single entry
3. Track all sources: [CodeRabbit], [GitHubAI], [OurAnalysis], [Multiple]

## SUMMARY REQUIREMENTS
**MANDATORY**: In your final summary:
1. List each UNIQUE issue exactly ONCE
2. Group by category (Security, Error Handling, Performance, Other)
3. Include detection source for each: "Issue X [CodeRabbit+OurAnalysis]"
4. Count total UNIQUE issues (not counting duplicates)
5. Highlight gaps: "Found X issues missed by other tools"

## OUTPUT FORMAT
Structure your response as:

### 🔒 Security Issues (X unique issues)
[List each unique security issue with OWASP category]

### ⚠️ Error Handling Issues (X unique issues)  
[List each unique error handling issue with error paths]

### 🚀 Performance Issues (X unique issues)
[List each unique performance issue with metrics]

### 📋 Other Issues (X unique issues)
[List other issues]

### 📊 Analysis Summary
- Total unique issues: X
- By tool: OurAnalysis (X), CodeRabbit overlap (X), GitHub AI overlap (X)
- Critical gaps: [Issues only we found]

If no issues in a category: "✅ No [category] issues detected"
"""

def get_strict_prompt() -> str:
    """Get strict review prompt - zero tolerance for any issues."""
    return """You are an uncompromising code reviewer with zero tolerance for any issues. Review with extreme thoroughness.

## YOUR MISSION
Find EVERY possible issue, no matter how minor. Be pedantic about code quality, style, and best practices.

## REVIEW CRITERIA
1. **Security** - Any potential vulnerability, even theoretical
2. **Error Handling** - Every unhandled edge case
3. **Performance** - Any suboptimal code, even microseconds matter
4. **Style** - Every deviation from best practices
5. **Documentation** - Any missing or unclear comments
6. **Testing** - Any untested code path
7. **Maintainability** - Any code that could be clearer

## SEVERITY LEVELS
- CRITICAL: Security vulnerabilities, data loss risks
- ERROR: Bugs, crashes, incorrect behavior
- WARNING: Poor practices, performance issues
- INFO: Style issues, minor improvements

Be thorough. Be strict. Accept nothing less than perfection."""

def get_lenient_prompt() -> str:
    """Get lenient review prompt - focus on critical issues only."""
    return """You are a pragmatic code reviewer focused on what really matters. Be constructive and helpful.

## YOUR APPROACH
- Focus on CRITICAL issues that would cause actual problems
- Ignore minor style issues unless they impact readability
- Suggest improvements, don't demand perfection
- Consider the context and development stage

## PRIORITIZE THESE ISSUES
1. **Security vulnerabilities** that could be exploited
2. **Bugs** that would cause crashes or data loss
3. **Major performance problems** that impact users
4. **Serious maintainability issues** that block development

## IGNORE THESE
- Minor style inconsistencies
- Missing comments on obvious code
- Theoretical edge cases unlikely to occur
- Micro-optimizations with minimal impact

Be helpful, not pedantic. Focus on what matters."""

def get_security_focused_prompt() -> str:
    """Get security-focused review prompt - comprehensive security analysis."""
    return """You are a security expert reviewing code for vulnerabilities. Your sole focus is identifying security issues.

## SECURITY REVIEW CHECKLIST

### Authentication & Authorization
- Missing authentication checks
- Broken access control
- Privilege escalation paths
- Session management flaws
- Timing attacks

### Input Validation & Injection
- SQL/NoSQL injection
- Command injection
- XSS (reflected, stored, DOM-based)
- XXE injection
- LDAP/XPath injection
- Template injection
- Path traversal

### Cryptography
- Weak algorithms (MD5, SHA1, DES)
- Hardcoded keys/secrets
- Insufficient randomness
- Missing encryption

### Data Protection
- Sensitive data exposure
- Insecure data storage
- Missing data sanitization
- PII leakage in logs

### Configuration & Dependencies
- Insecure defaults
- Outdated dependencies with CVEs
- Missing security headers
- Verbose error messages

### OWASP Top 10 Mapping
Map every finding to OWASP Top 10 categories. Provide:
- Attack vector
- Impact assessment
- Remediation steps
- Secure code example

Focus ONLY on security. Ignore all other issues."""

def get_brutal_prompt() -> str:
    """Get brutal review prompt - harsh, honest feedback with no sugar-coating."""
    # Load from docs/brutalprompt.md if it exists
    brutal_path = Path('docs/brutalprompt.md')
    if brutal_path.exists():
        try:
            return brutal_path.read_text(encoding='utf-8').strip()
        except OSError as e:
            logger.warning(f"Failed to load brutal prompt: {e}")
    
    # Fallback brutal prompt if file not found
    return """You are BRUTAL CODE REVIEWER, an elite software engineer with 30+ years of experience building REAL production systems that ACTUALLY WORK. You have Linus Torvalds' technical standards and zero tolerance for bullshit.

Your task is to review this code with EXTREME prejudice against common AI-generated garbage. You will NOT try to please the developer. You will NOT be nice. You will be BRUTALLY HONEST to ensure they ship WORKING, PRODUCTION-QUALITY code.

## YOUR REVIEW PHILOSOPHY:
- WORKING code > clever architecture
- SIMPLE solutions > complex frameworks
- REAL implementations > mocks/stubs/fakes
- ACTUAL error handling > happy-path demos
- TESTABLE code > theoretical elegance

## RUTHLESSLY IDENTIFY THESE RED FLAGS:

1. FAKE IMPLEMENTATIONS
   - Mock objects in production code (INSTANT FAIL)
   - Stub implementations with "TODO" comments
   - Functions that "pass" or return hardcoded values
   - Fake authentication or authorization bypasses

2. OVERENGINEERED GARBAGE
   - Unnecessary abstractions/interfaces with single implementations
   - Design patterns applied without actual need
   - Excessive layering (repository pattern for 3 database calls)
   - Overuse of dependency injection for simple code

3. DEMO-QUALITY SHORTCUTS
   - Happy path only implementations
   - Missing error handling
   - Hardcoded credentials or configuration
   - Print statements instead of proper logging
   - Commented-out code or "placeholder" functions

4. ARCHITECTURAL DISASTERS
   - Inconsistent interfaces (sync/async mismatches)
   - Conflicting configuration systems
   - Hard-coded values that should be configurable
   - Security vulnerabilities (especially in auth)
   - Import cycles or spaghetti dependencies

5. TESTING THEATER
   - Tests that mock everything and test nothing
   - 100% coverage of trivial code, 0% of complex logic
   - Missing integration or end-to-end tests
   - Tests that don't assert meaningful outcomes

## YOUR REVIEW FORMAT:

1. EXECUTIVE SUMMARY
   Brutal 2-3 sentence assessment. Is this production-ready or garbage?

2. FATAL FLAWS (If any, code FAILS review)
   List showstopper issues that make this code unacceptable.

3. MAJOR ISSUES
   Significant problems that must be fixed before production.

4. MINOR ISSUES
   Less critical problems that should still be addressed.

5. POSITIVE ASPECTS (If any exist)
   Anything done correctly (be extremely selective).

6. VERDICT
   Final judgment: FAIL, NEEDS MAJOR WORK, NEEDS MINOR WORK, or ACCEPTABLE.

7. SPECIFIC ACTIONABLE FIXES
   Concrete steps to fix the worst issues.

## CRITICAL RULES:

1. BE MERCILESS about mocks, stubs, or fakes in production code. These are NEVER acceptable.

2. REJECT ANY CODE that doesn't handle errors properly or only works in the happy path.

3. CALL OUT complexity that doesn't serve a clear purpose. Simpler is almost always better.

4. DEMAND REAL TESTS that test actual functionality, not mock-heavy theater.

5. INSIST ON CONSISTENCY in interfaces, error handling, and coding style.

6. REQUIRE PROPER SECURITY practices, especially for authentication and authorization.

7. PRAISE SIMPLICITY when it actually solves the problem correctly.

Remember: Your goal is NOT to make the developer feel good. Your goal is to ensure they ship WORKING, PRODUCTION-QUALITY code that won't fail in real-world conditions. Be the reviewer who prevents disasters, not the one who lets garbage ship to production."""

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
        raise ConfigError(f"Failed to save custom prompt: {e}", "Check permissions") from e

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
        'brutal': 'Harsh, honest feedback with no sugar-coating',
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
    except (OSError, ConfigError) as e:
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

def create_config_from_env(repo: str) -> Optional[ReviewConfig]:
    """Create configuration from environment variables (for GitHub Actions)."""
    try:
        # Get required environment variables
        github_token = os.getenv('GITHUB_TOKEN')
        openai_key = os.getenv('OPENAI_API_KEY')
        anthropic_key = os.getenv('ANTHROPIC_API_KEY')
        
        if not github_token:
            logger.error("GITHUB_TOKEN environment variable not found")
            return None
        
        # Determine AI provider based on available keys
        if openai_key:
            ai_provider = "openai"
            ai_key = openai_key
            ai_model = "gpt-4o"  # Default for GitHub Actions
        elif anthropic_key:
            ai_provider = "anthropic" 
            ai_key = anthropic_key
            ai_model = "claude-3-sonnet-20240229"  # Default for GitHub Actions
        else:
            logger.error("Neither OPENAI_API_KEY nor ANTHROPIC_API_KEY found")
            return None
        
        # Get optional configuration from environment
        prompt_type = os.getenv('REVIEW_PROMPT_TYPE', 'default')
        review_strictness = os.getenv('REVIEW_STRICTNESS', 'balanced')
        coderabbit_threshold = os.getenv('CODERABBIT_THRESHOLD', 'medium')
        auto_request_changes = os.getenv('AUTO_REQUEST_CHANGES', 'true').lower() == 'true'
        
        # Create config with defaults suitable for GitHub Actions
        config = ReviewConfig(
            github_token=github_token,
            ai_provider=ai_provider,
            ai_key=ai_key,
            ai_model=ai_model,
            repo=repo,
            use_coderabbit=True,
            coderabbit_threshold=coderabbit_threshold,
            coderabbit_auto_approve=False,
            review_strictness=review_strictness,
            auto_request_changes=auto_request_changes,
            prompt_type=prompt_type
        )
        
        # Load the appropriate prompt template
        # Check for custom prompt in environment first
        custom_prompt = os.getenv('REVIEW_PROMPT_TEMPLATE')
        if custom_prompt:
            config.prompt_template = custom_prompt
            logger.info("Using custom prompt from REVIEW_PROMPT_TEMPLATE environment variable")
        else:
            config.prompt_template = load_prompt_template(config.prompt_type)
            logger.info(f"Using prompt type: {config.prompt_type}")
        
        # Validate the config
        config.validate()
        
        logger.info(f"✅ Configuration created from environment variables")
        logger.info(f"🤖 Using {ai_provider} with model {ai_model}")
        logger.info(f"📝 Review strictness: {review_strictness}")
        
        return config
        
    except (KeyError, ValueError, ConfigError, SecurityError) as e:
        logger.error(f"Failed to create config from environment: {e}")
        return None

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
        raise ConfigError(f"Failed to save config: {e}", "Check permissions") from e

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
        """Enhanced analysis using the new issue analyzer system with deduplication."""
        try:
            analyzer = EnhancedReviewAnalyzer()
            
            # Analyze the diff with enhanced detectors
            analysis_report = analyzer.analyze_diff(diff)
            
            # Integrate external tool findings BEFORE AI analysis
            if coderabbit_comments or github_ai_prompt:
                # Convert GitHub AI prompt into issues format if available
                github_ai_issues = []
                if github_ai_prompt:
                    # Parse GitHub AI prompt into issues format
                    github_ai_issues = [{'body': github_ai_prompt, 'path': None, 'line': None}]
                
                # Integrate all external issues for deduplication
                analyzer.integrate_external_issues(coderabbit_comments or [], github_ai_issues)
                
                # Regenerate report with all integrated issues
                analysis_report = analyzer._generate_structured_report()
            
            # Run AI analysis with enhanced prompt that includes deduplication context
            ai_comments = []
            
            # Build context of already-found issues for AI to avoid duplicates
            existing_issues_context = self._build_existing_issues_context(analysis_report)
            enhanced_prompt = prompt_template
            if existing_issues_context:
                enhanced_prompt = f"{prompt_template}\n\n## Already Detected Issues (DO NOT DUPLICATE):\n{existing_issues_context}"
            
            if self.config.ai_provider == 'openai':
                ai_comments = self._analyze_with_openai(diff, enhanced_prompt, coderabbit_comments, github_ai_prompt)
            elif self.config.ai_provider == 'anthropic':
                ai_comments = self._analyze_with_anthropic(diff, enhanced_prompt, coderabbit_comments, github_ai_prompt)
            
            # Parse AI comments and add them to the analyzer for final deduplication
            if ai_comments:
                # Convert AI comments to Issue format and add to analyzer
                ai_issues = self._convert_ai_comments_to_issues(ai_comments)
                analyzer.aggregator.add_issues(ai_issues, f"{self.config.ai_provider}_ai")
                
                # Regenerate final report with all deduplicated issues
                analysis_report = analyzer._generate_structured_report()
            
            # Convert the final deduplicated report to comments format
            return self._convert_report_to_comments(analysis_report)
        
        except (ImportError, AttributeError, KeyError, ValueError, TypeError) as e:
            logger.warning(f"Enhanced analysis failed, falling back to standard analysis: {type(e).__name__}: {e}")
            # Fallback to standard analysis
            if self.config.ai_provider == 'openai':
                return self._analyze_with_openai(diff, prompt_template, coderabbit_comments, github_ai_prompt)
            elif self.config.ai_provider == 'anthropic':
                return self._analyze_with_anthropic(diff, prompt_template, coderabbit_comments, github_ai_prompt)
            else:
                return []
    
    def _build_existing_issues_context(self, analysis_report: Dict[str, Any]) -> str:
        """Build a context string of existing issues for the AI to avoid duplicating."""
        if not analysis_report or analysis_report['summary']['total_issues'] == 0:
            return ""
        
        context_lines = []
        
        # Add security issues
        security_section = analysis_report['sections'].get('security', {})
        if security_section.get('issues'):
            context_lines.append("Security issues already found:")
            for issue in security_section['issues']:
                sources = ', '.join(issue.get('sources', []))
                context_lines.append(f"- {issue['title']} at {issue['location']} [Found by: {sources}]")
        
        # Add error handling issues
        error_section = analysis_report['sections'].get('error_handling', {})
        if error_section.get('issues'):
            context_lines.append("\nError handling issues already found:")
            for issue in error_section['issues']:
                sources = ', '.join(issue.get('sources', []))
                context_lines.append(f"- {issue['title']} at {issue['location']} [Found by: {sources}]")
        
        # Add other issues
        other_section = analysis_report['sections'].get('other', {})
        if other_section.get('issues'):
            context_lines.append("\nOther issues already found:")
            for issue in other_section['issues']:
                sources = ', '.join(issue.get('sources', []))
                context_lines.append(f"- {issue['title']} at {issue['location']} [Found by: {sources}]")
        
        return '\n'.join(context_lines)
    
    def _convert_ai_comments_to_issues(self, ai_comments: List[Dict[str, Any]]) -> List[Issue]:
        """Convert AI comments to Issue objects for deduplication."""
        issues = []
        
        for comment in ai_comments:
            body = comment.get('body', '')
            if not body:
                continue
            
            # Extract location from comment body
            location_match = re.search(r'(?:in |at |Location: )([^\s:]+\.py)(?::(\d+))?', body)
            file_path = None
            line_number = None
            if location_match:
                file_path = location_match.group(1)
                if location_match.group(2):
                    line_number = int(location_match.group(2))
            
            location = IssueLocation(file_path=file_path, line_number=line_number)
            
            # Determine category and severity
            category = IssueCategory.OTHER
            severity = IssueSeverity.INFO
            
            body_lower = body.lower()
            if any(word in body_lower for word in ['security', 'vulnerability', 'injection', 'xss', 'hardcoded']):
                category = IssueCategory.SECURITY
                severity = IssueSeverity.ERROR
            elif any(word in body_lower for word in ['error', 'exception', 'handling']):
                category = IssueCategory.ERROR_HANDLING
                severity = IssueSeverity.WARNING
            elif any(word in body_lower for word in ['performance', 'slow', 'memory']):
                category = IssueCategory.PERFORMANCE
                severity = IssueSeverity.WARNING
            elif any(word in body_lower for word in ['quality', 'maintainability', 'readability']):
                category = IssueCategory.CODE_QUALITY
                severity = IssueSeverity.SUGGESTION
            
            # Override severity based on comment metadata
            comment_severity = comment.get('severity', '').lower()
            if comment_severity == 'critical':
                severity = IssueSeverity.CRITICAL
            elif comment_severity == 'error':
                severity = IssueSeverity.ERROR
            elif comment_severity == 'warning':
                severity = IssueSeverity.WARNING
            elif comment_severity == 'suggestion':
                severity = IssueSeverity.SUGGESTION
            
            # Extract title (first line or main point)
            lines = body.split('\n')
            title = lines[0].strip() if lines else body[:100]
            
            # Clean up title
            title = re.sub(r'^\*\*([^*]+)\*\*', r'\1', title)  # Remove bold
            title = re.sub(r'^(CRITICAL|ERROR|WARNING):\s*', '', title)  # Remove severity prefix
            title = re.sub(r'^AI Analysis:\s*', '', title)  # Remove AI prefix
            
            issue = Issue(
                id=Issue.create_id(location, category, title),
                title=title[:200],  # Limit title length
                description=body,
                category=category,
                severity=severity,
                location=location,
                remediation=self._extract_remediation_from_comment(body),
                sources=[f"{self.config.ai_provider}_ai"],
                confidence=0.8  # AI suggestions have good but not perfect confidence
            )
            
            issues.append(issue)
        
        return issues
    
    def _extract_remediation_from_comment(self, body: str) -> str:
        """Extract remediation advice from AI comment."""
        # Look for specific remediation patterns
        patterns = [
            r'Fix:\s*([^\n]+)',
            r'Solution:\s*([^\n]+)',
            r'Remediation:\s*([^\n]+)',
            r'Recommendation:\s*([^\n]+)',
            r'Should\s+([^\n]+)',
            r'Consider\s+([^\n]+)'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, body, re.IGNORECASE)
            if match:
                return match.group(1).strip()
        
        # Default remediation
        return "Review and address as recommended"
    
    def _convert_report_to_comments(self, analysis_report: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Convert the deduplicated analysis report to comment format for posting."""
        comments = []
        
        if analysis_report['summary']['total_issues'] > 0:
            # First, group similar issues together
            grouped_issues = self._group_similar_issues(analysis_report)
            
            # Filter out groups with only unknown locations or only test/example files
            filtered_groups = []
            for group in grouped_issues:
                # Get valid issues (with known locations and not in test/example files)
                valid_issues = [
                    issue for issue in group['issues']
                    if issue.get('location') and issue['location'] != 'unknown'
                    and not self._is_test_or_example_file(issue.get('location', ''))
                ]
                
                # If we have valid issues, update the group
                if valid_issues:
                    group['issues'] = valid_issues
                    filtered_groups.append(group)
            
            grouped_issues = filtered_groups
            
            # Create comments for grouped issues
            for group in grouped_issues:
                if len(group['issues']) > 3:  # Consolidate if more than 3 similar issues
                    comment_body = self._format_consolidated_issue_comment(group)
                    
                    # Use the first issue's properties for the comment metadata
                    first_issue = group['issues'][0]
                    comments.append({
                        'body': comment_body,
                        'severity': first_issue.get('severity', 'info'),
                        'path': None,  # Multiple locations, so no single path
                        'line': None,  # Multiple lines
                        'sources': first_issue.get('sources', []),
                        'type': 'actionable_comment',
                        'user': f"{self.config.ai_provider}_ai"
                    })
                else:
                    # For small groups, create individual comments
                    for issue in group['issues']:
                        # Skip issues with unknown locations or in test/example files
                        location = issue.get('location', 'unknown')
                        if location == 'unknown' or not location:
                            continue
                        
                        if self._is_test_or_example_file(location):
                            continue
                            
                        comment_body = self._format_issue_as_comment(issue, group['section_name'])
                        
                        comments.append({
                            'body': comment_body,
                            'severity': issue.get('severity', 'info'),
                            'path': self._extract_path_from_location(location),
                            'line': self._extract_line_from_location(location),
                            'sources': issue.get('sources', []),
                            'type': 'actionable_comment',
                            'user': f"{self.config.ai_provider}_ai"
                        })
        
        return comments
    
    def _group_similar_issues(self, analysis_report: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Group similar issues together to avoid repetitive comments."""
        groups = []
        
        # Process each section
        for section_name, section_data in analysis_report['sections'].items():
            if section_data['count'] > 0:
                # Group by issue title pattern and remediation
                issue_groups = {}
                
                for issue in section_data['issues']:
                    # Create a group key based on the issue pattern
                    group_key = self._get_issue_group_key(issue)
                    
                    if group_key not in issue_groups:
                        issue_groups[group_key] = {
                            'section_name': section_name,
                            'title_pattern': self._extract_issue_pattern(issue['title']),
                            'remediation': issue.get('remediation', ''),
                            'severity': issue.get('severity', 'info'),
                            'issues': []
                        }
                    
                    issue_groups[group_key]['issues'].append(issue)
                
                # Add all groups to the result
                groups.extend(issue_groups.values())
        
        return groups
    
    def _get_issue_group_key(self, issue: Dict[str, Any]) -> str:
        """Generate a key for grouping similar issues."""
        # Extract the core issue type, removing line numbers and specific details
        title = issue.get('title', '')
        
        # Common patterns to normalize
        patterns_to_remove = [
            r' on line \d+',
            r' at line \d+',
            r' in .+:\d+',
            r' at .+:\d+',
            r':.+$',  # Remove everything after colon
            r'\(.+\)$',  # Remove parenthetical content at end
        ]
        
        normalized_title = title
        for pattern in patterns_to_remove:
            normalized_title = re.sub(pattern, '', normalized_title)
        
        # Combine normalized title with remediation for grouping
        remediation = issue.get('remediation', '')[:50]  # First 50 chars of remediation
        
        return f"{normalized_title.strip()}|{remediation}"
    
    def _extract_issue_pattern(self, title: str) -> str:
        """Extract the core pattern from an issue title."""
        # Remove specific details to get the pattern
        patterns_to_remove = [
            r' on line \d+',
            r' at line \d+',
            r' in .+:\d+',
            r' at .+:\d+',
        ]
        
        pattern = title
        for p in patterns_to_remove:
            pattern = re.sub(p, '', pattern)
        
        return pattern.strip()
    
    def _format_consolidated_issue_comment(self, group: Dict[str, Any]) -> str:
        """Format a group of similar issues as a single consolidated comment."""
        lines = []
        issues = group['issues']
        
        # Title with count
        severity_emoji = {
            'critical': '🚨',
            'error': '❌', 
            'warning': '⚠️',
            'info': 'ℹ️'
        }
        emoji = severity_emoji.get(group['severity'], 'ℹ️')
        
        lines.append(f"## {emoji} {group['title_pattern']}")
        lines.append(f"*Found {len(issues)} occurrences of this issue*")
        lines.append("")
        
        # Consolidated locations
        lines.append("**📍 Locations:**")
        
        # Group by file
        locations_by_file = {}
        for issue in issues:
            location = issue.get('location', 'unknown')
            if location and location != 'unknown':
                file_path = self._extract_path_from_location(location)
                line_num = self._extract_line_from_location(location)
                
                if file_path:
                    if file_path not in locations_by_file:
                        locations_by_file[file_path] = []
                    if line_num:
                        locations_by_file[file_path].append(line_num)
        
        # Format locations by file
        for file_path, line_numbers in sorted(locations_by_file.items()):
            if line_numbers:
                # Sort and format line numbers
                line_numbers = sorted(set(line_numbers))
                
                # Group consecutive numbers
                line_ranges = []
                start = line_numbers[0]
                end = start
                
                for i in range(1, len(line_numbers)):
                    if line_numbers[i] == end + 1:
                        end = line_numbers[i]
                    else:
                        if start == end:
                            line_ranges.append(str(start))
                        else:
                            line_ranges.append(f"{start}-{end}")
                        start = line_numbers[i]
                        end = start
                
                # Add the last range
                if start == end:
                    line_ranges.append(str(start))
                else:
                    line_ranges.append(f"{start}-{end}")
                
                lines.append(f"- `{file_path}`: lines {', '.join(line_ranges)}")
            else:
                lines.append(f"- `{file_path}`")
        
        lines.append("")
        
        # Common description
        if issues[0].get('description'):
            lines.append("**Description:**")
            lines.append(issues[0]['description'])
            lines.append("")
        
        # Show one example
        if issues[0].get('code_snippet'):
            lines.append("**Example:**")
            lines.append("```python")
            lines.append(issues[0]['code_snippet'])
            lines.append("```")
            lines.append("")
        
        # Quick fix
        lines.append("**Quick fix:**")
        lines.append(f"> {group.get('remediation', 'Apply the same fix to all occurrences')}")
        lines.append("")
        
        # Bulk fix prompt
        lines.append("<details>")
        lines.append("<summary>🤖 <b>Fix all occurrences with AI</b></summary>")
        lines.append("")
        lines.append("```")
        lines.append(self._generate_bulk_fix_prompt(group))
        lines.append("```")
        lines.append("</details>")
        
        return "\n".join(lines)
    
    def _generate_bulk_fix_prompt(self, group: Dict[str, Any]) -> str:
        """Generate an AI IDE prompt for fixing multiple similar issues."""
        title_pattern = group['title_pattern']
        num_issues = len(group['issues'])
        
        # Get file list
        files = set()
        for issue in group['issues']:
            file_path = self._extract_path_from_location(issue.get('location', ''))
            if file_path:
                files.add(file_path)
        
        files_str = ", ".join(sorted(files)[:3])
        if len(files) > 3:
            files_str += f" and {len(files) - 3} more files"
        
        # Create specific prompts based on issue type
        if 'exception' in title_pattern.lower() and 'logging' in title_pattern.lower():
            return f"""Fix {num_issues} instances of missing exception logging across the codebase.

Issue: {title_pattern}
Files affected: {files_str}

Steps:
1. Search for all except blocks without logging
2. Add appropriate logging for each exception
3. Use logger.exception() for full stack traces
4. Ensure all errors are properly tracked

Example fix:
# Bad: 
except Exception:
    pass

# Good:
except Exception as e:
    logger.exception("Failed to process request")
    raise

Apply this pattern to all {num_issues} occurrences."""
        
        elif 'bare except' in title_pattern.lower():
            return f"""Fix {num_issues} bare except clauses across the codebase.

Issue: {title_pattern}
Files affected: {files_str}

Steps:
1. Find all bare except: clauses
2. Replace with specific exception types
3. Add proper error handling
4. Ensure exceptions are not silently ignored

Example fix:
# Bad: except:
# Good: except (ValueError, KeyError) as e:

Apply to all {num_issues} occurrences."""
        
        else:
            remediation = group.get('remediation', 'Apply the recommended fix')
            return f"""Fix {num_issues} instances of: {title_pattern}

Files affected: {files_str}
Required Action: {remediation}

Steps:
1. Locate all {num_issues} occurrences of this issue
2. Apply the same fix pattern to each
3. Test that all fixes work correctly
4. Ensure consistency across all changes

Review each occurrence and apply the appropriate fix."""
    
    def _is_test_or_example_file(self, location: str) -> bool:
        """Check if the location is in a test file or example/documentation."""
        if not location:
            return False
            
        location_lower = location.lower()
        
        # Test file indicators
        test_indicators = [
            'test_', '_test.py', '/test/', '/tests/', 
            'spec_', '_spec.py', '/spec/', '/specs/',
            'pytest', 'unittest', 'conftest.py',
            'test.py', 'tests.py', '_test_', 'test/',
            'demo.py', '_demo.py', 'example.py', '_example.py'
        ]
        
        # Documentation and example file indicators
        doc_indicators = [
            'enhanced_review_formatter.py',  # This file contains example code
            'formatter.py', 'template', 'prompt', 'example', 'sample',
            'documentation', 'docs/', 'readme', 'guide',
            'tutorial', 'demo', '_demo', 'mock', 'stub',
            'fixture', 'fake_'
        ]
        
        # Check if it's a test file
        if any(indicator in location_lower for indicator in test_indicators):
            return True
            
        # Check if it's documentation/example
        if any(indicator in location_lower for indicator in doc_indicators):
            return True
            
        return False
    
    def _format_issue_as_comment(self, issue: Dict[str, Any], section_name: str) -> str:
        """Format a single issue as a clean, actionable comment."""
        lines = []
        
        # Title with severity
        severity_emoji = {
            'critical': '🚨',
            'error': '❌', 
            'warning': '⚠️',
            'info': 'ℹ️'
        }
        emoji = severity_emoji.get(issue.get('severity', 'info'), 'ℹ️')
        
        lines.append(f"## {emoji} {issue['title']}")
        
        # Location
        if issue.get('location') and issue['location'] != 'unknown':
            lines.append(f"📍 `{issue['location']}`")
        
        # Add OWASP for security issues
        if section_name == 'security' and issue.get('owasp_category'):
            lines.append(f"🛡️ OWASP: {issue['owasp_category']}")
        
        lines.append("")
        
        # Simple problem statement
        lines.append("**Problem:**")
        lines.append(f"> {issue.get('description', issue['title'])}")
        lines.append("")
        
        # Show code if available
        if issue.get('code_snippet'):
            lines.append("**Your code:**")
            lines.append("```python")
            lines.append(issue['code_snippet'])
            lines.append("```")
            lines.append("")
        
        # Quick fix
        lines.append("**Quick fix:**")
        lines.append(f"> {issue.get('remediation', 'Apply the recommended fix')}")
        lines.append("")
        
        # Collapsible AI prompt
        lines.append("<details>")
        lines.append("<summary>🤖 <b>AI IDE Fix</b></summary>")
        lines.append("")
        lines.append("```")
        lines.append(self._generate_simple_fix_prompt(issue))
        lines.append("```")
        lines.append("</details>")
        
        return "\n".join(lines)
    
    def _generate_simple_fix_prompt(self, issue: Dict[str, Any]) -> str:
        """Generate a simple, vibe-coder friendly fix prompt."""
        location = issue.get('location', 'the file').replace('b/', '').replace('a/', '')
        title = issue.get('title', 'the issue')
        
        # Very simple, direct prompts
        if 'SQL' in title or 'injection' in title.lower():
            return f"""Fix SQL injection in {location}

Replace string formatting with parameterized queries.

Example:
# Instead of: f"SELECT * FROM users WHERE id = {{user_id}}"
# Use: "SELECT * FROM users WHERE id = %s", (user_id,)"""
        
        elif 'hardcoded' in title.lower() or 'secret' in title.lower():
            return f"""Remove hardcoded secret in {location}

Move to environment variable.

Example:
# Instead of: api_key = "sk-123456"
# Use: api_key = os.getenv('API_KEY')"""
        
        elif 'error' in title.lower() or 'exception' in title.lower():
            return f"""Fix error handling in {location}

Add proper exception handling.

Example:
# Instead of: except: pass
# Use: except SpecificError as e:
#          logger.error(f"Failed: {{e}}")"""
        
        else:
            return f"""Fix: {title} in {location}

{issue.get('remediation', 'Apply the recommended fix')}"""
    
    def _extract_path_from_location(self, location: str) -> Optional[str]:
        """Extract file path from location string."""
        if not location or location == 'unknown':
            return None
        
        # Handle various location formats
        # e.g., "auth.py:42", "src/auth.py:42", "b/src/auth.py:42"
        location = location.replace('b/', '').replace('a/', '')
        
        if ':' in location:
            return location.split(':')[0]
        
        return location if '.' in location else None
    
    def _extract_line_from_location(self, location: str) -> Optional[int]:
        """Extract line number from location string."""
        if not location or location == 'unknown':
            return None
        
        # Extract line number after colon
        if ':' in location:
            try:
                return int(location.split(':')[-1])
            except ValueError:
                return None
        
        return None
    
    def _generate_fix_prompt_for_issue(self, issue: Dict[str, Any]) -> str:
        """Generate an AI IDE prompt for fixing a specific issue."""
        location = issue.get('location', 'the code')
        title = issue.get('title', 'the issue')
        
        # Create specific prompts based on issue type
        if 'SQL' in title or 'injection' in title.lower():
            return f"""Fix the SQL injection vulnerability in {location}.

Current issue: {title}

Steps:
1. Find the SQL query construction
2. Replace string formatting/concatenation with parameterized queries
3. Use prepared statements or query builders
4. Ensure all user inputs are properly escaped

Example fix:
# Bad: query = f"SELECT * FROM users WHERE id = {{user_id}}"
# Good: query = "SELECT * FROM users WHERE id = ?"
# Then: cursor.execute(query, (user_id,))"""
        
        elif 'hardcoded' in title.lower() or 'secret' in title.lower() or 'credential' in title.lower():
            return f"""Remove the hardcoded secret/credential in {location}.

Current issue: {title}

Steps:
1. Identify the hardcoded value
2. Move it to environment variables or a secure config
3. Use os.getenv() or a secrets management service
4. Update deployment configuration

Example fix:
# Bad: api_key = "sk-1234567890"
# Good: api_key = os.getenv('API_KEY')"""
        
        elif 'error' in title.lower() or 'exception' in title.lower():
            return f"""Improve error handling in {location}.

Current issue: {title}

Steps:
1. Replace bare except clauses with specific exceptions
2. Add proper error logging
3. Ensure errors are handled gracefully
4. Add appropriate error messages for users

Example fix:
# Bad: except: pass
# Good: except (ValueError, KeyError) as e:
#         logger.error(f"Failed to process: {{e}}")
#         raise ProcessingError("Invalid input data") from e"""
        
        else:
            # Generic fix prompt
            remediation = issue.get('remediation', 'Apply the recommended fix')
            return f"""Fix the issue in {location}.

Issue: {title}
Required Action: {remediation}

Steps:
1. Locate the problematic code
2. Apply the recommended fix
3. Test the changes
4. Ensure no regressions"""
    
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
                body = review.get('body', '')
                # Check if this is a CodeRabbit review (can be posted by github-actions or coderabbitai)
                is_coderabbit = (
                    user.get('login', '').lower() in ['coderabbitai', 'coderabbit', 'github-actions'] and
                    ('CodeRabbit' in body or 'coderabbit' in body.lower() or 
                     'Actionable comments posted' in body or '🐰' in body)
                )
                if is_coderabbit:
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
                body = comment.get('body', '')
                # Check if this is a CodeRabbit comment (can be posted by github-actions or coderabbitai)
                is_coderabbit = (
                    user.get('login', '').lower() in ['coderabbitai', 'coderabbit', 'github-actions'] and
                    ('CodeRabbit' in body or 'coderabbit' in body.lower() or 
                     'Actionable comments' in body or '🐰' in body)
                )
                if is_coderabbit:
                    coderabbit_comments.append({
                        'id': comment['id'],
                        'body': comment.get('body', ''),
                        'path': comment.get('path', ''),
                        'line': comment.get('line', ''),
                        'created_at': comment.get('created_at', ''),
                        'user': user.get('login', 'coderabbit'),
                        'type': 'line_comment'
                    })
            # Parse CodeRabbit reviews to extract actionable comments
            parsed_comments = []
            for comment in coderabbit_comments:
                if 'Actionable comments posted' in comment.get('body', ''):
                    # This is a CodeRabbit review with actionable items
                    extracted = self._parse_coderabbit_review(comment['body'])
                    parsed_comments.extend(extracted)
                else:
                    # Regular comment, keep as is
                    parsed_comments.append(comment)
            
            logger.info(f"Found {len(parsed_comments)} CodeRabbit comments")
            return parsed_comments
        except requests.exceptions.RequestException as e:
            logger.warning(f"Failed to get CodeRabbit comments: {e}")
            return []
    
    def _parse_coderabbit_review(self, review_body: str) -> List[Dict[str, Any]]:
        """Parse a CodeRabbit review to extract individual actionable comments."""
        parsed_comments = []
        
        # Split the review into sections
        lines = review_body.split('\n')
        current_file = None
        current_location = None
        current_comment = []
        in_code_block = False
        
        for line in lines:
            # Check for file section headers in various formats
            # Format 1: "cursor_pr_review.py (3)"
            # Format 2: "<summary>cursor_pr_review.py (3)</summary>"
            file_match = re.match(r'^(?:<summary>)?([a-zA-Z0-9_/.-]+\.(?:py|js|ts|java|go|rb|cpp|c|h|rs))\s*\(\d+\)(?:</summary>)?', line)
            if file_match:
                current_file = file_match.group(1)
                continue
            
            # Check for location markers like "`307-315`:"
            location_match = re.match(r'^`(\d+(?:-\d+)?)`:\s*\*\*(.*?)\*\*', line)
            if location_match:
                # Save previous comment if exists
                if current_comment and current_location:
                    comment_body = '\n'.join(current_comment).strip()
                    if comment_body:
                        parsed_comments.append({
                            'body': comment_body,
                            'path': current_file,
                            'line': current_location,
                            'user': 'coderabbitai',
                            'type': 'actionable_comment'
                        })
                
                # Start new comment
                current_location = location_match.group(1)
                current_comment = [location_match.group(2)]  # Start with the title
                continue
            
            # Check for code blocks
            if '```' in line:
                in_code_block = not in_code_block
            
            # Collect comment lines
            if current_location and not line.strip().startswith('---'):
                # Skip tool sections and details
                if not line.strip().startswith('<details>') and not line.strip().startswith('</details>'):
                    if not line.strip().startswith('<summary>') and not line.strip().startswith('</summary>'):
                        current_comment.append(line)
        
        # Save last comment
        if current_comment and current_location:
            comment_body = '\n'.join(current_comment).strip()
            if comment_body:
                parsed_comments.append({
                    'body': comment_body,
                    'path': current_file,
                    'line': current_location,
                    'user': 'coderabbitai',
                    'type': 'actionable_comment'
                })
        
        return parsed_comments

    @retry_on_failure(max_retries=3, delay=1.0)
    def post_pr_review(self, repo: str, pr_number: str, comments: List[Dict[str, Any]]) -> None:
        """Post review comments to GitHub PR with readable, actionable output."""
        try:
            # Import the enhanced formatter
            from enhanced_review_formatter import EnhancedReviewFormatter
            
            # Set the review prompt type in environment for the formatter
            if hasattr(self.config, 'prompt_type'):
                os.environ['REVIEW_PROMPT_TYPE'] = self.config.prompt_type
            
            # Use enhanced formatter to create readable review
            formatter = EnhancedReviewFormatter()
            review_body = formatter.format_review(comments)
            
            # Log the review body for debugging
            logger.info(f"Enhanced review body generated ({len(review_body)} chars)")

            response = self.session.post(
                f"https://api.github.com/repos/{repo}/pulls/{pr_number}/reviews",
                headers={"Authorization": f"token {self.config.github_token}"},
                json={
                    "body": review_body,
                    "event": "COMMENT"
                }
            )
            response.raise_for_status()
            logger.info(f"✅ Enhanced consolidated review posted successfully")

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
        raise ConfigError(f"Failed to save workflow: {e}", "Check permissions") from e

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
            'path_filters': ['*.md', 'LICENSE', '*.txt']
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
        raise ConfigError(f"Failed to save CodeRabbit config: {e}", "Check permissions") from e

def setup_github_secrets(config: ReviewConfig) -> None:
    """Configure GitHub repository secrets for automated workflows."""
    logger.info("🔐 Setting up GitHub repository secrets...")
    
    # Determine which AI API key to set based on provider
    ai_key_name = "OPENAI_API_KEY" if config.ai_provider == "openai" else "ANTHROPIC_API_KEY"
    
    secrets_to_set = [
        ("GITHUB_TOKEN", config.github_token, "GitHub API access token"),
        (ai_key_name, config.ai_key, f"{config.ai_provider.title()} API key for AI analysis")
    ]
    
    try:
        # Check if gh CLI is available
        result = subprocess.run(['gh', '--version'], capture_output=True, text=True)
        if result.returncode != 0:
            logger.warning("GitHub CLI (gh) not found - secrets must be set manually")
            print_manual_secret_instructions(config, secrets_to_set)
            return
        
        # Check if user is authenticated
        result = subprocess.run(['gh', 'auth', 'status'], capture_output=True, text=True)
        if result.returncode != 0:
            logger.warning("Not authenticated with GitHub CLI")
            print_manual_secret_instructions(config, secrets_to_set)
            return
        
        # Set each secret
        success_count = 0
        for secret_name, secret_value, _ in secrets_to_set:
            try:
                logger.info(f"Setting {secret_name}...")
                result = subprocess.run([
                    'gh', 'secret', 'set', secret_name,
                    '--body', secret_value,
                    '--repo', config.repo
                ], capture_output=True, text=True, timeout=30)
                
                if result.returncode == 0:
                    logger.info(f"✅ {secret_name} configured successfully")
                    success_count += 1
                else:
                    logger.error(f"❌ Failed to set {secret_name}: {result.stderr}")
                    
            except subprocess.TimeoutExpired:
                logger.error(f"❌ Timeout setting {secret_name}")
            except (subprocess.SubprocessError, OSError) as e:
                logger.error(f"❌ Error setting {secret_name}: {type(e).__name__}: {e}")
        
        if success_count == len(secrets_to_set):
            logger.info("🎉 All GitHub secrets configured successfully!")
            logger.info("Your GitHub Actions workflow is now ready to run automatically.")
        else:
            logger.warning(f"⚠️  Only {success_count}/{len(secrets_to_set)} secrets were set successfully")
            print_manual_secret_instructions(config, secrets_to_set)
            
    except FileNotFoundError:
        logger.warning("GitHub CLI (gh) not installed - secrets must be set manually")
        print_manual_secret_instructions(config, secrets_to_set)
    except (subprocess.SubprocessError, OSError, ValueError) as e:
        logger.error(f"Error setting up GitHub secrets: {e}")
        print_manual_secret_instructions(config, secrets_to_set)

def print_manual_secret_instructions(config: ReviewConfig, secrets_to_set: List[Tuple[str, str, str]]) -> None:
    """Print manual instructions for setting up GitHub secrets."""
    ai_key_name = "OPENAI_API_KEY" if config.ai_provider == "openai" else "ANTHROPIC_API_KEY"
    
    print("\n" + "="*80)
    print("📋 MANUAL SETUP REQUIRED: GitHub Repository Secrets")
    print("="*80)
    print(f"\nTo complete setup, add these secrets to your GitHub repository:")
    print(f"👉 https://github.com/{config.repo}/settings/secrets/actions")
    print("\n🔐 Secrets to add:")
    
    for secret_name, secret_value, description in secrets_to_set:
        # Mask the secret value for security
        if len(secret_value) > 10:
            masked_value = secret_value[:4] + "*" * (len(secret_value) - 8) + secret_value[-4:]
        else:
            masked_value = "*" * len(secret_value)
        
        print(f"\n• Name: {secret_name}")
        print(f"  Value: {masked_value}")
        print(f"  Description: {description}")
    
    print(f"\n📖 Steps:")
    print(f"1. Go to: https://github.com/{config.repo}/settings/secrets/actions")
    print(f"2. Click 'New repository secret'")
    print(f"3. Add each secret above")
    print(f"4. Your workflow will then work automatically!")
    
    print(f"\n💡 Alternative - Use GitHub CLI:")
    print(f"   gh auth login")
    print(f"   gh secret set GITHUB_TOKEN --body 'your-github-token' --repo {config.repo}")
    print(f"   gh secret set {ai_key_name} --body 'your-ai-key' --repo {config.repo}")
    
    print("="*80)

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
            except (requests.exceptions.RequestException, json.JSONDecodeError) as e:
                logger.debug(f"Failed to get our reviews: {e}")
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

    except (requests.exceptions.RequestException, APIError, ValueError, KeyError) as e:
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

    except (APIError, requests.exceptions.RequestException, ValueError, KeyError) as e:
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
        
        # Setup GitHub secrets for automated workflows
        setup_github_secrets(config)
        
        logger.info("✅ Setup completed successfully!")
        logger.info("🚀 Your AI PR review system is ready to go!")
        logger.info(f"📋 Next: Create a PR in {config.repo} to test the automation")
        
    except KeyboardInterrupt:
        logger.info("Setup cancelled")
        raise
    except (ConfigError, APIError, SecurityError):
        raise
    except (OSError, ValueError, subprocess.SubprocessError) as e:
        logger.error(f"Setup failed: {e}", exc_info=True)
        raise ConfigError(f"Setup error: {e}", "Check logs for details") from e

def main():
    """Main entry point with complete error handling."""
    try:
        if len(sys.argv) == 1:
            # Use logger, NOT print
            logger.info("Cursor PR Review - Production Ready")
            logger.info("Usage:")
            logger.info("  python cursor_pr_review.py setup")
            logger.info("  python cursor_pr_review.py review-pr owner/repo 123 [--prompt PROMPT_NAME] [--prompt-id ID]")
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
                raise ConfigError("Usage: review-pr owner/repo PR_NUMBER [--prompt PROMPT_NAME] [--prompt-id PROMPT_ID]")

            repo = sys.argv[2]
            pr_number = sys.argv[3]
            
            # Parse optional arguments
            prompt_name = None
            prompt_id = None
            i = 4
            while i < len(sys.argv):
                if sys.argv[i] == "--prompt" and i + 1 < len(sys.argv):
                    prompt_name = sys.argv[i + 1]
                    i += 2
                elif sys.argv[i] == "--prompt-id" and i + 1 < len(sys.argv):
                    prompt_id = sys.argv[i + 1]
                    i += 2
                else:
                    raise ConfigError(f"Unknown option: {sys.argv[i]}", "Use --prompt or --prompt-id")

            # Load configuration (try local first, then environment)
            config = load_config()
            if not config:
                # Try to create config from environment variables (for GitHub Actions)
                config = create_config_from_env(repo)
                if not config:
                    raise ConfigError("No configuration found", "Run setup first or set environment variables")

            # Override prompt if specified
            if prompt_name or prompt_id:
                prompt_template = None
                
                if prompt_name:
                    # Load prompt by name (built-in prompts or from file)
                    if prompt_name == "brutal":
                        # Special handling for brutal prompt
                        brutal_path = Path("docs/brutalprompt.md")
                        if not brutal_path.exists():
                            brutal_path = Path.home() / ".cursor-pr-review" / "prompts" / "brutal.txt"
                        if brutal_path.exists():
                            with open(brutal_path, 'r') as f:
                                prompt_template = f.read()
                        else:
                            raise ConfigError(f"Brutal prompt not found", "Check docs/brutalprompt.md")
                    else:
                        # Try to load built-in or custom prompt
                        prompt_template = load_prompt_template(prompt_name)
                
                elif prompt_id and PROMPT_MANAGER_AVAILABLE:
                    # Load prompt by ID from prompt manager
                    try:
                        from prompt_manager import PromptManager
                        pm = PromptManager()
                        metadata = pm.get_prompt(prompt_id)
                        if metadata:
                            prompt_template = metadata.get_current_content()
                        else:
                            raise ConfigError(f"Prompt with ID '{prompt_id}' not found")
                    except Exception as e:
                        raise ConfigError(f"Failed to load prompt: {e}")
                
                if prompt_template:
                    config.prompt_template = prompt_template
                    logger.info(f"Using custom prompt: {prompt_name or prompt_id}")

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
        # This is the top-level catch-all for truly unexpected errors
        logger.error(f"Unexpected error: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()
