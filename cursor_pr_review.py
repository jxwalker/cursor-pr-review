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
    prompt_template: str = "Please review this code for bugs, security issues, and style problems."
    
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
            raise APIError(f"GitHub API error: {e}")
        except requests.exceptions.RequestException as e:
            raise APIError(f"GitHub API connection failed: {e}", "Check internet connection")
    
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
            raise APIError(f"OpenAI API error: {e}")
    
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
            raise APIError(f"Anthropic API error: {e}")

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
            raise APIError(f"Failed to get PR details: {e}")

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
            raise APIError(f"Failed to get PR diff: {e}")

    def analyze_code_with_ai(self, diff: str, prompt_template: str) -> List[Dict[str, Any]]:
        """Analyze code diff using AI and return review comments."""
        if self.config.ai_provider == 'openai':
            return self._analyze_with_openai(diff, prompt_template)
        elif self.config.ai_provider == 'anthropic':
            return self._analyze_with_anthropic(diff, prompt_template)
        else:
            raise ConfigError(f"Unknown AI provider: {self.config.ai_provider}")

    def _analyze_with_openai(self, diff: str, prompt_template: str) -> List[Dict[str, Any]]:
        """Analyze code using OpenAI."""
        try:
            prompt = f"{prompt_template}\n\nCode diff:\n{diff}"

            response = self.session.post(
                "https://api.openai.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {self.config.ai_key}"},
                json={
                    "model": self.config.ai_model,
                    "messages": [{"role": "user", "content": prompt}],
                    "max_tokens": 1000
                }
            )
            response.raise_for_status()

            result = response.json()
            analysis = result['choices'][0]['message']['content']

            # Parse analysis into review comments
            return self._parse_ai_analysis(analysis)

        except requests.exceptions.RequestException as e:
            raise APIError(f"OpenAI analysis failed: {e}")

    def _analyze_with_anthropic(self, diff: str, prompt_template: str) -> List[Dict[str, Any]]:
        """Analyze code using Anthropic."""
        try:
            prompt = f"{prompt_template}\n\nCode diff:\n{diff}"

            response = self.session.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": self.config.ai_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json"
                },
                json={
                    "model": self.config.ai_model,
                    "max_tokens": 1000,
                    "messages": [{"role": "user", "content": prompt}]
                }
            )
            response.raise_for_status()

            result = response.json()
            analysis = result['content'][0]['text']

            # Parse analysis into review comments
            return self._parse_ai_analysis(analysis)

        except requests.exceptions.RequestException as e:
            raise APIError(f"Anthropic analysis failed: {e}")

    def _parse_ai_analysis(self, analysis: str) -> List[Dict[str, Any]]:
        """Parse AI analysis into structured review comments."""
        comments = []

        # Simple parsing - look for issues mentioned in the analysis
        lines = analysis.split('\n')
        for line in lines:
            line = line.strip()
            if line and ('issue' in line.lower() or 'problem' in line.lower() or 'bug' in line.lower()):
                comments.append({
                    'body': line,
                    'path': None,  # Would need more sophisticated parsing to determine file
                    'line': None   # Would need more sophisticated parsing to determine line
                })

        return comments

    def post_pr_review(self, repo: str, pr_number: str, comments: List[Dict[str, Any]]) -> None:
        """Post review comments to GitHub PR."""
        try:
            # Create a general review comment
            review_body = "AI Code Review Results:\n\n"
            for i, comment in enumerate(comments, 1):
                review_body += f"{i}. {comment['body']}\n"

            response = self.session.post(
                f"https://api.github.com/repos/{repo}/pulls/{pr_number}/reviews",
                headers={"Authorization": f"token {self.config.github_token}"},
                json={
                    "body": review_body,
                    "event": "COMMENT"
                }
            )
            response.raise_for_status()
            logger.info("Review posted successfully")

        except requests.exceptions.RequestException as e:
            raise APIError(f"Failed to post review: {e}")

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

def review_pr(config: ReviewConfig, repo: str, pr_number: str) -> None:
    """Review a specific PR using AI."""
    logger.info(f"Starting AI review for PR #{pr_number} in {repo}")

    try:
        # Initialize API client
        client = APIClient(config)

        # Get PR details from GitHub
        pr_data = client.get_pr_details(repo, pr_number)
        logger.info(f"Reviewing PR: {pr_data['title']}")

        # Get PR diff
        pr_diff = client.get_pr_diff(repo, pr_number)

        # Analyze with AI
        review_comments = client.analyze_code_with_ai(pr_diff, config.prompt_template)

        # Post review comments
        if review_comments:
            client.post_pr_review(repo, pr_number, review_comments)
            logger.info(f"Posted {len(review_comments)} review comments")
        else:
            logger.info("No issues found - PR looks good!")

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
        
        # Create and validate config
        config = ReviewConfig(
            github_token=github_token,
            ai_provider=ai_provider,
            ai_key=ai_key,
            ai_model="",  # Will be set below
            repo=repo,
            use_coderabbit=True,
            coderabbit_threshold=coderabbit_threshold,
            coderabbit_auto_approve=coderabbit_auto_approve
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
