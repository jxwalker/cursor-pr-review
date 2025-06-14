#!/usr/bin/env python3
"""
CURSOR PR REVIEW - SIMPLE AI CODE REVIEWER FOR VIBE CODERS

⚠️ COMPLEXITY WARNING ⚠️
This code has been refactored TWICE to remove complexity.
DO NOT ADD:
- Complex parsing systems
- Multiple abstraction layers  
- Issue deduplication
- Enhanced analyzers
- Complicated formatters

KEEP IT SIMPLE. IT WORKS.

History of doom:
v1: Simple → Complex → Broken
v2: Refactored to simple → Complex → Broken  
v3: THIS VERSION. KEEP. IT. SIMPLE.
"""

import os
import sys
import re
import json
import requests
import argparse
from pathlib import Path
from typing import List, Dict, Any, Optional


class SimpleReviewer:
    """Dead simple PR reviewer that actually works."""
    
    def __init__(self, github_token: str, ai_key: str, ai_provider: str = "openai", prompt_type: str = "default"):
        self.github_token = github_token
        self.ai_key = ai_key
        self.ai_provider = ai_provider
        self.prompt_type = prompt_type
        
    def review_pr(self, repo: str, pr_number: int) -> None:
        """Review a PR and post comments."""
        print(f"🔍 Reviewing PR #{pr_number} in {repo}...")
        
        # Get the diff
        diff = self._get_diff(repo, pr_number)
        if not diff:
            print("❌ No diff found")
            return
            
        # Get AI analysis
        print("🤖 Analyzing code...")
        issues = self._analyze_diff(diff)
        
        if not issues:
            print("✅ No issues found!")
            self._post_approval(repo, pr_number)
            return
            
        # Post review
        print(f"📝 Posting {len(issues)} comments...")
        self._post_review(repo, pr_number, issues)
        
    def _get_diff(self, repo: str, pr_number: int) -> str:
        """Get PR diff."""
        url = f"https://api.github.com/repos/{repo}/pulls/{pr_number}"
        headers = {"Authorization": f"token {self.github_token}"}
        
        response = requests.get(url, headers=headers)
        if response.status_code != 200:
            print(f"Failed to get PR: {response.status_code}")
            return ""
            
        pr_data = response.json()
        diff_url = pr_data['diff_url']
        
        response = requests.get(diff_url, headers=headers)
        return response.text if response.status_code == 200 else ""
        
    def _analyze_diff(self, diff: str) -> List[Dict[str, Any]]:
        """Analyze diff with AI."""
        # Extract only added lines and their locations
        files_content = self._parse_diff(diff)
        if not files_content:
            return []
            
        # Build simple prompt
        prompt = self._build_prompt(files_content)
        
        # Call AI
        if self.ai_provider == "openai":
            response = self._call_openai(prompt)
        else:
            response = self._call_anthropic(prompt)
            
        if not response:
            return []
            
        # Parse simple format
        return self._parse_ai_response(response)
        
    def _parse_diff(self, diff: str) -> Dict[str, List[tuple]]:
        """Parse diff into files and their added lines."""
        files_content = {}
        current_file = None
        base_line = 0
        
        for line in diff.split('\n'):
            # New file
            if line.startswith('+++'):
                current_file = line[6:].strip() if line[6:].strip() != '/dev/null' else None
                if current_file and current_file.startswith('b/'):
                    current_file = current_file[2:]
                if current_file:
                    files_content[current_file] = []
                    
            # Line numbers
            elif line.startswith('@@'):
                match = re.search(r'\+(\d+)', line)
                if match:
                    base_line = int(match.group(1)) - 1
                    
            # Added line
            elif line.startswith('+') and not line.startswith('+++'):
                if current_file:
                    base_line += 1
                    files_content[current_file].append((base_line, line[1:]))
            elif not line.startswith('-'):
                base_line += 1
                
        return files_content
        
    def _build_prompt(self, files_content: Dict[str, List[tuple]]) -> str:
        """Build a simple, effective prompt."""
        prompts = {
            "brutal": """You are BRUTAL CODE REVIEWER. Review this code with ZERO tolerance for bad practices.

For EACH issue, use EXACTLY this format:
```
FILE: filename.py
LINE: 42
ISSUE: What's wrong (be harsh but accurate)
FIX: How to fix it (be specific)
```

Look for: security holes, bad practices, demo code in production, error handling failures.
BE BRUTAL. Here's the code:

""",
            "lenient": """You are a friendly code reviewer. Only report CRITICAL issues that would break production.

For EACH critical issue, respond in EXACTLY this format:
```
FILE: filename.py
LINE: 42
ISSUE: Brief description
FIX: Quick solution
```

Be lenient - only major problems. Here's the code:

""",
            "security": """You are a security-focused code reviewer. Find ALL security vulnerabilities.

For EACH security issue, respond in EXACTLY this format:
```
FILE: filename.py
LINE: 42
ISSUE: Security vulnerability description
FIX: Secure solution
```

Focus on: injection, auth, secrets, crypto, input validation. Here's the code:

""",
            "default": """You are a code reviewer for vibe coders. Review this code for:
1. Security issues (SQL injection, hardcoded secrets, eval/exec, etc)
2. Obvious bugs
3. Major problems

For EACH issue found, respond in EXACTLY this format:
```
FILE: filename.py
LINE: 42
ISSUE: Clear description of the problem
FIX: Specific solution
```

Only report real issues. Be concise. Here's the code to review:

"""
        }
        
        prompt = prompts.get(self.prompt_type, prompts["default"])
        
        for filename, lines in files_content.items():
            if lines:
                prompt += f"\n=== {filename} ===\n"
                for line_num, content in lines:
                    prompt += f"{line_num}: {content}\n"
                    
        return prompt
        
    def _call_openai(self, prompt: str) -> Optional[str]:
        """Call OpenAI API."""
        response = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {self.ai_key}",
                "Content-Type": "application/json"
            },
            json={
                "model": "gpt-4o",
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.3
            }
        )
        
        if response.status_code != 200:
            print(f"OpenAI error: {response.status_code}")
            return None
            
        result = response.json()
        return result['choices'][0]['message']['content']
        
    def _call_anthropic(self, prompt: str) -> Optional[str]:
        """Call Anthropic API."""
        response = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": self.ai_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json"
            },
            json={
                "model": "claude-3-sonnet-20240229",
                "max_tokens": 1500,
                "messages": [{"role": "user", "content": prompt}]
            }
        )
        
        if response.status_code != 200:
            print(f"Anthropic error: {response.status_code}")
            return None
            
        result = response.json()
        return result['content'][0]['text']
        
    def _parse_ai_response(self, response: str) -> List[Dict[str, Any]]:
        """Parse AI response into issues."""
        issues = []
        
        # Find all issue blocks
        pattern = r'FILE:\s*(.+?)\nLINE:\s*(\d+)\nISSUE:\s*(.+?)\nFIX:\s*(.+?)(?=\n(?:FILE:|$))'
        matches = re.findall(pattern, response, re.DOTALL)
        
        for match in matches:
            filename, line_num, issue_desc, fix_desc = match
            issues.append({
                'path': filename.strip(),
                'line': int(line_num.strip()),
                'body': f"**{issue_desc.strip()}**\n\n{fix_desc.strip()}"
            })
            
        return issues
        
    def _post_review(self, repo: str, pr_number: int, issues: List[Dict[str, Any]]) -> None:
        """Post review comments."""
        if not issues:
            return
            
        # Get latest commit
        url = f"https://api.github.com/repos/{repo}/pulls/{pr_number}"
        headers = {"Authorization": f"token {self.github_token}"}
        response = requests.get(url, headers=headers)
        
        if response.status_code != 200:
            print("Failed to get PR details")
            return
            
        commit_sha = response.json()['head']['sha']
        
        # Create review
        review_body = f"# 🤖 AI Code Review\n\nFound {len(issues)} issue(s) that need attention."
        
        # Build review comments
        comments = []
        for issue in issues:
            comments.append({
                'path': issue['path'],
                'line': issue['line'],
                'body': issue['body']
            })
            
        # Post the review
        review_url = f"https://api.github.com/repos/{repo}/pulls/{pr_number}/reviews"
        review_data = {
            'commit_id': commit_sha,
            'body': review_body,
            'event': 'COMMENT',
            'comments': comments
        }
        
        response = requests.post(review_url, headers=headers, json=review_data)
        
        if response.status_code == 200:
            print(f"✅ Posted review with {len(issues)} comments")
        else:
            print(f"❌ Failed to post review: {response.status_code}")
            print(response.json())
            
    def _post_approval(self, repo: str, pr_number: int) -> None:
        """Post approval when no issues found."""
        url = f"https://api.github.com/repos/{repo}/pulls/{pr_number}"
        headers = {"Authorization": f"token {self.github_token}"}
        response = requests.get(url, headers=headers)
        
        if response.status_code != 200:
            return
            
        commit_sha = response.json()['head']['sha']
        
        review_url = f"https://api.github.com/repos/{repo}/pulls/{pr_number}/reviews"
        review_data = {
            'commit_id': commit_sha,
            'body': "# ✅ AI Code Review\n\nNo issues found! This code looks good to merge.",
            'event': 'APPROVE'
        }
        
        response = requests.post(review_url, headers=headers, json=review_data)
        if response.status_code == 200:
            print("✅ Posted approval")


# Configuration management
class Config:
    """Simple configuration."""
    def __init__(self):
        self.github_token = None
        self.ai_provider = "openai"
        self.ai_key = None
        self.prompt_type = "default"
        
    def load_from_file(self) -> bool:
        """Load config from file."""
        config_file = Path.home() / '.cursor-pr-review' / 'config.json'
        if not config_file.exists():
            return False
            
        try:
            with open(config_file) as f:
                data = json.load(f)
            self.github_token = data.get('github_token')
            self.ai_provider = data.get('ai_provider', 'openai')
            self.ai_key = data.get('ai_key')
            self.prompt_type = data.get('prompt_type', 'default')
            return True
        except:
            return False
            
    def load_from_env(self) -> bool:
        """Load config from environment."""
        self.github_token = os.environ.get('GITHUB_TOKEN')
        self.ai_key = os.environ.get('OPENAI_API_KEY') or os.environ.get('ANTHROPIC_API_KEY')
        
        if os.environ.get('ANTHROPIC_API_KEY'):
            self.ai_provider = "anthropic"
            
        self.prompt_type = os.environ.get('REVIEW_PROMPT_TYPE', 'default')
        
        return bool(self.github_token and self.ai_key)
        
    def save_to_file(self) -> None:
        """Save config to file."""
        config_dir = Path.home() / '.cursor-pr-review'
        config_dir.mkdir(exist_ok=True)
        
        config_file = config_dir / 'config.json'
        with open(config_file, 'w') as f:
            json.dump({
                'github_token': self.github_token,
                'ai_provider': self.ai_provider,
                'ai_key': self.ai_key,
                'prompt_type': self.prompt_type
            }, f, indent=2)


def setup_interactive():
    """Interactive setup."""
    print("🚀 Cursor PR Review Setup")
    print("-" * 40)
    
    config = Config()
    
    # GitHub token
    print("\n1. GitHub Token")
    print("   Create at: https://github.com/settings/tokens")
    print("   Needs: repo (all), write:discussion")
    config.github_token = input("Enter GitHub token: ").strip()
    
    # AI provider
    print("\n2. AI Provider")
    print("   1) OpenAI (recommended)")
    print("   2) Anthropic")
    choice = input("Choose (1/2): ").strip()
    
    if choice == "2":
        config.ai_provider = "anthropic"
        print("\n3. Anthropic API Key")
        print("   Get at: https://console.anthropic.com/")
        config.ai_key = input("Enter Anthropic API key: ").strip()
    else:
        config.ai_provider = "openai"
        print("\n3. OpenAI API Key")
        print("   Get at: https://platform.openai.com/")
        config.ai_key = input("Enter OpenAI API key: ").strip()
        
    # Save config
    config.save_to_file()
    print("\n✅ Setup complete! Config saved to ~/.cursor-pr-review/config.json")
    print("\nUsage: python cursor_pr_review.py review-pr <owner/repo> <pr_number>")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Simple AI PR reviewer for vibe coders")
    parser.add_argument('command', choices=['setup', 'review-pr'], help='Command to run')
    parser.add_argument('repo', nargs='?', help='Repository (owner/repo)')
    parser.add_argument('pr_number', nargs='?', type=int, help='PR number')
    parser.add_argument('--prompt', choices=['default', 'brutal', 'lenient', 'security'], 
                       default='default', help='Review style')
    
    args = parser.parse_args()
    
    if args.command == 'setup':
        setup_interactive()
        return
        
    if args.command == 'review-pr':
        if not args.repo or not args.pr_number:
            print("Usage: python cursor_pr_review.py review-pr <owner/repo> <pr_number>")
            sys.exit(1)
            
        # Load config
        config = Config()
        if not config.load_from_env() and not config.load_from_file():
            print("❌ No configuration found. Run 'python cursor_pr_review.py setup' first")
            sys.exit(1)
            
        # Override prompt type if specified
        if args.prompt:
            config.prompt_type = args.prompt
            
        # Create reviewer and run
        reviewer = SimpleReviewer(
            config.github_token, 
            config.ai_key,
            config.ai_provider,
            config.prompt_type
        )
        reviewer.review_pr(args.repo, args.pr_number)


if __name__ == "__main__":
    main()