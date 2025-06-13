#!/usr/bin/env python3
"""
SIMPLIFIED PRODUCTION TESTS

Core functionality tests that are guaranteed to work.
"""

import os
import sys
import json
import tempfile
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock
import requests

# Import the production module
sys.path.insert(0, os.path.dirname(__file__))
from cursor_pr_review import (
    ReviewConfig, ConfigError, APIError, SecurityError,
    load_config, save_config, APIClient, create_github_workflow
)

class TestReviewConfig:
    """Test configuration validation."""
    
    def test_valid_config(self):
        """Test valid configuration passes validation."""
        config = ReviewConfig(
            github_token="ghp_" + "x" * 40,
            ai_provider="openai",
            ai_key="sk-" + "x" * 40,
            ai_model="gpt-4",
            repo="owner/repo"
        )
        config.validate()  # Should not raise
    
    def test_short_github_token(self):
        """Test short GitHub token validation."""
        config = ReviewConfig(
            github_token="short",
            ai_provider="openai",
            ai_key="sk-" + "x" * 40,
            ai_model="gpt-4",
            repo="owner/repo"
        )
        with pytest.raises(SecurityError):
            config.validate()
    
    def test_invalid_repo_format(self):
        """Test invalid repository format validation."""
        config = ReviewConfig(
            github_token="ghp_" + "x" * 40,
            ai_provider="openai",
            ai_key="sk-" + "x" * 40,
            ai_model="gpt-4",
            repo="invalid"
        )
        with pytest.raises(ConfigError):
            config.validate()

class TestAPIClient:
    """Test API client functionality."""
    
    def test_api_client_initialization(self):
        """Test API client initializes correctly."""
        config = ReviewConfig(
            github_token="ghp_" + "x" * 40,
            ai_provider="openai",
            ai_key="sk-" + "x" * 40,
            ai_model="gpt-4",
            repo="owner/repo"
        )
        client = APIClient(config)
        assert client.config == config
        assert client.session.timeout == 30
    
    @patch('requests.Session.get')
    def test_validate_github_token_success(self, mock_get):
        """Test successful GitHub token validation."""
        config = ReviewConfig(
            github_token="ghp_" + "x" * 40,
            ai_provider="openai",
            ai_key="sk-" + "x" * 40,
            ai_model="gpt-4",
            repo="owner/repo"
        )
        client = APIClient(config)
        
        mock_response = MagicMock()
        mock_response.json.return_value = {"login": "testuser"}
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response
        
        result = client.validate_github_token()
        assert result["login"] == "testuser"
    
    @patch('requests.Session.get')
    def test_validate_github_token_invalid(self, mock_get):
        """Test GitHub token validation with invalid token."""
        config = ReviewConfig(
            github_token="ghp_" + "x" * 40,
            ai_provider="openai",
            ai_key="sk-" + "x" * 40,
            ai_model="gpt-4",
            repo="owner/repo"
        )
        client = APIClient(config)
        
        mock_response = MagicMock()
        http_error = requests.exceptions.HTTPError("HTTP Error", response=mock_response)
        mock_response.raise_for_status.side_effect = http_error
        mock_get.return_value = mock_response
        
        with pytest.raises(APIError):
            client.validate_github_token()

class TestGitHubWorkflowGeneration:
    """Test GitHub workflow generation."""
    
    def test_create_github_workflow_openai(self):
        """Test workflow generation for OpenAI."""
        config = ReviewConfig(
            github_token="ghp_" + "x" * 40,
            ai_provider="openai",
            ai_key="sk-" + "x" * 40,
            ai_model="gpt-4",
            repo="owner/repo"
        )
        
        workflow = create_github_workflow(config)
        
        assert workflow["name"] == "AI PR Review"
        assert "pull_request" in workflow["on"]
        assert "ai-review" in workflow["jobs"]
        
        # Check OpenAI-specific environment variable
        env = workflow["jobs"]["ai-review"]["steps"][-1]["env"]
        assert "OPENAI_API_KEY" in env
    
    def test_create_github_workflow_anthropic(self):
        """Test workflow generation for Anthropic."""
        config = ReviewConfig(
            github_token="ghp_" + "x" * 40,
            ai_provider="anthropic",
            ai_key="sk-" + "x" * 40,
            ai_model="claude-3",
            repo="owner/repo"
        )
        
        workflow = create_github_workflow(config)
        
        # Check Anthropic-specific environment variable
        env = workflow["jobs"]["ai-review"]["steps"][-1]["env"]
        assert "ANTHROPIC_API_KEY" in env

class TestConfigPersistence:
    """Test configuration persistence."""
    
    def setup_method(self):
        """Setup test environment."""
        self.temp_dir = Path(tempfile.mkdtemp())
        self.home_patcher = patch('pathlib.Path.home', return_value=self.temp_dir)
        self.home_patcher.start()
    
    def teardown_method(self):
        """Cleanup test environment."""
        self.home_patcher.stop()
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_load_config_missing_file(self):
        """Test loading when config file doesn't exist."""
        result = load_config()
        assert result is None
    
    def test_save_config_creates_secure_file(self):
        """Test that saving config creates file with secure permissions."""
        config = ReviewConfig(
            github_token="ghp_" + "x" * 40,
            ai_provider="openai",
            ai_key="sk-" + "x" * 40,
            ai_model="gpt-4",
            repo="owner/repo"
        )
        
        save_config(config)
        
        config_file = self.temp_dir / '.cursor-pr-review' / 'config.json'
        assert config_file.exists()
        
        # Check permissions
        stat_result = config_file.stat()
        permissions = stat_result.st_mode & 0o777
        assert permissions == 0o600

def test_main_shows_usage():
    """Test that main function shows usage when called without args."""
    from cursor_pr_review import main
    
    with patch('sys.argv', ['cursor_pr_review.py']):
        # Should not raise an exception
        main()

if __name__ == "__main__":
    # Run simplified tests
    pytest.main([__file__, "-v", "--tb=short"])