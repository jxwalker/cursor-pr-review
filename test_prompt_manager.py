#!/usr/bin/env python3
"""
COMPREHENSIVE TESTS FOR PROMPT MANAGEMENT SYSTEM

Tests for prompt CRUD, versioning, history, and CLI functionality.
"""

import os
import sys
import json
import tempfile
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(__file__))

from prompt_manager import PromptManager, PromptMetadata, PromptVersion, PromptDefaults
from prompt_cli import PromptCLI

class TestPromptVersion:
    """Test PromptVersion data structure."""
    
    def test_create_prompt_version(self):
        """Test creating a new prompt version."""
        content = "Test prompt content for review"
        created_by = "testuser"
        change_reason = "Initial version"
        
        version = PromptVersion.create(content, created_by, change_reason)
        
        assert version.version == 1
        assert version.content == content
        assert version.created_by == created_by
        assert version.change_reason == change_reason
        assert len(version.content_hash) == 16
        assert version.size == len(content)
        assert isinstance(version.created_at, str)
    
    def test_prompt_version_with_custom_version_number(self):
        """Test creating prompt version with custom version number."""
        version = PromptVersion.create("content", "user", "reason", 5)
        assert version.version == 5

class TestPromptMetadata:
    """Test PromptMetadata data structure."""
    
    def test_create_builtin_metadata(self):
        """Test creating built-in prompt metadata."""
        metadata = PromptMetadata.create_builtin(
            "test_builtin", "Test Builtin", "A test prompt", "general"
        )
        
        assert metadata.id == "test_builtin"
        assert metadata.name == "Test Builtin"
        assert metadata.is_builtin is True
        assert metadata.is_active is True
        assert metadata.prompt_type == "general"
        assert metadata.language == "general"
        assert "builtin" in metadata.tags
        assert metadata.created_by == "system"
    
    def test_create_custom_metadata(self):
        """Test creating custom prompt metadata."""
        metadata = PromptMetadata.create_custom(
            "Custom Prompt", "A custom test prompt", "security", "python", "testuser", ["tag1", "tag2"]
        )
        
        assert metadata.name == "Custom Prompt"
        assert metadata.is_builtin is False
        assert metadata.is_active is True
        assert metadata.prompt_type == "security"
        assert metadata.language == "python"
        assert metadata.tags == ["tag1", "tag2"]
        assert metadata.created_by == "testuser"
        assert metadata.id.startswith("custom_")
    
    def test_add_version_to_metadata(self):
        """Test adding versions to prompt metadata."""
        metadata = PromptMetadata.create_custom(
            "Test", "Test prompt", "general", "general", "user"
        )
        
        # Add first version
        version1 = metadata.add_version("First content", "user", "Initial")
        assert version1.version == 1
        assert metadata.current_version == 1
        assert len(metadata.versions) == 1
        
        # Add second version
        version2 = metadata.add_version("Second content", "user", "Update")
        assert version2.version == 2
        assert metadata.current_version == 2
        assert len(metadata.versions) == 2
    
    def test_get_current_content(self):
        """Test getting current content from metadata."""
        metadata = PromptMetadata.create_custom(
            "Test", "Test prompt", "general", "general", "user"
        )
        
        # No versions yet
        assert metadata.get_current_content() == ""
        
        # Add version
        metadata.add_version("Test content", "user", "Initial")
        assert metadata.get_current_content() == "Test content"

class TestPromptDefaults:
    """Test PromptDefaults functionality."""
    
    def test_set_and_get_default(self):
        """Test setting and getting default prompts."""
        defaults = PromptDefaults()
        
        defaults.set_default("security", "python", "sec_prompt_1")
        defaults.set_default("general", "javascript", "gen_prompt_1")
        
        assert defaults.get_default("security", "python") == "sec_prompt_1"
        assert defaults.get_default("general", "javascript") == "gen_prompt_1"
        assert defaults.get_default("nonexistent", "python") is None
    
    def test_fallback_to_general_language(self):
        """Test fallback to general language for defaults."""
        defaults = PromptDefaults()
        
        defaults.set_default("security", "general", "general_sec_prompt")
        
        # Should fallback to general when specific language not found
        assert defaults.get_default("security", "go") == "general_sec_prompt"
        assert defaults.get_default("security", "general") == "general_sec_prompt"

class TestPromptManager:
    """Test PromptManager functionality."""
    
    def setup_method(self):
        """Setup test environment."""
        self.temp_dir = Path(tempfile.mkdtemp())
        self.home_patcher = patch('pathlib.Path.home', return_value=self.temp_dir)
        self.home_patcher.start()
        
        # Create prompts directory with test files
        self.prompts_dir = Path('prompts')
        self.prompts_dir.mkdir(exist_ok=True)
        
        test_prompts = {
            'default.txt': 'Default prompt for testing with security and bug detection',
            'strict.txt': 'Strict prompt for comprehensive analysis',
            'security-focused.txt': 'Security-focused prompt with vulnerability detection'
        }
        
        for filename, content in test_prompts.items():
            (self.prompts_dir / filename).write_text(content)
        
        self.manager = PromptManager()
    
    def teardown_method(self):
        """Cleanup test environment."""
        self.home_patcher.stop()
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
        shutil.rmtree(self.prompts_dir, ignore_errors=True)
    
    def test_manager_initialization(self):
        """Test PromptManager initialization."""
        assert isinstance(self.manager, PromptManager)
        assert self.manager.data_dir.exists()
        
        # Should have built-in prompts
        builtin_prompts = [p for p in self.manager.list_prompts() if p.is_builtin]
        assert len(builtin_prompts) > 0
        
        # Check specific built-ins
        default_prompt = self.manager.get_prompt('default')
        assert default_prompt is not None
        assert default_prompt.is_builtin is True
    
    def test_list_prompts_filtering(self):
        """Test listing prompts with filtering."""
        # Create a custom prompt
        self.manager.create_prompt(
            "Custom Security", "Custom security prompt", "Custom security content",
            "security", "python", ["custom"], "testuser"
        )
        
        # Test type filtering
        security_prompts = self.manager.list_prompts(prompt_type="security")
        assert len(security_prompts) >= 1
        assert all(p.prompt_type == "security" for p in security_prompts)
        
        # Test language filtering
        python_prompts = self.manager.list_prompts(language="python")
        assert len(python_prompts) >= 1
        
        # Test include inactive
        all_prompts = self.manager.list_prompts(include_inactive=True)
        active_prompts = self.manager.list_prompts(include_inactive=False)
        assert len(all_prompts) >= len(active_prompts)
    
    def test_create_custom_prompt(self):
        """Test creating custom prompts."""
        metadata = self.manager.create_prompt(
            "Test Custom", "Test description", "Test content for custom prompt",
            "performance", "javascript", ["test", "custom"], "testuser", "Initial creation"
        )
        
        assert metadata.name == "Test Custom"
        assert metadata.prompt_type == "performance"
        assert metadata.language == "javascript"
        assert metadata.tags == ["test", "custom"]
        assert metadata.is_builtin is False
        assert metadata.is_active is True
        assert metadata.current_version == 1
        assert metadata.get_current_content() == "Test content for custom prompt"
        
        # Should be saved and retrievable
        retrieved = self.manager.get_prompt(metadata.id)
        assert retrieved is not None
        assert retrieved.name == "Test Custom"
    
    def test_update_prompt(self):
        """Test updating prompt content."""
        # Create a custom prompt
        metadata = self.manager.create_prompt(
            "Updatable", "Test prompt", "Original content", "general", "general", [], "user"
        )
        
        # Update it
        new_version = self.manager.update_prompt(
            metadata.id, "Updated content", "user", "Content improvement"
        )
        
        assert new_version.version == 2
        assert new_version.content == "Updated content"
        assert new_version.change_reason == "Content improvement"
        assert metadata.current_version == 2
        assert metadata.get_current_content() == "Updated content"
    
    def test_update_builtin_fails(self):
        """Test that updating built-in prompts fails."""
        with pytest.raises(ValueError, match="Cannot modify built-in prompt"):
            self.manager.update_prompt("default", "New content", "user")
    
    def test_update_nonexistent_fails(self):
        """Test that updating non-existent prompt fails."""
        with pytest.raises(ValueError, match="not found"):
            self.manager.update_prompt("nonexistent", "Content", "user")
    
    def test_update_with_same_content_fails(self):
        """Test that updating with same content fails."""
        metadata = self.manager.create_prompt(
            "Same Content", "Test", "Original content", "general", "general", [], "user"
        )
        
        with pytest.raises(ValueError, match="No changes detected"):
            self.manager.update_prompt(metadata.id, "Original content", "user")
    
    def test_delete_prompt(self):
        """Test deleting custom prompts."""
        # Create a custom prompt
        metadata = self.manager.create_prompt(
            "Deletable", "Test prompt", "Content", "general", "general", [], "user"
        )
        
        assert metadata.is_active is True
        
        # Delete it
        self.manager.delete_prompt(metadata.id, "user")
        
        # Should be marked inactive
        updated_metadata = self.manager.get_prompt(metadata.id)
        assert updated_metadata.is_active is False
        
        # Should not appear in active lists
        active_prompts = self.manager.list_prompts(include_inactive=False)
        assert not any(p.id == metadata.id for p in active_prompts)
        
        # Should appear in inactive lists
        all_prompts = self.manager.list_prompts(include_inactive=True)
        assert any(p.id == metadata.id for p in all_prompts)
    
    def test_delete_builtin_fails(self):
        """Test that deleting built-in prompts fails."""
        with pytest.raises(ValueError, match="Cannot delete built-in prompt"):
            self.manager.delete_prompt("default", "user")
    
    def test_rollback_prompt(self):
        """Test rolling back to previous version."""
        # Create and update a prompt
        metadata = self.manager.create_prompt(
            "Rollback Test", "Test", "Version 1", "general", "general", [], "user"
        )
        self.manager.update_prompt(metadata.id, "Version 2", "user", "Second version")
        self.manager.update_prompt(metadata.id, "Version 3", "user", "Third version")
        
        assert metadata.current_version == 3
        assert metadata.get_current_content() == "Version 3"
        
        # Rollback to version 1
        new_version = self.manager.rollback_prompt(metadata.id, 1, "user")
        
        assert new_version.version == 4  # New version created
        assert new_version.content == "Version 1"  # Content from version 1
        assert "Rolled back to version 1" in new_version.change_reason
        assert metadata.current_version == 4
        assert metadata.get_current_content() == "Version 1"
    
    def test_rollback_builtin_fails(self):
        """Test that rolling back built-in prompts fails."""
        with pytest.raises(ValueError, match="Cannot rollback built-in prompt"):
            self.manager.rollback_prompt("default", 1, "user")
    
    def test_rollback_nonexistent_version_fails(self):
        """Test that rolling back to non-existent version fails."""
        metadata = self.manager.create_prompt(
            "Test", "Test", "Content", "general", "general", [], "user"
        )
        
        with pytest.raises(ValueError, match="Version 999 not found"):
            self.manager.rollback_prompt(metadata.id, 999, "user")
    
    def test_get_prompt_diff(self):
        """Test getting diff between versions."""
        # Create and update a prompt
        metadata = self.manager.create_prompt(
            "Diff Test", "Test", "Line 1\nLine 2\nLine 3", "general", "general", [], "user"
        )
        self.manager.update_prompt(metadata.id, "Line 1\nLine 2 Modified\nLine 3", "user", "Changed line 2")
        
        # Get diff
        diff = self.manager.get_prompt_diff(metadata.id, 1, 2)
        
        assert "Line 2" in diff
        assert "Line 2 Modified" in diff
        assert "@@" in diff  # Unified diff format
    
    def test_set_and_get_default_prompt(self):
        """Test setting and getting default prompts."""
        # Create a custom prompt
        metadata = self.manager.create_prompt(
            "Default Test", "Test", "Content", "security", "python", [], "user"
        )
        
        # Set as default
        self.manager.set_default_prompt("security", "python", metadata.id, "user")
        
        # Should be retrievable as default
        default_id = self.manager.get_default_prompt("security", "python")
        assert default_id == metadata.id
    
    def test_set_default_nonexistent_fails(self):
        """Test that setting non-existent prompt as default fails."""
        with pytest.raises(ValueError, match="not found"):
            self.manager.set_default_prompt("security", "python", "nonexistent", "user")
    
    def test_validate_prompt_content(self):
        """Test prompt content validation."""
        # Short content
        issues = self.manager.validate_prompt_content("Short")
        assert any("very short" in issue for issue in issues)
        
        # Long content
        long_content = "x" * 15000
        issues = self.manager.validate_prompt_content(long_content)
        assert any("very long" in issue for issue in issues)
        
        # Missing patterns
        issues = self.manager.validate_prompt_content("This prompt has no important keywords")
        assert any("Consider including guidance" in issue for issue in issues)
        
        # Good content
        good_content = "Review for security issues, bugs, errors, and general issues. " * 2
        issues = self.manager.validate_prompt_content(good_content)
        assert len(issues) == 0
    
    def test_get_prompt_history(self):
        """Test getting prompt history."""
        # Create and modify a prompt
        metadata = self.manager.create_prompt(
            "History Test", "Test", "Content", "general", "general", [], "user"
        )
        self.manager.update_prompt(metadata.id, "Updated", "user", "Update")
        self.manager.delete_prompt(metadata.id, "user")
        
        # Get history
        history = self.manager.get_prompt_history(metadata.id)
        
        assert len(history) >= 3  # create, update, delete
        assert any(entry['action'] == 'create' for entry in history)
        assert any(entry['action'] == 'update' for entry in history)
        assert any(entry['action'] == 'delete' for entry in history)
        
        # Should be sorted by timestamp (newest first)
        timestamps = [entry['timestamp'] for entry in history]
        assert timestamps == sorted(timestamps, reverse=True)

class TestPromptCLI:
    """Test PromptCLI functionality."""
    
    def setup_method(self):
        """Setup test environment."""
        self.temp_dir = Path(tempfile.mkdtemp())
        self.home_patcher = patch('pathlib.Path.home', return_value=self.temp_dir)
        self.home_patcher.start()
        
        # Create prompts directory
        self.prompts_dir = Path('prompts')
        self.prompts_dir.mkdir(exist_ok=True)
        (self.prompts_dir / 'default.txt').write_text('Default prompt for testing')
        
        self.cli = PromptCLI()
    
    def teardown_method(self):
        """Cleanup test environment."""
        self.home_patcher.stop()
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
        shutil.rmtree(self.prompts_dir, ignore_errors=True)
    
    @patch('builtins.print')
    def test_list_prompts_output(self, mock_print):
        """Test CLI list prompts output."""
        self.cli.list_prompts()
        
        # Check that output was generated
        assert mock_print.called
        # Handle different call structures more safely
        print_calls = []
        for call in mock_print.call_args_list:
            if call[0]:  # Check if args exist
                print_calls.append(str(call[0][0]))
        output = ' '.join(print_calls)
        
        assert "Prompt Library" in output or "prompts" in output.lower()
        assert "default" in output
    
    @patch('builtins.print')
    def test_view_prompt_output(self, mock_print):
        """Test CLI view prompt output."""
        self.cli.view_prompt('default')
        
        # Check that detailed output was generated
        assert mock_print.called
        print_calls = []
        for call in mock_print.call_args_list:
            if call[0]:  # Check if args exist
                print_calls.append(str(call[0][0]))
        output = ' '.join(print_calls)
        
        assert "default" in output
        assert "Content:" in output
    
    @patch('builtins.print')
    def test_view_nonexistent_prompt(self, mock_print):
        """Test viewing non-existent prompt."""
        self.cli.view_prompt('nonexistent')
        
        print_calls = []
        for call in mock_print.call_args_list:
            if call[0]:  # Check if args exist
                print_calls.append(str(call[0][0]))
        output = ' '.join(print_calls)
        
        assert "not found" in output
    
    @patch('builtins.input')
    @patch('builtins.print')
    def test_delete_prompt_confirmation(self, mock_print, mock_input):
        """Test delete prompt with confirmation."""
        # Create a prompt to delete
        metadata = self.cli.manager.create_prompt(
            "To Delete", "Test", "Content", "general", "general", [], "user"
        )
        
        # Mock user saying 'no' to confirmation
        mock_input.return_value = "no"
        self.cli.delete_prompt(metadata.id)
        
        # Should still be active
        updated = self.cli.manager.get_prompt(metadata.id)
        assert updated.is_active is True
        
        # Mock user saying 'yes' to confirmation
        mock_input.return_value = "yes"
        self.cli.delete_prompt(metadata.id)
        
        # Should now be inactive
        updated = self.cli.manager.get_prompt(metadata.id)
        assert updated.is_active is False
    
    @patch('builtins.print')
    def test_show_history_output(self, mock_print):
        """Test showing prompt history."""
        # Create and modify a prompt
        metadata = self.cli.manager.create_prompt(
            "History Test", "Test", "Content", "general", "general", [], "user"
        )
        
        self.cli.show_history(metadata.id)
        
        print_calls = []
        for call in mock_print.call_args_list:
            if call[0]:  # Check if args exist
                print_calls.append(str(call[0][0]))
        output = ' '.join(print_calls)
        
        assert "History:" in output
        assert "create" in output
    
    @patch('os.getenv')
    @patch('builtins.print')
    def test_set_default_success(self, mock_print, mock_getenv):
        """Test setting default prompt."""
        mock_getenv.return_value = "testuser"
        
        # Create a prompt
        metadata = self.cli.manager.create_prompt(
            "Default Test", "Test", "Content", "security", "python", [], "user"
        )
        
        self.cli.set_default("security", "python", metadata.id)
        
        print_calls = []
        for call in mock_print.call_args_list:
            if call[0]:  # Check if args exist
                print_calls.append(str(call[0][0]))
        output = ' '.join(print_calls)
        
        assert "Set" in output
        assert "default" in output
        assert metadata.id in output

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])