#!/usr/bin/env python3
"""
PROMPT CLI INTERFACE

Advanced CLI for prompt CRUD operations, versioning, and management.
"""

import os
import sys
import tempfile
import subprocess
from typing import List, Optional
from pathlib import Path

from prompt_manager import PromptManager, PromptMetadata

class PromptCLI:
    """Command-line interface for prompt management."""
    
    def __init__(self):
        self.manager = PromptManager()
    
    def list_prompts(self, prompt_type: str = None, language: str = None, include_inactive: bool = False) -> None:
        """List all prompts with filtering options."""
        prompts = self.manager.list_prompts(prompt_type, language, include_inactive)
        
        if not prompts:
            print("No prompts found matching the criteria.")
            return
        
        print(f"\n📝 Prompt Library ({len(prompts)} prompts)")
        print("=" * 80)
        
        # Group by type for better organization
        by_type = {}
        for prompt in prompts:
            if prompt.prompt_type not in by_type:
                by_type[prompt.prompt_type] = []
            by_type[prompt.prompt_type].append(prompt)
        
        for ptype, type_prompts in sorted(by_type.items()):
            print(f"\n🏷️  {ptype.upper()} ({len(type_prompts)} prompts)")
            print("-" * 60)
            
            for prompt in type_prompts:
                status_icon = "🔧" if prompt.is_builtin else "👤"
                active_icon = "✅" if prompt.is_active else "❌"
                default_icon = "⭐" if self._is_default_prompt(prompt) else "  "
                
                print(f"  {status_icon} {active_icon} {default_icon} {prompt.id:<20} {prompt.name}")
                print(f"      📄 {prompt.description}")
                print(f"      🌐 Language: {prompt.language} | 📊 Versions: {len(prompt.versions)} | 📏 Size: {prompt.size if hasattr(prompt, 'size') else 'N/A'} chars")
                
                if prompt.tags:
                    print(f"      🏷️  Tags: {', '.join(prompt.tags)}")
                print()
        
        print("Legend: 🔧=Built-in 👤=Custom ✅=Active ❌=Inactive ⭐=Default")
        print("\n💡 Use 'prompt view <id>' to see full content")
        print("💡 Use 'prompt create' to create a new prompt")
    
    def view_prompt(self, prompt_id: str, version: Optional[int] = None) -> None:
        """View full prompt content and metadata."""
        metadata = self.manager.get_prompt(prompt_id)
        if not metadata:
            print(f"❌ Prompt '{prompt_id}' not found")
            return
        
        # Get specific version or current
        if version:
            target_version = next((v for v in metadata.versions if v.version == version), None)
            if not target_version:
                print(f"❌ Version {version} not found for prompt '{prompt_id}'")
                return
            content = target_version.content
            version_info = f" (Version {version})"
        else:
            content = metadata.get_current_content()
            version_info = f" (Version {metadata.current_version})"
        
        print(f"\n📝 {metadata.name}{version_info}")
        print("=" * 80)
        print(f"🆔 ID: {metadata.id}")
        print(f"📄 Description: {metadata.description}")
        print(f"🏷️  Type: {metadata.prompt_type}")
        print(f"🌐 Language: {metadata.language}")
        print(f"👤 Created by: {metadata.created_by}")
        print(f"📅 Created: {metadata.created_at}")
        print(f"📅 Updated: {metadata.updated_at}")
        print(f"📊 Current Version: {metadata.current_version}")
        print(f"📏 Size: {len(content)} characters")
        
        if metadata.tags:
            print(f"🏷️  Tags: {', '.join(metadata.tags)}")
        
        if self._is_default_prompt(metadata):
            print("⭐ This is a default prompt for some configurations")
        
        print("\n📄 Content:")
        print("-" * 80)
        print(content)
        print("-" * 80)
        
        if metadata.versions:
            print(f"\n📊 Version History ({len(metadata.versions)} versions):")
            for v in sorted(metadata.versions, key=lambda x: x.version, reverse=True):
                current_marker = " ← Current" if v.version == metadata.current_version else ""
                print(f"  v{v.version}: {v.created_at} by {v.created_by} - {v.change_reason}{current_marker}")
        
        print(f"\n💡 Use 'prompt history {prompt_id}' for detailed change history")
        print(f"💡 Use 'prompt edit {prompt_id}' to modify this prompt")
    
    def create_prompt(self) -> None:
        """Interactive wizard to create a new prompt."""
        print("\n🎨 Create New Prompt")
        print("=" * 40)
        
        # Gather metadata
        name = input("Name: ").strip()
        if not name:
            print("❌ Name is required")
            return
        
        description = input("Description: ").strip()
        if not description:
            print("❌ Description is required")
            return
        
        # Prompt type
        print("\nPrompt Types:")
        types = ['general', 'security', 'performance', 'strict', 'lenient', 'custom']
        for i, ptype in enumerate(types, 1):
            print(f"  {i}. {ptype}")
        
        type_choice = input(f"Choose type (1-{len(types)}) [1]: ").strip()
        try:
            type_idx = int(type_choice) - 1 if type_choice else 0
            prompt_type = types[type_idx] if 0 <= type_idx < len(types) else 'general'
        except ValueError:
            prompt_type = 'general'
        
        # Language
        print("\nLanguages:")
        languages = ['general', 'python', 'javascript', 'java', 'go', 'rust', 'typescript']
        for i, lang in enumerate(languages, 1):
            print(f"  {i}. {lang}")
        
        lang_choice = input(f"Choose language (1-{len(languages)}) [1]: ").strip()
        try:
            lang_idx = int(lang_choice) - 1 if lang_choice else 0
            language = languages[lang_idx] if 0 <= lang_idx < len(languages) else 'general'
        except ValueError:
            language = 'general'
        
        # Tags
        tags_input = input("Tags (comma-separated, optional): ").strip()
        tags = [t.strip() for t in tags_input.split(',') if t.strip()] if tags_input else []
        
        # Content creation
        print("\n📝 Content Creation")
        print("Choose how to create the prompt content:")
        print("  1. Type directly (multi-line)")
        print("  2. Open in external editor")
        print("  3. Load from file")
        
        content_choice = input("Choice (1-3) [2]: ").strip()
        
        content = ""
        if content_choice == "1":
            content = self._get_multiline_input()
        elif content_choice == "3":
            content = self._load_from_file()
        else:  # Default to editor
            content = self._edit_in_external_editor()
        
        if not content or not content.strip():
            print("❌ Content is required")
            return
        
        # Validation
        issues = self.manager.validate_prompt_content(content)
        if issues:
            print("\n⚠️  Validation Warnings:")
            for issue in issues:
                print(f"  • {issue}")
            
            if input("\nContinue anyway? (y/n) [n]: ").strip().lower() != 'y':
                print("❌ Prompt creation cancelled")
                return
        
        # Create the prompt
        try:
            created_by = os.getenv('USER', 'user')
            metadata = self.manager.create_prompt(
                name, description, content, prompt_type, language, tags, created_by
            )
            
            print(f"\n✅ Prompt created successfully!")
            print(f"🆔 ID: {metadata.id}")
            print(f"📏 Size: {len(content)} characters")
            print(f"📊 Version: {metadata.current_version}")
            
            # Ask about setting as default
            if input(f"\nSet as default for {prompt_type}/{language}? (y/n) [n]: ").strip().lower() == 'y':
                self.manager.set_default_prompt(prompt_type, language, metadata.id, created_by)
                print(f"⭐ Set as default for {prompt_type}/{language}")
            
        except Exception as e:
            print(f"❌ Failed to create prompt: {e}")
    
    def edit_prompt(self, prompt_id: str) -> None:
        """Edit a prompt in external editor."""
        metadata = self.manager.get_prompt(prompt_id)
        if not metadata:
            print(f"❌ Prompt '{prompt_id}' not found")
            return
        
        if metadata.is_builtin:
            print(f"❌ Cannot edit built-in prompt '{prompt_id}'")
            print("💡 Use 'prompt create' to create a custom version")
            return
        
        current_content = metadata.get_current_content()
        
        print(f"\n✏️  Editing: {metadata.name}")
        print(f"📄 Description: {metadata.description}")
        print(f"📏 Current size: {len(current_content)} characters")
        
        # Edit in external editor
        new_content = self._edit_in_external_editor(current_content)
        
        if not new_content or new_content.strip() == current_content.strip():
            print("❌ No changes made")
            return
        
        # Validation
        issues = self.manager.validate_prompt_content(new_content)
        if issues:
            print("\n⚠️  Validation Warnings:")
            for issue in issues:
                print(f"  • {issue}")
        
        # Change reason
        change_reason = input("\nReason for change: ").strip()
        if not change_reason:
            change_reason = "Content update"
        
        try:
            created_by = os.getenv('USER', 'user')
            new_version = self.manager.update_prompt(prompt_id, new_content, created_by, change_reason)
            
            print(f"\n✅ Prompt updated successfully!")
            print(f"📊 New version: {new_version.version}")
            print(f"📏 New size: {new_version.size} characters")
            print(f"📝 Change: {change_reason}")
            
        except Exception as e:
            print(f"❌ Failed to update prompt: {e}")
    
    def delete_prompt(self, prompt_id: str) -> None:
        """Delete a custom prompt with confirmation."""
        metadata = self.manager.get_prompt(prompt_id)
        if not metadata:
            print(f"❌ Prompt '{prompt_id}' not found")
            return
        
        if metadata.is_builtin:
            print(f"❌ Cannot delete built-in prompt '{prompt_id}'")
            return
        
        print(f"\n🗑️  Delete Prompt: {metadata.name}")
        print(f"📄 Description: {metadata.description}")
        print(f"📊 Versions: {len(metadata.versions)}")
        print(f"📅 Created: {metadata.created_at}")
        
        if self._is_default_prompt(metadata):
            print("⚠️  This prompt is set as default for some configurations")
        
        # Confirmation
        confirm = input("\nAre you sure you want to delete this prompt? (yes/no): ").strip().lower()
        if confirm != 'yes':
            print("❌ Deletion cancelled")
            return
        
        try:
            deleted_by = os.getenv('USER', 'user')
            self.manager.delete_prompt(prompt_id, deleted_by)
            print(f"✅ Prompt '{metadata.name}' deleted successfully")
            
        except Exception as e:
            print(f"❌ Failed to delete prompt: {e}")
    
    def show_history(self, prompt_id: str) -> None:
        """Show detailed history for a prompt."""
        metadata = self.manager.get_prompt(prompt_id)
        if not metadata:
            print(f"❌ Prompt '{prompt_id}' not found")
            return
        
        history = self.manager.get_prompt_history(prompt_id)
        
        print(f"\n📊 History: {metadata.name}")
        print("=" * 80)
        
        if not history:
            print("No history records found")
            return
        
        for entry in history:
            print(f"📅 {entry['timestamp']}")
            print(f"👤 User: {entry['user']}")
            print(f"🔧 Action: {entry['action']}")
            print(f"📝 Details: {entry['details']}")
            print("-" * 40)
    
    def rollback_prompt(self, prompt_id: str, target_version: int) -> None:
        """Rollback a prompt to a previous version."""
        metadata = self.manager.get_prompt(prompt_id)
        if not metadata:
            print(f"❌ Prompt '{prompt_id}' not found")
            return
        
        if metadata.is_builtin:
            print(f"❌ Cannot rollback built-in prompt '{prompt_id}'")
            return
        
        target = next((v for v in metadata.versions if v.version == target_version), None)
        if not target:
            print(f"❌ Version {target_version} not found")
            return
        
        print(f"\n⏪ Rollback: {metadata.name}")
        print(f"📊 Current version: {metadata.current_version}")
        print(f"📊 Target version: {target_version}")
        print(f"📅 Target created: {target.created_at}")
        print(f"📝 Target reason: {target.change_reason}")
        print(f"📏 Target size: {target.size} characters")
        
        # Show diff preview
        if metadata.current_version != target_version:
            print(f"\n📋 Changes preview (first 200 chars):")
            current_content = metadata.get_current_content()
            preview_diff = current_content[:200] + "..." if len(current_content) > 200 else current_content
            target_preview = target.content[:200] + "..." if len(target.content) > 200 else target.content
            print(f"Current: {preview_diff}")
            print(f"Target:  {target_preview}")
        
        # Confirmation
        if input("\nConfirm rollback? (y/n) [n]: ").strip().lower() != 'y':
            print("❌ Rollback cancelled")
            return
        
        try:
            rolled_back_by = os.getenv('USER', 'user')
            new_version = self.manager.rollback_prompt(prompt_id, target_version, rolled_back_by)
            
            print(f"✅ Rollback successful!")
            print(f"📊 New version: {new_version.version}")
            print(f"📝 Content restored from version {target_version}")
            
        except Exception as e:
            print(f"❌ Rollback failed: {e}")
    
    def show_diff(self, prompt_id: str, version1: int, version2: int) -> None:
        """Show diff between two versions."""
        try:
            diff = self.manager.get_prompt_diff(prompt_id, version1, version2)
            
            print(f"\n📋 Diff: {prompt_id} (v{version1} vs v{version2})")
            print("=" * 80)
            
            if not diff:
                print("No differences found")
            else:
                print(diff)
                
        except Exception as e:
            print(f"❌ Failed to generate diff: {e}")
    
    def set_default(self, prompt_type: str, language: str, prompt_id: str) -> None:
        """Set default prompt for a type/language combination."""
        try:
            set_by = os.getenv('USER', 'user')
            self.manager.set_default_prompt(prompt_type, language, prompt_id, set_by)
            print(f"✅ Set '{prompt_id}' as default for {prompt_type}/{language}")
            
        except Exception as e:
            print(f"❌ Failed to set default: {e}")
    
    def _is_default_prompt(self, metadata: PromptMetadata) -> bool:
        """Check if a prompt is set as default for any configuration."""
        for ptype, languages in self.manager._defaults.defaults.items():
            for lang, default_id in languages.items():
                if default_id == metadata.id:
                    return True
        return False
    
    def _get_multiline_input(self) -> str:
        """Get multi-line input from user."""
        print("Enter prompt content (press Ctrl+D when done, Ctrl+C to cancel):")
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
            print("\n❌ Input cancelled")
            return ""
        
        return '\n'.join(lines)
    
    def _load_from_file(self) -> str:
        """Load content from a file."""
        file_path = input("File path: ").strip()
        if not file_path:
            return ""
        
        try:
            path = Path(file_path)
            if not path.exists():
                print(f"❌ File not found: {file_path}")
                return ""
            
            return path.read_text(encoding='utf-8')
            
        except Exception as e:
            print(f"❌ Failed to read file: {e}")
            return ""
    
    def _edit_in_external_editor(self, initial_content: str = "") -> str:
        """Edit content in external editor."""
        editor = os.getenv('EDITOR', 'nano')
        
        with tempfile.NamedTemporaryFile(mode='w+', suffix='.txt', delete=False) as f:
            f.write(initial_content)
            temp_path = f.name
        
        try:
            subprocess.run([editor, temp_path], check=True)
            
            with open(temp_path, 'r') as f:
                content = f.read()
            
            return content
            
        except subprocess.CalledProcessError:
            print(f"❌ Editor '{editor}' failed")
            return ""
        except FileNotFoundError:
            print(f"❌ Editor '{editor}' not found")
            print("💡 Set EDITOR environment variable or use 'nano', 'vim', etc.")
            return ""
        finally:
            try:
                os.unlink(temp_path)
            except:
                pass