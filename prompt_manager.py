#!/usr/bin/env python3
"""
ADVANCED PROMPT MANAGEMENT SYSTEM

Enterprise-grade prompt CRUD with versioning, history tracking, and metadata management.
"""

import os
import sys
import json
import logging
import difflib
import tempfile
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional, List, Union
from dataclasses import dataclass, asdict, field
from uuid import uuid4
import hashlib

logger = logging.getLogger('cursor_pr_review')

@dataclass
class PromptVersion:
    """Represents a single version of a prompt."""
    version: int
    content: str
    created_at: str
    created_by: str
    change_reason: str
    content_hash: str
    size: int
    
    @classmethod
    def create(cls, content: str, created_by: str, change_reason: str, version: int = 1) -> 'PromptVersion':
        """Create a new prompt version."""
        content_hash = hashlib.sha256(content.encode('utf-8')).hexdigest()[:16]
        return cls(
            version=version,
            content=content,
            created_at=datetime.now(timezone.utc).isoformat(),
            created_by=created_by,
            change_reason=change_reason,
            content_hash=content_hash,
            size=len(content)
        )

@dataclass
class PromptMetadata:
    """Complete metadata for a prompt including versioning."""
    id: str
    name: str
    description: str
    prompt_type: str  # 'security', 'performance', 'general', 'strict', 'lenient'
    language: str  # 'python', 'javascript', 'general', etc.
    tags: List[str]
    is_builtin: bool
    is_active: bool
    created_at: str
    updated_at: str
    created_by: str
    current_version: int
    versions: List[PromptVersion] = field(default_factory=list)
    
    @classmethod
    def create_builtin(cls, id: str, name: str, description: str, prompt_type: str, language: str = 'general') -> 'PromptMetadata':
        """Create metadata for a built-in prompt."""
        now = datetime.now(timezone.utc).isoformat()
        return cls(
            id=id,
            name=name,
            description=description,
            prompt_type=prompt_type,
            language=language,
            tags=['builtin'],
            is_builtin=True,
            is_active=True,
            created_at=now,
            updated_at=now,
            created_by='system',
            current_version=1,
            versions=[]
        )
    
    @classmethod
    def create_custom(cls, name: str, description: str, prompt_type: str, language: str, created_by: str, tags: List[str] = None) -> 'PromptMetadata':
        """Create metadata for a custom prompt."""
        now = datetime.now(timezone.utc).isoformat()
        prompt_id = f"custom_{uuid4().hex[:8]}"
        return cls(
            id=prompt_id,
            name=name,
            description=description,
            prompt_type=prompt_type,
            language=language,
            tags=tags or [],
            is_builtin=False,
            is_active=True,
            created_at=now,
            updated_at=now,
            created_by=created_by,
            current_version=0,
            versions=[]
        )
    
    def get_current_content(self) -> str:
        """Get the content of the current version."""
        if not self.versions:
            return ""
        
        current = next((v for v in self.versions if v.version == self.current_version), None)
        return current.content if current else ""
    
    def add_version(self, content: str, created_by: str, change_reason: str) -> PromptVersion:
        """Add a new version to this prompt."""
        new_version_num = max((v.version for v in self.versions), default=0) + 1
        new_version = PromptVersion.create(content, created_by, change_reason, new_version_num)
        
        self.versions.append(new_version)
        self.current_version = new_version_num
        self.updated_at = new_version.created_at
        
        return new_version

@dataclass 
class PromptDefaults:
    """Default prompt assignments by type and language."""
    defaults: Dict[str, Dict[str, str]] = field(default_factory=dict)  # type -> language -> prompt_id
    
    def set_default(self, prompt_type: str, language: str, prompt_id: str) -> None:
        """Set default prompt for a type/language combination."""
        if prompt_type not in self.defaults:
            self.defaults[prompt_type] = {}
        self.defaults[prompt_type][language] = prompt_id
    
    def get_default(self, prompt_type: str, language: str = 'general') -> Optional[str]:
        """Get default prompt ID for a type/language combination."""
        return self.defaults.get(prompt_type, {}).get(language) or self.defaults.get(prompt_type, {}).get('general')

class PromptManager:
    """Advanced prompt management with CRUD, versioning, and history."""
    
    def __init__(self):
        self.data_dir = Path.home() / '.cursor-pr-review' / 'prompts'
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        self.metadata_file = self.data_dir / 'metadata.json'
        self.defaults_file = self.data_dir / 'defaults.json'
        self.history_file = self.data_dir / 'history.log'
        
        self._metadata: Dict[str, PromptMetadata] = {}
        self._defaults = PromptDefaults()
        
        self._load_data()
        self._ensure_builtins()
    
    def _load_data(self) -> None:
        """Load all prompt metadata and defaults."""
        # Load metadata
        if self.metadata_file.exists():
            try:
                with open(self.metadata_file, 'r') as f:
                    data = json.load(f)
                    self._metadata = {
                        k: PromptMetadata(**v) for k, v in data.items()
                    }
            except Exception as e:
                logger.warning(f"Failed to load prompt metadata: {e}")
        
        # Load defaults
        if self.defaults_file.exists():
            try:
                with open(self.defaults_file, 'r') as f:
                    data = json.load(f)
                    self._defaults = PromptDefaults(**data)
            except Exception as e:
                logger.warning(f"Failed to load prompt defaults: {e}")
    
    def _save_data(self) -> None:
        """Save all prompt metadata and defaults."""
        try:
            # Save metadata
            with open(self.metadata_file, 'w') as f:
                data = {k: asdict(v) for k, v in self._metadata.items()}
                json.dump(data, f, indent=2)
            
            # Save defaults
            with open(self.defaults_file, 'w') as f:
                json.dump(asdict(self._defaults), f, indent=2)
            
            # Set secure permissions
            os.chmod(self.metadata_file, 0o600)
            os.chmod(self.defaults_file, 0o600)
            
        except Exception as e:
            raise RuntimeError(f"Failed to save prompt data: {e}")
    
    def _log_action(self, action: str, prompt_id: str, details: str = "", user: str = "system") -> None:
        """Log an action to the history file."""
        timestamp = datetime.now(timezone.utc).isoformat()
        log_entry = {
            'timestamp': timestamp,
            'user': user,
            'action': action,
            'prompt_id': prompt_id,
            'details': details
        }
        
        try:
            with open(self.history_file, 'a') as f:
                f.write(json.dumps(log_entry) + '\n')
        except Exception as e:
            logger.warning(f"Failed to log action: {e}")
    
    def _ensure_builtins(self) -> None:
        """Ensure built-in prompts are registered with metadata."""
        builtins = {
            'default': {
                'name': 'Default Review',
                'description': 'Balanced review focusing on security, bugs, performance, and quality',
                'type': 'general',
                'language': 'general'
            },
            'strict': {
                'name': 'Strict Review',
                'description': 'Thorough analysis with zero tolerance for any issues',
                'type': 'strict',
                'language': 'general'
            },
            'lenient': {
                'name': 'Lenient Review',
                'description': 'Focus on critical issues only, practical and constructive',
                'type': 'lenient',
                'language': 'general'
            },
            'security-focused': {
                'name': 'Security-Focused Review',
                'description': 'Comprehensive security-first analysis',
                'type': 'security',
                'language': 'general'
            }
        }
        
        for builtin_id, info in builtins.items():
            if builtin_id not in self._metadata:
                metadata = PromptMetadata.create_builtin(
                    builtin_id, info['name'], info['description'], 
                    info['type'], info['language']
                )
                
                # Load content from file if exists
                builtin_file = Path('prompts') / f'{builtin_id}.txt'
                if builtin_file.exists():
                    content = builtin_file.read_text(encoding='utf-8').strip()
                    metadata.add_version(content, 'system', 'Initial builtin version')
                
                self._metadata[builtin_id] = metadata
        
        # Set default assignments
        if not self._defaults.defaults:
            self._defaults.set_default('general', 'general', 'default')
            self._defaults.set_default('strict', 'general', 'strict')
            self._defaults.set_default('lenient', 'general', 'lenient')
            self._defaults.set_default('security', 'general', 'security-focused')
        
        self._save_data()
    
    def list_prompts(self, prompt_type: str = None, language: str = None, include_inactive: bool = False) -> List[PromptMetadata]:
        """List all prompts with optional filtering."""
        prompts = []
        
        for metadata in self._metadata.values():
            if not include_inactive and not metadata.is_active:
                continue
            
            if prompt_type and metadata.prompt_type != prompt_type:
                continue
            
            if language and metadata.language != language and metadata.language != 'general':
                continue
            
            prompts.append(metadata)
        
        return sorted(prompts, key=lambda p: (p.is_builtin, p.name))
    
    def get_prompt(self, prompt_id: str) -> Optional[PromptMetadata]:
        """Get a prompt by ID."""
        return self._metadata.get(prompt_id)
    
    def create_prompt(self, name: str, description: str, content: str, prompt_type: str, 
                     language: str = 'general', tags: List[str] = None, 
                     created_by: str = 'user', change_reason: str = 'Initial creation') -> PromptMetadata:
        """Create a new custom prompt."""
        if not name or not content:
            raise ValueError("Name and content are required")
        
        metadata = PromptMetadata.create_custom(name, description, prompt_type, language, created_by, tags)
        metadata.add_version(content, created_by, change_reason)
        
        self._metadata[metadata.id] = metadata
        self._save_data()
        self._log_action('create', metadata.id, f"Created prompt '{name}'", created_by)
        
        return metadata
    
    def update_prompt(self, prompt_id: str, content: str, created_by: str = 'user', 
                     change_reason: str = 'Updated content') -> PromptVersion:
        """Update a prompt with new content."""
        metadata = self._metadata.get(prompt_id)
        if not metadata:
            raise ValueError(f"Prompt '{prompt_id}' not found")
        
        if metadata.is_builtin:
            raise ValueError(f"Cannot modify built-in prompt '{prompt_id}'")
        
        if metadata.get_current_content() == content:
            raise ValueError("No changes detected in content")
        
        new_version = metadata.add_version(content, created_by, change_reason)
        self._save_data()
        self._log_action('update', prompt_id, f"Updated to version {new_version.version}: {change_reason}", created_by)
        
        return new_version
    
    def delete_prompt(self, prompt_id: str, deleted_by: str = 'user') -> None:
        """Delete a custom prompt (mark as inactive)."""
        metadata = self._metadata.get(prompt_id)
        if not metadata:
            raise ValueError(f"Prompt '{prompt_id}' not found")
        
        if metadata.is_builtin:
            raise ValueError(f"Cannot delete built-in prompt '{prompt_id}'")
        
        metadata.is_active = False
        metadata.updated_at = datetime.now(timezone.utc).isoformat()
        
        self._save_data()
        self._log_action('delete', prompt_id, f"Marked prompt as inactive", deleted_by)
    
    def rollback_prompt(self, prompt_id: str, target_version: int, rolled_back_by: str = 'user') -> PromptVersion:
        """Rollback a prompt to a previous version."""
        metadata = self._metadata.get(prompt_id)
        if not metadata:
            raise ValueError(f"Prompt '{prompt_id}' not found")
        
        if metadata.is_builtin:
            raise ValueError(f"Cannot rollback built-in prompt '{prompt_id}'")
        
        target = next((v for v in metadata.versions if v.version == target_version), None)
        if not target:
            raise ValueError(f"Version {target_version} not found for prompt '{prompt_id}'")
        
        # Create new version with old content
        new_version = metadata.add_version(
            target.content, 
            rolled_back_by, 
            f"Rolled back to version {target_version}"
        )
        
        self._save_data()
        self._log_action('rollback', prompt_id, f"Rolled back to version {target_version}, created version {new_version.version}", rolled_back_by)
        
        return new_version
    
    def get_prompt_diff(self, prompt_id: str, version1: int, version2: int) -> str:
        """Get diff between two versions of a prompt."""
        metadata = self._metadata.get(prompt_id)
        if not metadata:
            raise ValueError(f"Prompt '{prompt_id}' not found")
        
        v1 = next((v for v in metadata.versions if v.version == version1), None)
        v2 = next((v for v in metadata.versions if v.version == version2), None)
        
        if not v1:
            raise ValueError(f"Version {version1} not found")
        if not v2:
            raise ValueError(f"Version {version2} not found")
        
        diff = difflib.unified_diff(
            v1.content.splitlines(keepends=True),
            v2.content.splitlines(keepends=True),
            fromfile=f"version {version1}",
            tofile=f"version {version2}",
            lineterm=""
        )
        
        return ''.join(diff)
    
    def get_prompt_history(self, prompt_id: str) -> List[Dict[str, Any]]:
        """Get history of changes for a prompt."""
        if not self.history_file.exists():
            return []
        
        history = []
        try:
            with open(self.history_file, 'r') as f:
                for line in f:
                    entry = json.loads(line.strip())
                    if entry['prompt_id'] == prompt_id:
                        history.append(entry)
        except Exception as e:
            logger.warning(f"Failed to read history: {e}")
        
        return sorted(history, key=lambda x: x['timestamp'], reverse=True)
    
    def set_default_prompt(self, prompt_type: str, language: str, prompt_id: str, set_by: str = 'user') -> None:
        """Set default prompt for a type/language combination."""
        if prompt_id not in self._metadata:
            raise ValueError(f"Prompt '{prompt_id}' not found")
        
        self._defaults.set_default(prompt_type, language, prompt_id)
        self._save_data()
        self._log_action('set_default', prompt_id, f"Set as default for {prompt_type}/{language}", set_by)
    
    def get_default_prompt(self, prompt_type: str, language: str = 'general') -> Optional[str]:
        """Get default prompt ID for a type/language combination."""
        return self._defaults.get_default(prompt_type, language)
    
    def validate_prompt_content(self, content: str) -> List[str]:
        """Validate prompt content and return list of issues."""
        issues = []
        
        if len(content.strip()) < 50:
            issues.append("Prompt content is very short (< 50 characters)")
        
        if len(content) > 10000:
            issues.append("Prompt content is very long (> 10,000 characters)")
        
        # Check for common prompt patterns
        required_patterns = ['security', 'bug', 'error', 'issue']
        missing_patterns = [p for p in required_patterns if p.lower() not in content.lower()]
        if missing_patterns:
            issues.append(f"Consider including guidance for: {', '.join(missing_patterns)}")
        
        return issues