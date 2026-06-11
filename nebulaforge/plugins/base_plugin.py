"""
Base plugin system
"""
from __future__ import annotations

import importlib.util
import re
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from nebulaforge.utils.command_runner import SecureCommandRunner

_DEPENDENCY_NAME_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_.\-]*$")


class BasePlugin(ABC):
    """Base class for all plugins"""

    def __init__(self, config_manager, audit_logger, command_runner: Optional[SecureCommandRunner] = None):
        self.config_manager = config_manager
        self.audit_logger = audit_logger
        self.command_runner = command_runner
        self.plugin_name = self.__class__.__name__
        self.plugin_version = "1.0.0"

    @abstractmethod
    def get_name(self) -> str:
        """Get plugin name"""
        pass

    @abstractmethod
    def get_description(self) -> str:
        """Get plugin description"""
        pass

    @abstractmethod
    def get_commands(self) -> Dict[str, str]:
        """Get available plugin commands"""
        pass

    @abstractmethod
    def execute(self, command: str, **kwargs) -> Dict[str, Any]:
        """Execute plugin command"""
        pass

    def validate_environment(self, env_name: str) -> bool:
        """Validate that the environment exists and is accessible"""
        if self.command_runner is None:
            return False
        try:
            success, _ = self.command_runner.run_secure_command(
                ['conda', 'list', '-n', env_name, '--json'], 'validate_environment'
            )
            return success
        except Exception:
            return False

    def log_plugin_action(self, action: str, details: Dict[str, Any]) -> None:
        """Log plugin action to audit"""
        if self.audit_logger:
            self.audit_logger.log_system_event(
                f"plugin_{self.plugin_name}_{action}",
                f"Plugin {self.plugin_name}: {details}"
            )

    def get_plugin_info(self) -> Dict[str, Any]:
        """Get plugin information"""
        return {
            'name': self.get_name(),
            'description': self.get_description(),
            'version': self.plugin_version,
            'commands': self.get_commands()
        }

    def check_dependencies(self) -> List[str]:
        """Verify plugin dependencies"""
        missing_deps: List[str] = []

        dependencies = self.get_required_dependencies()
        for dep in dependencies:
            if not _DEPENDENCY_NAME_PATTERN.match(dep):
                missing_deps.append(dep)
                continue
            if importlib.util.find_spec(dep) is None:
                missing_deps.append(dep)

        return missing_deps

    def get_required_dependencies(self) -> List[str]:
        """Get list of required dependencies"""
        return []

    def is_available(self) -> bool:
        """Check if plugin is available"""
        return len(self.check_dependencies()) == 0
