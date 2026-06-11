"""
NebulaForge - Helpers comunes para interfaces CLI y TUI
"""

from typing import List, Optional


class CLIHelpers:
    """Shared methods between TUI and InteractiveCLI"""

    @staticmethod
    def select_environment(environments: List[str], action: str = "select") -> Optional[str]:
        """Generic environment selector"""
        if not environments:
            return None

        print(f"\n📋 Available environments for {action}:")
        for i, env in enumerate(environments, 1):
            print(f"   {i}. {env}")
        print("   0. ↩️ Cancel and return")

        try:
            choice = int(input(f"\n🔢 Select (0-{len(environments)}): "))
            if choice == 0:
                print("↩️ Operation cancelled")
                return None
            if 1 <= choice <= len(environments):
                return environments[choice - 1]
        except ValueError:
            print("❌ Invalid selection")
        return None

    @staticmethod
    def wait_for_continue(message: str = "\n📍 Press Enter to continue") -> None:
        """Generic wait to continue"""
        input(message)


# Convenience functions for compatibility
def select_environment(environments: List[str], action: str = "select") -> Optional[str]:
    return CLIHelpers.select_environment(environments, action)


def wait_for_continue(message: str = "\n📍 Press Enter to continue") -> None:
    return CLIHelpers.wait_for_continue(message)
