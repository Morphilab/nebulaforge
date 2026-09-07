"""
NebulaForge - Interactive CLI
"""

from pathlib import Path
from typing import List, Optional

from nebulaforge.core.environment_service import EnvironmentService
from nebulaforge.utils.formatters import OutputFormatters


class NebulaForgeInteractiveCLI:
    """Interactive CLI for NebulaForge — I/O only, logic delegated to EnvironmentService"""

    def __init__(self):
        self.svc = EnvironmentService(production_mode=False)

    def run(self) -> int:
        try:
            while True:
                choice = self.main_menu()
                handlers = {
                    0: lambda: (print("Goodbye!"), 0),
                    1: self.handle_list_environments,
                    2: self.handle_create_environment,
                    3: self.handle_manage_environment,
                    4: self.handle_install_packages,
                    5: self.handle_delete_environment,
                    6: self.handle_clone_environment,
                    7: self.handle_export_environment,
                    8: self.handle_import_environment,
                    9: self.handle_security_diagnostics,
                    10: self.handle_audit_logs,
                    11: self.handle_system_config,
                }
                handler = handlers.get(choice)
                if handler:
                    result = handler()
                    if result is not None:
                        return result
                else:
                    print("Invalid option")
        except KeyboardInterrupt:
            print("\nSession terminated by user")
            return 0
        except Exception as e:
            print(f"Error in interactive CLI: {e}")
            return 1

    def main_menu(self) -> int:
        profile = self.svc.get_current_profile_name()
        print(f"""
=== NebulaForge - Secure Conda Environment Manager ===

Security Level: {profile}

Available Options:

1. List existing environments
2. Create new secure environment
3. Manage specific environment
4. Manage packages
5. Delete environment (with backup)
6. Clone existing environment
7. Export environment to file
8. Import environment from file
9. Run security diagnostics
10. View audit logs
11. System configuration
0. Exit
""")
        try:
            return int(input("Select an option: ").strip())
        except ValueError:
            return -1

    def handle_list_environments(self):
        print("\nListing environments...")
        result = self.svc.list_environments()
        if result.success:
            print(OutputFormatters.format_environment_list(result.data))
        else:
            print(OutputFormatters.format_error_message(result.message))
        self._wait()

    def handle_create_environment(self):
        print("\nCreate New Environment")
        name = input("Environment name: ").strip()
        if not name:
            print("Name cannot be empty")
            return
        if not self.svc.validate_env_name(name):
            print("Invalid environment name")
            return

        python_version = input("Python version (Enter = 3.9): ").strip() or "3.9"
        packages_input = input("Initial packages (space separated): ").strip()
        packages = packages_input.split() if packages_input else []

        if packages:
            result = self.svc.validate_packages(packages)
            if not result.success:
                print(OutputFormatters.format_error_message(result.message))
                return

        print(f"\nCreating environment '{name}'...")
        result = self.svc.create_environment(name, python_version, packages)
        print(OutputFormatters.format_success_message(result.message) if result.success
              else OutputFormatters.format_error_message(result.message))
        self._wait()

    def handle_manage_environment(self):
        envs_result = self.svc.list_environments()
        if not envs_result.success or not envs_result.data:
            print("No environments available")
            self._wait()
            return

        env_name = self._select_env(envs_result.data)
        if not env_name:
            return

        while True:
            print(f"\nManaging: {env_name}")
            print("1. View info")
            print("2. Install packages")
            print("3. Update packages")
            print("4. List packages")
            print("5. Check vulnerabilities")
            print("0. Back to main menu")

            choice = input("Select option: ").strip()
            if choice == "0":
                break
            elif choice == "1":
                self._show_info(env_name)
            elif choice == "2":
                self._install_pkgs(env_name)
            elif choice == "3":
                self._update_pkgs(env_name)
            elif choice == "4":
                self._list_pkgs(env_name)
            elif choice == "5":
                self._check_vulns(env_name)
            else:
                print("Invalid option")

    def handle_install_packages(self):
        envs_result = self.svc.list_environments()
        if not envs_result.success or not envs_result.data:
            print("No environments available")
            self._wait()
            return
        env_name = self._select_env(envs_result.data)
        if env_name:
            self._install_pkgs(env_name)

    def handle_delete_environment(self):
        envs_result = self.svc.list_environments()
        if not envs_result.success or not envs_result.data:
            print("No environments available")
            self._wait()
            return

        env_name = self._select_env(envs_result.data)
        if not env_name:
            return

        confirm = input(f"Delete '{env_name}'? (y/N): ").strip().lower()
        if confirm not in ('y', 'yes'):
            print("Operation cancelled")
            return

        create_backup = input("Create backup? (Y/n): ").strip().lower() != 'n'
        result = self.svc.delete_environment(env_name, create_backup)
        print(OutputFormatters.format_success_message(result.message) if result.success
              else OutputFormatters.format_error_message(result.message))
        self._wait()

    def handle_clone_environment(self):
        print("\nClone Environment")
        envs_result = self.svc.list_environments()
        if not envs_result.success or not envs_result.data:
            print("No environments available")
            self._wait()
            return

        source = self._select_env(envs_result.data)
        if not source:
            return

        target = input("Name of the new environment: ").strip()
        if not target or not self.svc.validate_env_name(target):
            print("Invalid name")
            return

        result = self.svc.clone_environment(source, target)
        print(OutputFormatters.format_success_message(result.message) if result.success
              else OutputFormatters.format_error_message(result.message))
        self._wait()

    def handle_export_environment(self):
        print("\nExport Environment")
        envs_result = self.svc.list_environments()
        if not envs_result.success or not envs_result.data:
            print("No environments available")
            self._wait()
            return

        env_name = self._select_env(envs_result.data)
        if not env_name:
            return

        filename = input(f"File name (default: environment_{env_name}.yaml): ").strip()
        if not filename:
            filename = f"environment_{env_name}.yaml"

        result = self.svc.export_environment(env_name, filename)
        print(OutputFormatters.format_success_message(result.message) if result.success
              else OutputFormatters.format_error_message(result.message))
        self._wait()

    def handle_import_environment(self):
        print("\nImport Environment")
        filepath = input("Path to YAML file: ").strip()
        if not filepath or not Path(filepath).exists():
            print("File not found")
            return

        env_name = input("Name of the new environment: ").strip()
        if not env_name or not self.svc.validate_env_name(env_name):
            print("Invalid name")
            return

        result = self.svc.import_environment(Path(filepath), env_name)
        print(OutputFormatters.format_success_message(result.message) if result.success
              else OutputFormatters.format_error_message(result.message))
        self._wait()

    def handle_security_diagnostics(self):
        print("\nRunning security diagnostics...")
        result = self.svc.run_diagnostics()
        print(OutputFormatters.format_diagnostics_report(result.data))
        self._wait()

    def handle_audit_logs(self):
        print("\nAudit Logs")
        limit_str = input("Number of entries (default 10): ").strip() or "10"
        try:
            limit = int(limit_str)
        except ValueError:
            limit = 10
        result = self.svc.get_audit_trail(limit)
        print(OutputFormatters.format_audit_trail(result.data))
        self._wait()

    def handle_system_config(self):
        print("\nSystem Configuration")
        current = self.svc.get_security_info().get('profile_name', 'unknown')
        print(f"Current profile: {current}")

        profiles = self.svc.get_available_profiles()
        for i, p in enumerate(profiles, 1):
            print(f"   {i}. {p}")

        try:
            choice = input(f"\nSelect profile (1-{len(profiles)}): ").strip()
            level = profiles[int(choice) - 1]
            result = self.svc.change_security_level(level)
            print(OutputFormatters.format_success_message(result.message) if result.success
                  else OutputFormatters.format_error_message(result.message))
        except (ValueError, IndexError):
            print("Invalid selection")
        self._wait()

    def _select_env(self, environments: List[str]) -> Optional[str]:
        from nebulaforge.core.cli_helpers import select_environment
        return select_environment(environments)

    def _show_info(self, env_name: str) -> None:
        result = self.svc.get_environment_info(env_name)
        if not result.success:
            print(OutputFormatters.format_error_message(result.message))
            return
        print(OutputFormatters.format_environment_info(result.data))

    def _install_pkgs(self, env_name: str) -> None:
        packages_input = input("Packages to install: ").strip()
        if not packages_input:
            print("No packages specified")
            return
        packages = packages_input.split()
        result = self.svc.install_packages(env_name, packages)
        print(OutputFormatters.format_success_message(result.message) if result.success
              else OutputFormatters.format_error_message(result.message))

    def _update_pkgs(self, env_name: str) -> None:
        packages_input = input("Packages to update (empty = all): ").strip()
        packages = packages_input.split() if packages_input else None
        result = self.svc.update_packages(env_name, packages)
        print(OutputFormatters.format_success_message(result.message) if result.success
              else OutputFormatters.format_error_message(result.message))

    def _list_pkgs(self, env_name: str) -> None:
        result = self.svc.list_packages(env_name)
        if not result.success:
            print(OutputFormatters.format_error_message(result.message))
            return
        print(OutputFormatters.format_package_list(result.data))

    def _check_vulns(self, env_name: str) -> None:
        result = self.svc.check_vulnerabilities(env_name)
        if result.data:
            for v in result.data:
                print(f"  {v.get('package')}: {v.get('issue')}")
        else:
            print("No known vulnerabilities found")

    def _wait(self) -> None:
        from nebulaforge.core.cli_helpers import wait_for_continue
        wait_for_continue()


def run_interactive_cli() -> int:
    cli = NebulaForgeInteractiveCLI()
    return cli.run()
