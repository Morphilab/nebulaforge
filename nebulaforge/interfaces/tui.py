"""
NebulaForge TUI - Terminal User Interface (Rich)
"""

import sys
from pathlib import Path
from typing import List, Optional

try:
    from rich import box
    from rich.console import Console
    from rich.panel import Panel
    from rich.prompt import Confirm, IntPrompt, Prompt
    from rich.table import Table
    from rich.text import Text
except ImportError:
    print("Error: Rich is not installed. Install with: pip install rich")
    sys.exit(1)

from nebulaforge import __version__
from nebulaforge.core.environment_service import EnvironmentService
from nebulaforge.utils.formatters import OutputFormatters


class NebulaForgeTUI:
    """TUI for NebulaForge — Rich I/O only, logic delegated to EnvironmentService"""

    def __init__(self):
        self.console = Console()
        self.svc = EnvironmentService(production_mode=False)

    def run(self) -> int:
        try:
            self.show_welcome()
            handlers = {
                0: lambda: self._exit(),
                1: self.list_environments_flow,
                2: self.create_environment_flow,
                3: self.manage_environment_flow,
                4: self.install_packages_flow,
                5: self.delete_environment_flow,
                6: self.clone_environment_flow,
                7: self.export_environment_flow,
                8: self.import_environment_flow,
                9: self.security_diagnostics_flow,
                10: self.audit_logs_flow,
                11: self.system_config_flow,
            }
            while True:
                choice = self.main_menu()
                handler = handlers.get(choice)
                if handler:
                    result = handler()
                    if result is not None:
                        return result
                else:
                    self.console.print("[red]Invalid option[/red]")
        except KeyboardInterrupt:
            self.console.print("\n[yellow]Session terminated by user[/yellow]")
            return 0
        except Exception as e:
            self.console.print(f"[red]Error in TUI: {e}[/red]")
            return 1

    def _exit(self):
        self.console.print("[bold green]Goodbye![/bold green]")
        return 0

    def show_welcome(self):
        profile = self.svc.get_current_profile_name()
        welcome = Panel(
            Text(f"NebulaForge v{__version__}\nSecure Conda Environment Manager\nSecurity Level: {profile}",
                 justify="center"),
            style="blue", box=box.DOUBLE
        )
        self.console.print("\n", welcome, "\n")

    def main_menu(self) -> int:
        self.console.print("[bold cyan]Main Menu[/bold cyan]")
        self.console.print("-" * 50)

        items = [
            ("1", "List existing environments"),
            ("2", "Create new secure environment"),
            ("3", "Manage specific environment"),
            ("4", "Manage packages"),
            ("5", "Delete environment (with backup)"),
            ("6", "Clone existing environment"),
            ("7", "Export environment to file"),
            ("8", "Import environment from file"),
            ("9", "Run security diagnostics"),
            ("10", "View audit logs"),
            ("11", "System configuration"),
            ("0", "Exit"),
        ]
        table = Table(show_header=False, box=box.SIMPLE, padding=(0, 2))
        table.add_column("No", style="bold yellow", width=4)
        table.add_column("Description", style="white")
        for num, desc in items:
            table.add_row(num, desc)
        self.console.print(table, "\n")
        try:
            choice = IntPrompt.ask("Select an option", default=0, show_choices=False)
            return choice if 0 <= choice <= 11 else -1
        except (KeyboardInterrupt, Exception):
            return -1

    # ── Flows ───────────────────────────────────────────────

    def list_environments_flow(self):
        with self.console.status("[bold green]Fetching environments..."):
            result = self.svc.list_environments()
        if result.success and result.data:
            table = Table(title="Available Environments", box=box.ROUNDED)
            table.add_column("#", style="bold yellow", width=4)
            table.add_column("Name", style="cyan")
            table.add_column("Packages", style="green")
            table.add_column("Status", style="white")
            for i, env in enumerate(result.data, 1):
                info = self.svc.get_environment_info(env)
                count = info.data.get('package_count', '?') if info.success else 'Error'
                status = "OK" if info.success else "Error"
                table.add_row(str(i), env, str(count), status)
            self.console.print(table)
        elif result.success:
            self.console.print("[yellow]No environments available[/yellow]")
        else:
            self.console.print(f"[red]{result.message}[/red]")
        self._wait()

    def create_environment_flow(self):
        env_name = Prompt.ask("Environment name", default="")
        if not env_name:
            return
        if not self.svc.validate_env_name(env_name):
            self.console.print("[red]Invalid environment name[/red]")
            self._wait()
            return

        python_version = Prompt.ask("Python version", default="3.9")
        packages_input = Prompt.ask("Initial packages (space separated)", default="")
        packages = packages_input.split() if packages_input else []

        if packages:
            result = self.svc.validate_packages(packages)
            if not result.success:
                self.console.print(f"[red]{result.message}[/red]")
                self._wait()
                return

        if not Confirm.ask("Create the environment?", default=True):
            self.console.print("[yellow]Cancelled[/yellow]")
            return

        with self.console.status(f"[bold green]Creating environment '{env_name}'..."):
            result = self.svc.create_environment(env_name, python_version, packages)
        self.console.print(f"[green]{result.message}[/green]" if result.success
                           else f"[red]{result.message}[/red]")
        self._wait()

    def manage_environment_flow(self):
        envs_result = self.svc.list_environments()
        if not envs_result.success or not envs_result.data:
            self.console.print("[red]No environments available[/red]")
            self._wait()
            return

        env_name = self._select_env(envs_result.data, "manage")
        if not env_name:
            return

        while True:
            info = self.svc.get_environment_info(env_name)
            self.console.print(f"\n[bold cyan]Managing: {env_name}[/bold cyan]")
            if info.success:
                self.console.print(f"Python: {info.data.get('python_version', 'Unknown')}")
                self.console.print(f"Packages: {info.data.get('package_count', 0)}")

            self.console.print("1. View detailed information")
            self.console.print("2. Install packages")
            self.console.print("3. Update packages")
            self.console.print("4. List installed packages")
            self.console.print("5. Check for vulnerabilities")
            self.console.print("0. Back to main menu")

            try:
                choice = IntPrompt.ask("\nSelect option", default=0)
            except KeyboardInterrupt:
                break
            if choice == 0:
                break
            elif choice == 1:
                self._show_info(env_name)
            elif choice == 2:
                self._install_pkgs(env_name)
            elif choice == 3:
                self._update_pkgs(env_name)
            elif choice == 4:
                self._list_pkgs(env_name)
            elif choice == 5:
                self._check_vulns(env_name)

    def install_packages_flow(self):
        envs_result = self.svc.list_environments()
        if not envs_result.success or not envs_result.data:
            self.console.print("[red]No environments available[/red]")
            self._wait()
            return
        env_name = self._select_env(envs_result.data, "install packages")
        if env_name:
            self._install_pkgs(env_name)

    def delete_environment_flow(self):
        envs_result = self.svc.list_environments()
        if not envs_result.success or not envs_result.data:
            self.console.print("[red]No environments available[/red]")
            self._wait()
            return

        env_name = self._select_env(envs_result.data, "delete")
        if not env_name:
            return

        if not Confirm.ask(f"[red]Delete the environment '{env_name}'?[/red]"):
            self.console.print("[yellow]Cancelled[/yellow]")
            return

        create_backup = Confirm.ask("Create backup before deleting?", default=True)
        with self.console.status(f"[bold green]Deleting '{env_name}'..."):
            result = self.svc.delete_environment(env_name, create_backup)
        self.console.print(f"[green]{result.message}[/green]" if result.success
                           else f"[red]{result.message}[/red]")
        self._wait()

    def clone_environment_flow(self):
        envs_result = self.svc.list_environments()
        if not envs_result.success or not envs_result.data:
            self.console.print("[red]No environments available[/red]")
            self._wait()
            return

        source = self._select_env(envs_result.data, "clone")
        if not source:
            return

        target = Prompt.ask("Name of the new environment", default="")
        if not target or not self.svc.validate_env_name(target):
            self.console.print("[red]Invalid name[/red]")
            self._wait()
            return

        if not Confirm.ask(f"Clone '{source}' -> '{target}'?"):
            return

        with self.console.status("[bold green]Cloning..."):
            result = self.svc.clone_environment(source, target)
        self.console.print(f"[green]{result.message}[/green]" if result.success
                           else f"[red]{result.message}[/red]")
        self._wait()

    def export_environment_flow(self):
        envs_result = self.svc.list_environments()
        if not envs_result.success or not envs_result.data:
            self.console.print("[red]No environments[/red]")
            self._wait()
            return

        env_name = self._select_env(envs_result.data, "export")
        if not env_name:
            return

        default_file = f"environment_{env_name}.yaml"
        filename = Prompt.ask("File name", default=default_file)
        if not filename:
            return

        with self.console.status(f"[bold green]Exporting '{env_name}'..."):
            result = self.svc.export_environment(env_name, filename)
        self.console.print(f"[green]{result.message}[/green]" if result.success
                           else f"[red]{result.message}[/red]")
        self._wait()

    def import_environment_flow(self):
        input_path = Prompt.ask("Path to YAML file", default="")
        if not input_path:
            return

        input_file = Path(input_path)
        if not input_file.exists():
            self.console.print("[red]File not found[/red]")
            self._wait()
            return

        env_name = Prompt.ask("Name of the new environment", default="")
        if not env_name or not self.svc.validate_env_name(env_name):
            self.console.print("[red]Invalid name[/red]")
            self._wait()
            return

        if not Confirm.ask(f"Import as '{env_name}'?"):
            return

        with self.console.status("[bold green]Importing..."):
            result = self.svc.import_environment(input_file, env_name)
        self.console.print(f"[green]{result.message}[/green]" if result.success
                           else f"[red]{result.message}[/red]")
        self._wait()

    def security_diagnostics_flow(self):
        with self.console.status("[bold green]Analyzing..."):
            result = self.svc.run_diagnostics()
        self.console.print(OutputFormatters.format_diagnostics_report(result.data))
        self._wait()

    def audit_logs_flow(self):
        limit_str = Prompt.ask("Number of entries", default="10")
        try:
            limit = int(limit_str)
        except ValueError:
            limit = 10
        with self.console.status("[bold green]Loading..."):
            result = self.svc.get_audit_trail(limit)
        self.console.print(OutputFormatters.format_audit_trail(result.data))
        self._wait()

    def system_config_flow(self):
        current = self.svc.get_security_info().get('profile_name', 'unknown')
        self.console.print(f"Current profile: [cyan]{current}[/cyan]")

        profiles = self.svc.get_available_profiles()
        self.console.print("\nAvailable profiles:")
        for i, p in enumerate(profiles, 1):
            self.console.print(f"   {i}. {p}")

        try:
            choice = IntPrompt.ask(f"Select (1-{len(profiles)})", default=1)
            if 1 <= choice <= len(profiles):
                result = self.svc.change_security_level(profiles[choice - 1])
                self.console.print(f"[green]{result.message}[/green]" if result.success
                                   else f"[red]{result.message}[/red]")
        except Exception:
            self.console.print("[red]Invalid selection[/red]")
        self._wait()

    # ── Helpers ──────────────────────────────────────────

    def _select_env(self, environments: List[str], action: str = "") -> Optional[str]:
        from nebulaforge.core.cli_helpers import select_environment
        return select_environment(environments, action)

    def _show_info(self, env_name: str) -> None:
        result = self.svc.get_environment_info(env_name)
        if not result.success:
            self.console.print(f"[red]{result.message}[/red]")
            self._wait()
            return

        table = Table(title=env_name, box=box.ROUNDED)
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="green")
        table.add_row("Packages", str(result.data.get('package_count', 0)))
        table.add_row("Python", result.data.get('python_version', 'unknown'))
        self.console.print(table)

        vulns = result.data.get('security_issues', [])
        if vulns:
            self.console.print("[bold yellow]Detected vulnerabilities:[/bold yellow]")
            for v in vulns[:5]:
                self.console.print(f"  * {v.get('package')}: {v.get('issue')}")
        self._wait()

    def _install_pkgs(self, env_name: str) -> None:
        pkgs_input = Prompt.ask("Packages to install (empty to cancel)")
        if not pkgs_input:
            return
        packages = pkgs_input.split()
        result = self.svc.validate_packages(packages)
        if not result.success:
            self.console.print(f"[red]{result.message}[/red]")
            return
        with self.console.status(f"[bold green]Installing in {env_name}..."):
            result = self.svc.install_packages(env_name, packages)
        self.console.print(f"[green]{result.message}[/green]" if result.success
                           else f"[red]{result.message}[/red]")
        self._wait()

    def _update_pkgs(self, env_name: str) -> None:
        pkgs_input = Prompt.ask("Packages to update (empty = all)")
        packages = pkgs_input.split() if pkgs_input else None
        with self.console.status("[bold green]Updating..."):
            result = self.svc.update_packages(env_name, packages)
        self.console.print(f"[green]{result.message}[/green]" if result.success
                           else f"[red]{result.message}[/red]")
        self._wait()

    def _list_pkgs(self, env_name: str) -> None:
        result = self.svc.list_packages(env_name)
        if not result.success:
            self.console.print(f"[red]{result.message}[/red]")
            self._wait()
            return

        packages = result.data[:30]
        table = Table(title=f"Packages in {env_name}", box=box.ROUNDED)
        table.add_column("Package", style="cyan")
        table.add_column("Version", style="green")
        for pkg in packages:
            table.add_row(pkg.get('name', 'Unknown'), pkg.get('version', 'Unknown'))
        self.console.print(table)
        self._wait()

    def _check_vulns(self, env_name: str) -> None:
        with self.console.status("[bold green]Searching for vulnerabilities..."):
            result = self.svc.check_vulnerabilities(env_name)

        if result.data:
            table = Table(title=f"Vulnerabilities in {env_name}", box=box.ROUNDED)
            table.add_column("Package", style="cyan")
            table.add_column("Issue", style="red")
            table.add_column("Severity", style="yellow")
            for v in result.data:
                table.add_row(v.get('package'), v.get('issue'), v.get('severity', 'medium'))
            self.console.print(table)
        else:
            self.console.print("[green]No known vulnerabilities found[/green]")
        self._wait()

    def _wait(self) -> None:
        from nebulaforge.core.cli_helpers import wait_for_continue
        wait_for_continue()


def run_tui() -> int:
    return NebulaForgeTUI().run()
