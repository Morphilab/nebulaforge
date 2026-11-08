"""
NebulaForge - Traditional CLI Interface

"""

import argparse
from typing import List, Optional

from nebulaforge.core.environment_service import EnvironmentService
from nebulaforge.utils.formatters import OutputFormatters


class NebulaForgeCLI:
    """Traditional CLI interface for NebulaForge"""

    def __init__(self, production_mode: Optional[bool] = None):
        self.svc = EnvironmentService(production_mode=production_mode)
        self.parser = self._setup_parser()

    def _setup_parser(self) -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(
            description='NebulaForge - Secure Conda environment management',
            epilog='For more options, use --help with each command'
        )
        subparsers = parser.add_subparsers(dest='command', help='Available commands')

        list_parser = subparsers.add_parser('list', help='List available environments')
        list_parser.add_argument('--verbose', '-v', action='store_true', help='Show detailed information')

        create_parser = subparsers.add_parser('create', help='Create new environment')
        create_parser.add_argument('name', help='Environment name')
        create_parser.add_argument('--python', help='Python version (e.g. 3.9)')
        create_parser.add_argument('--packages', nargs='+', help='Initial packages')
        create_parser.add_argument('--channels', nargs='+', help='Additional channels')
        create_parser.add_argument('--yes', action='store_true', help='Confirm the operation non-interactively')

        install_parser = subparsers.add_parser('install', help='Install packages')
        install_parser.add_argument('environment', help='Environment name')
        install_parser.add_argument('packages', nargs='+', help='Packages to install')
        install_parser.add_argument('--no-conflict-check', action='store_true', help='Skip conflict check')
        install_parser.add_argument('--yes', action='store_true', help='Confirm the operation non-interactively')

        remove_parser = subparsers.add_parser('remove', help='Delete environment')
        remove_parser.add_argument('environment', help='Environment name')
        remove_parser.add_argument('--no-backup', action='store_true', help='Do not create backup')
        remove_parser.add_argument('--yes', action='store_true', help='Confirm the operation non-interactively')

        info_parser = subparsers.add_parser('info', help='Show environment info')
        info_parser.add_argument('environment', help='Environment name')

        update_parser = subparsers.add_parser('update', help='Update packages')
        update_parser.add_argument('environment', help='Environment name')
        update_parser.add_argument('packages', nargs='*', help='Specific packages to update')
        update_parser.add_argument('--yes', action='store_true', help='Confirm the operation non-interactively')

        backup_parser = subparsers.add_parser('backup', help='Manage backups')
        backup_parser.add_argument('--create', help='Create backup of environment')
        backup_parser.add_argument('--list', action='store_true', help='List backups')
        backup_parser.add_argument('--restore', help='Restore backup')
        backup_parser.add_argument('--yes', action='store_true', help='Confirm the operation non-interactively')

        subparsers.add_parser('diagnostics', help='Run security diagnostics')

        audit_parser = subparsers.add_parser('audit', help='View audit logs')
        audit_parser.add_argument('--limit', type=int, default=10, help='Entry limit')

        config_parser = subparsers.add_parser('config', help='System configuration')
        config_parser.add_argument('--security-level', choices=['low', 'medium', 'high', 'paranoid'],
                                   help='Change security level')
        config_parser.add_argument('--production-mode', choices=['on', 'off'],
                                   help='Enable or disable production mode')

        return parser

    def run_from_args(self, args: List[str]) -> int:
        """Execute from command line arguments"""
        try:
            parsed_args = self.parser.parse_args(args)

            if not parsed_args.command:
                self.parser.print_help()
                return 1

            command_method = getattr(self, f'handle_{parsed_args.command}', None)
            if command_method:
                return command_method(parsed_args)
            else:
                print(f"Command not implemented: {parsed_args.command}")
                return 1

        except SystemExit as e:
            if e.code is None:
                return 0
            return e.code if isinstance(e.code, int) else 1
        except Exception as e:
            print(f"Error executing command: {e}")
            return 1

    def _result_exit_code(self, result, success_code: int = 0) -> int:
        """Map a ServiceResult to a CLI exit code.

        Exit code 2 is reserved for policy outcomes (confirmation required,
        protected environment, production mode) so scripts can distinguish
        them from ordinary failures.
        """
        if result.success:
            print(OutputFormatters.format_success_message(result.message))
            return success_code

        message = (result.message or "").lower()
        if any(marker in message for marker in ("confirmation required", "production mode", "protected")):
            print(OutputFormatters.format_warning_message(result.message))
            return 2

        print(OutputFormatters.format_error_message(result.message))
        return 1

    def handle_list(self, args) -> int:
        """Handle list command"""
        result = self.svc.list_environments()
        if result.success:
            if args.verbose:
                for env in result.data or []:
                    info = self.svc.get_environment_info(env)
                    if info.success:
                        print(f"{env}: {info.data.get('package_count', 0)} packages")
                    else:
                        print(f"{env}: Error getting info")
            else:
                print(OutputFormatters.format_environment_list(result.data or []))
            return 0
        else:
            print(OutputFormatters.format_error_message(result.message))
            return 1

    def handle_create(self, args) -> int:
        """Handle create command"""
        if not self.svc.validate_env_name(args.name):
            print("❌ Invalid environment name")
            return 1

        if args.packages:
            pkg_result = self.svc.validate_packages(args.packages)
            if not pkg_result.success:
                print(f"❌ {pkg_result.message}")
                return 1

        print(f"⏳ Creating environment '{args.name}'...")
        result = self.svc.create_environment(
            args.name,
            args.python or "3.9",
            args.packages,
            confirmed=getattr(args, 'yes', False),
        )

        return self._result_exit_code(result)

    def handle_install(self, args) -> int:
        """Handle install command"""
        if not self.svc.validate_env_name(args.environment):
            print("❌ Invalid environment name")
            return 1

        pkg_result = self.svc.validate_packages(args.packages)
        if not pkg_result.success:
            print(f"❌ {pkg_result.message}")
            return 1

        print(f"⏳ Installing packages in '{args.environment}'...")
        result = self.svc.install_packages(
            args.environment,
            args.packages,
            conflict_check=not args.no_conflict_check,
            confirmed=getattr(args, 'yes', False),
        )

        return self._result_exit_code(result)

    def handle_remove(self, args) -> int:
        """Handle remove command"""
        if not self.svc.validate_env_name(args.environment):
            print("❌ Invalid environment name")
            return 1

        print(f"⏳ Removing environment '{args.environment}'...")
        result = self.svc.delete_environment(
            args.environment,
            create_backup=not args.no_backup,
            confirmed=getattr(args, 'yes', False),
        )

        return self._result_exit_code(result)

    def handle_info(self, args) -> int:
        """Handle info command"""
        result = self.svc.get_environment_info(args.environment)

        if not result.success:
            print(OutputFormatters.format_error_message(result.message))
            return 1

        env_info = result.data
        print(f"📊 Environment info: {args.environment}")
        print(f"   Packages: {env_info.get('package_count', 0)}")
        print(f"   Python: {env_info.get('python_version', 'unknown')}")

        vulnerabilities = env_info.get('security_issues', [])
        if vulnerabilities:
            print(f"   ⚠️  Vulnerabilities: {len(vulnerabilities)}")
            for vuln in vulnerabilities[:3]:
                print(f"      - {vuln.get('package')}: {vuln.get('issue')}")

        return 0

    def handle_update(self, args) -> int:
        """Handle update command"""
        if not self.svc.validate_env_name(args.environment):
            print("❌ Invalid environment name")
            return 1

        print(f"⏳ Updating packages in '{args.environment}'...")
        result = self.svc.update_packages(
            args.environment,
            args.packages or None,
            confirmed=getattr(args, 'yes', False),
        )

        return self._result_exit_code(result)

    def handle_backup(self, args) -> int:
        """Handle backup command"""
        if args.create:
            result = self.svc.create_backup(args.create)
            if result.success:
                print(OutputFormatters.format_success_message(result.message))
                return 0
            else:
                print(OutputFormatters.format_error_message(result.message))
                return 1

        elif args.list:
            result = self.svc.list_backups()
            if result.data:
                for backup in result.data:
                    print(OutputFormatters.format_backup_info(backup))
                return 0
            else:
                print("No backups available")
                return 0

        elif args.restore:
            result = self.svc.restore_backup(
                args.restore,
                confirmed=getattr(args, 'yes', False),
            )
            return self._result_exit_code(result)

        else:
            print("Must specify --create, --list, or --restore")
            return 1

    def handle_diagnostics(self, args) -> int:
        """Handle diagnostics command"""
        print("🔧 Running security diagnostics...")
        result = self.svc.run_diagnostics()
        print(OutputFormatters.format_diagnostics_report(result.data))
        if not result.success:
            return 1
        if result.data.get('overall_security_score', 0) < 50:
            return 2
        return 0

    def handle_audit(self, args) -> int:
        """Handle audit command"""
        result = self.svc.get_audit_trail(args.limit)
        print(OutputFormatters.format_audit_trail(result.data))
        return 0

    def handle_config(self, args) -> int:
        """Handle config command"""
        changed = False

        if args.security_level:
            result = self.svc.change_security_level(args.security_level)
            if not result.success:
                print(OutputFormatters.format_error_message(result.message))
                return 1
            print(OutputFormatters.format_success_message(result.message))
            changed = True

        if args.production_mode is not None:
            result = self.svc.set_production_mode(args.production_mode == 'on')
            if not result.success:
                print(OutputFormatters.format_error_message(result.message))
                return 1
            print(OutputFormatters.format_success_message(result.message))
            changed = True

        if not changed:
            print("Must specify --security-level or --production-mode")
            return 1
        return 0
