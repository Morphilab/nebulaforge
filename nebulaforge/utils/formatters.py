"""
NebulaForge - Output formatting utilities
"""

from typing import Dict, List


class Icons:
    REPORT = "\U0001F527"
    STATS = "\U0001F4CA"
    LOCK = "\U0001F510"
    BULB = "\U0001F4A1"
    EMPTY = "\U0001F4ED"
    TARGET = "\U0001F3AF"
    CLOCK = "\U0001F552"
    CHECK = "\u2705"
    CROSS = "\u274C"
    WARN = "\u26A0\uFE0F"
    PACKAGE = "\U0001F4E6"
    ARROW = "\u2192"


class OutputFormatters:
    """Output formatters with configurable icons"""

    use_icons: bool = True

    @staticmethod
    def _maybe(text: str, icon: str) -> str:
        return f"{icon} {text}" if OutputFormatters.use_icons else text

    @staticmethod
    def format_diagnostics_report(d: Dict) -> str:
        lines = [OutputFormatters._maybe("Security Diagnostics Report", Icons.REPORT),
                 "=" * 60]
        score = d.get('overall_security_score', 0)
        status = d.get('overall_status', 'unknown')
        lines.append(
            OutputFormatters._maybe(
                f"General Status: {status.upper()} (Score: {score}/100)",
                Icons.STATS
            )
        )

        profile = d.get('security_status', {}).get('security_profile', {})
        if profile:
            lines.append(
                OutputFormatters._maybe(
                    f"Profile: {profile.get('current', 'N/A')} ({profile.get('level', 'N/A')})",
                    Icons.LOCK
                )
            )

        recommendations = d.get('recommendations', [])
        if recommendations:
            lines.append(f"\n{OutputFormatters._maybe('Recommendations:', Icons.BULB)}")
            for r in recommendations:
                lines.append(f"   \u2022 {r}")
        return "\n".join(lines)

    @staticmethod
    def format_environment_list(envs: List[str]) -> str:
        if not envs:
            return OutputFormatters._maybe("No environments available", Icons.EMPTY)
        out = [OutputFormatters._maybe("Available Environments", Icons.TARGET),
               "\u2500" * 40]
        for i, e in enumerate(envs, 1):
            out.append(f"{i:2d}. {e}")
        out.append(f"\n{OutputFormatters._maybe(f'Total: {len(envs)} environments', Icons.STATS)}")
        return "\n".join(out)

    @staticmethod
    def format_audit_trail(trail: List[Dict]) -> str:
        if not trail:
            return OutputFormatters._maybe("No audit records", Icons.STATS)
        lines = [OutputFormatters._maybe("Audit Records", Icons.STATS),
                 "\u2500" * 65]
        for entry in reversed(trail):
            ts = entry.get('timestamp', 'N/A')
            lines.append(OutputFormatters._maybe(ts, Icons.CLOCK))
            action = entry.get('action', 'N/A')
            target = entry.get('target', 'N/A')
            status = entry.get('status', 'N/A')
            lines.append(f"   {action} {Icons.ARROW} {target} [{status}]")
        return "\n".join(lines)

    @staticmethod
    def format_success_message(msg: str) -> str:
        return OutputFormatters._maybe(msg, Icons.CHECK)

    @staticmethod
    def format_error_message(msg: str) -> str:
        return OutputFormatters._maybe(msg, Icons.CROSS)

    @staticmethod
    def format_warning_message(msg: str) -> str:
        return OutputFormatters._maybe(msg, Icons.WARN)

    @staticmethod
    def format_backup_info(backup: Dict) -> str:
        name = backup.get('env_name', 'Unknown')
        created = backup.get('created_time', '')
        deps = backup.get('dependencies_count', 0)
        return OutputFormatters._maybe(f"{name} | {created} | {deps} packages", Icons.PACKAGE)

    @staticmethod
    def format_environment_info(env_info: Dict) -> str:
        lines = [
            OutputFormatters._maybe(
                f"Environment: {env_info.get('name', 'Unknown')}", Icons.STATS
            ),
            f"   Packages: {env_info.get('package_count', 0)}",
            f"   Python: {env_info.get('python_version', 'unknown')}"
        ]
        return "\n".join(lines)

    @staticmethod
    def format_package_list(packages: List[Dict]) -> str:
        if not packages:
            return "No packages"
        lines = [OutputFormatters._maybe("Installed packages:", Icons.PACKAGE)]
        for pkg in packages[:20]:
            lines.append(
                f"   \u2022 {pkg.get('name', 'Unknown')} == {pkg.get('version', 'unknown')}"
            )
        if len(packages) > 20:
            lines.append(f"   ... and {len(packages) - 20} more")
        return "\n".join(lines)
