"""
Tests for output formatters
"""

from nebulaforge.utils.formatters import OutputFormatters, Icons


def test_format_success_message_with_icons():
    OutputFormatters.use_icons = True
    assert OutputFormatters.format_success_message("Environment created") == "✅ Environment created"


def test_format_success_message_without_icons():
    OutputFormatters.use_icons = False
    assert OutputFormatters.format_success_message("Environment created") == "Environment created"


def test_format_environment_list_with_icons():
    OutputFormatters.use_icons = True
    envs = ["base", "my_env", "project"]
    result = OutputFormatters.format_environment_list(envs)
    assert "Available Environments" in result
    assert "base" in result


def test_format_environment_list_without_icons():
    OutputFormatters.use_icons = False
    result = OutputFormatters.format_environment_list([])
    assert "No environments available" == result
    assert "📭" not in result


def test_format_environment_list_empty_with_icons():
    OutputFormatters.use_icons = True
    result = OutputFormatters.format_environment_list([])
    assert "📭" in result


def test_format_error_message_with_icons():
    OutputFormatters.use_icons = True
    assert "❌" in OutputFormatters.format_error_message("Failed")


def test_format_error_message_without_icons():
    OutputFormatters.use_icons = False
    assert "❌" not in OutputFormatters.format_error_message("Failed")
    assert OutputFormatters.format_error_message("Failed") == "Failed"


def test_format_warning_message_with_icons():
    OutputFormatters.use_icons = True
    assert "⚠️" in OutputFormatters.format_warning_message("Warning")


def test_format_warning_message_without_icons():
    OutputFormatters.use_icons = False
    assert "⚠️" not in OutputFormatters.format_warning_message("Warning")
    assert OutputFormatters.format_warning_message("Warning") == "Warning"


def test_format_diagnostics_report_with_icons():
    OutputFormatters.use_icons = True
    d = {'overall_security_score': 85, 'overall_status': 'good', 'recommendations': []}
    r = OutputFormatters.format_diagnostics_report(d)
    assert "🔧" in r


def test_format_diagnostics_report_without_icons():
    OutputFormatters.use_icons = False
    d = {'overall_security_score': 85, 'overall_status': 'good', 'recommendations': []}
    r = OutputFormatters.format_diagnostics_report(d)
    assert "🔧" not in r
    assert "Security Diagnostics Report" in r


def test_format_backup_info_with_icons():
    OutputFormatters.use_icons = True
    b = {'env_name': 'test', 'created_time': 'now', 'dependencies_count': 10}
    r = OutputFormatters.format_backup_info(b)
    assert "📦" in r


def test_format_backup_info_without_icons():
    OutputFormatters.use_icons = False
    b = {'env_name': 'test', 'created_time': 'now', 'dependencies_count': 10}
    r = OutputFormatters.format_backup_info(b)
    assert "📦" not in r
    assert "test | now | 10 packages" == r


def test_icons_class_attributes():
    assert Icons.CHECK == "✅"
    assert Icons.CROSS == "❌"
    assert Icons.WARN == "⚠️"


def test_format_audit_trail_empty_with_icons():
    OutputFormatters.use_icons = True
    r = OutputFormatters.format_audit_trail([])
    assert "📊" in r


def test_format_audit_trail_empty_without_icons():
    OutputFormatters.use_icons = False
    r = OutputFormatters.format_audit_trail([])
    assert "📊" not in r
    assert "No audit records" == r


def test_format_package_list():
    OutputFormatters.use_icons = True
    pkgs = [{'name': 'numpy', 'version': '1.21.0'}]
    r = OutputFormatters.format_package_list(pkgs)
    assert "numpy" in r
    assert "1.21.0" in r


def test_format_environment_info():
    OutputFormatters.use_icons = True
    info = {'name': 'myenv', 'package_count': 10, 'python_version': '3.10'}
    r = OutputFormatters.format_environment_info(info)
    assert "myenv" in r
    assert "3.10" in r


def test_format_package_list_truncated():
    OutputFormatters.use_icons = True
    pkgs = [{'name': f'pkg{i}', 'version': '1.0'} for i in range(30)]
    r = OutputFormatters.format_package_list(pkgs)
    assert "... and 10 more" in r


def test_format_package_list_empty():
    r = OutputFormatters.format_package_list([])
    assert r == "No packages"