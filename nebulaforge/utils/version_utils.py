"""
NebulaForge - Version comparison utilities
"""

from packaging import version as pkg_version


def version_in_range(version: str, version_range: str) -> bool:
    try:
        parsed_version = pkg_version.parse(version)
        if version_range.startswith('<='):
            return parsed_version <= pkg_version.parse(version_range[2:])
        if version_range.startswith('>='):
            return parsed_version >= pkg_version.parse(version_range[2:])
        if version_range.startswith('<'):
            return parsed_version < pkg_version.parse(version_range[1:])
        if version_range.startswith('>'):
            return parsed_version > pkg_version.parse(version_range[1:])
        if version_range.startswith('=='):
            return parsed_version == pkg_version.parse(version_range[2:])
        if version_range.startswith('='):
            return parsed_version == pkg_version.parse(version_range[1:])
        # No prefix: treat as exact equality
        return parsed_version == pkg_version.parse(version_range)
    except Exception:
        return False
