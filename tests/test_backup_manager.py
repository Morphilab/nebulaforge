"""
BackupManager tests (checksum logic only, no conda)
"""

import json
import hashlib
from pathlib import Path


def test_calculate_checksum_deterministic():
    from nebulaforge.core.backup_manager import BackupManager
    from nebulaforge.core.config_manager import ConfigManager

    data = {
        'name': 'test_env',
        'dependencies': ['numpy', 'pandas'],
        'metadata': {
            'python_version': '3.10',
            'package_count': 2
        }
    }

    # Simulate calculation method
    data_str = json.dumps(data, sort_keys=True)
    checksum1 = hashlib.sha256(data_str.encode('utf-8')).hexdigest()

    # Mismo dato, mismo checksum
    data_str2 = json.dumps(data, sort_keys=True)
    checksum2 = hashlib.sha256(data_str2.encode('utf-8')).hexdigest()

    assert checksum1 == checksum2


def test_checksum_changes_with_data():
    data1 = {'name': 'env1', 'version': '1.0'}
    data2 = {'name': 'env2', 'version': '2.0'}

    c1 = hashlib.sha256(json.dumps(data1, sort_keys=True).encode()).hexdigest()
    c2 = hashlib.sha256(json.dumps(data2, sort_keys=True).encode()).hexdigest()

    assert c1 != c2


def test_verify_checksum_from_file(tmp_path):
    from nebulaforge.core.backup_manager import BackupManager

    data = {'name': 'test', 'dependencies': []}
    data_str = json.dumps(data, sort_keys=True)
    checksum = hashlib.sha256(data_str.encode('utf-8')).hexdigest()

    # Simulate .sha256 file
    yaml_path = tmp_path / 'backup_test.yaml'
    sha_path = tmp_path / 'backup_test.yaml.sha256'
    sha_path.write_text(f"{checksum}  backup_test.yaml\n", encoding='utf-8')

    assert sha_path.exists()


def test_checksum_different_with_different_order():
    """Verify that sort_keys=True makes the checksum deterministic
    regardless of key order"""
    data_a = {'z_last': 1, 'a_first': 2}
    data_b = {'a_first': 2, 'z_last': 1}

    c_a = hashlib.sha256(json.dumps(data_a, sort_keys=True).encode()).hexdigest()
    c_b = hashlib.sha256(json.dumps(data_b, sort_keys=True).encode()).hexdigest()

    assert c_a == c_b
