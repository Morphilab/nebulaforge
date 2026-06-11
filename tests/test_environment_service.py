"""
Tests for core/environment_service.py
"""

from unittest.mock import MagicMock, patch

from nebulaforge.core.environment_service import EnvironmentService, ServiceResult


def _mock_service():
    with patch('nebulaforge.core.environment_service.SecurityManager') as MockSM, \
         patch('nebulaforge.core.environment_service.SecurityValidator') as MockSV:
        sv_instance = MockSV.return_value
        sv_instance.validate_env_name.return_value = True
        sv_instance.validate_package_list.return_value = (True, [])
        sv_instance.validate_filename.return_value = True

        sm_instance = MockSM.return_value
        sm_instance.list_environments.return_value = (True, ['env1', 'env2'])
        sm_instance.create_secure_environment.return_value = (True, 'Created')
        sm_instance.get_environment_info.return_value = {'name': 'env1', 'package_count': 5, 'python_version': '3.10'}
        sm_instance.install_packages.return_value = (True, 'Installed')
        sm_instance.update_packages.return_value = (True, 'Updated')
        sm_instance.delete_environment.return_value = (True, 'Deleted')
        sm_instance.clone_environment.return_value = (True, 'Cloned')
        sm_instance.export_environment.return_value = (True, 'Exported')
        sm_instance.import_environment.return_value = (True, 'Imported')
        sm_instance.run_security_diagnostics.return_value = {'overall_security_score': 85, 'overall_status': 'good'}
        sm_instance.get_audit_trail.return_value = []
        sm_instance.change_security_level.return_value = True
        sm_instance.dependency_checker = MagicMock()
        sm_instance.dependency_checker.check_vulnerabilities.return_value = []
        sm_instance.dependency_checker.get_outdated_packages.return_value = []
        sm_instance.get_system_status.return_value = {'security_profile': 'medium', 'environments_count': 2}
        sm_instance.config_manager.security_profiles = {'low': {}, 'medium': {}, 'high': {}}

        return EnvironmentService.__new__(EnvironmentService), sm_instance, sv_instance


def test_service_result_namedtuple():
    r = ServiceResult(True, 'ok')
    assert r.success is True
    assert r.message == 'ok'
    assert r.data is None


def test_service_result_with_data():
    r = ServiceResult(False, 'fail', ['bad-pkg'])
    assert r.success is False
    assert r.data == ['bad-pkg']


def test_validate_env_name_delegates():
    svc, sm, sv = _mock_service()
    sv.validate_env_name.return_value = True
    svc.validator = sv
    assert svc.validate_env_name('good_env') is True


def test_validate_env_name_fails():
    svc, sm, sv = _mock_service()
    sv.validate_env_name.return_value = False
    svc.validator = sv
    assert svc.validate_env_name('bad name!') is False


def test_validate_packages_valid():
    svc, sm, sv = _mock_service()
    sv.validate_package_list.return_value = (True, [])
    svc.validator = sv
    result = svc.validate_packages(['numpy', 'pandas'])
    assert result.success is True


def test_validate_packages_invalid():
    svc, sm, sv = _mock_service()
    sv.validate_package_list.return_value = (False, ['hack-pkg'])
    svc.validator = sv
    result = svc.validate_packages(['hack-pkg'])
    assert result.success is False
    assert 'Invalid' in result.message


def test_list_environments():
    svc, sm, sv = _mock_service()
    svc.sm = sm
    result = svc.list_environments()
    assert result.success is True
    assert result.data == ['env1', 'env2']


def test_list_environments_fails():
    svc, sm, sv = _mock_service()
    sm.list_environments.return_value = (False, 'error')
    svc.sm = sm
    result = svc.list_environments()
    assert result.success is False


def test_create_environment_success():
    svc, sm, sv = _mock_service()
    svc.sm = sm
    svc.validator = sv
    result = svc.create_environment('myenv', '3.10', ['numpy'])
    assert result.success is True
    assert result.message == 'Created'


def test_create_environment_invalid_name():
    svc, sm, sv = _mock_service()
    sv.validate_env_name.return_value = False
    svc.validator = sv
    result = svc.create_environment('bad name!')
    assert result.success is False
    assert 'Invalid' in result.message


def test_create_environment_invalid_packages():
    svc, sm, sv = _mock_service()
    sv.validate_package_list.return_value = (False, ['hack-pkg'])
    svc.validator = sv
    result = svc.create_environment('myenv', packages=['hack-pkg'])
    assert result.success is False
    assert 'Invalid' in result.message


def test_get_environment_info():
    svc, sm, sv = _mock_service()
    sm.get_environment_info.return_value = {'name': 'env1', 'packages': ['numpy']}
    svc.sm = sm
    result = svc.get_environment_info('env1')
    assert result.success is True


def test_get_environment_info_error():
    svc, sm, sv = _mock_service()
    sm.get_environment_info.return_value = {'error': 'not found'}
    svc.sm = sm
    result = svc.get_environment_info('nonexistent')
    assert result.success is False
    assert 'not found' in result.message


def test_install_packages():
    svc, sm, sv = _mock_service()
    svc.sm = sm
    svc.validator = sv
    result = svc.install_packages('myenv', ['numpy'])
    assert result.success is True


def test_install_packages_invalid_name():
    svc, sm, sv = _mock_service()
    sv.validate_env_name.return_value = False
    svc.validator = sv
    result = svc.install_packages('bad name!', ['numpy'])
    assert result.success is False


def test_install_packages_invalid_pkg():
    svc, sm, sv = _mock_service()
    sv.validate_package_list.return_value = (False, ['hack-pkg'])
    svc.validator = sv
    result = svc.install_packages('myenv', ['hack-pkg'])
    assert result.success is False


def test_delete_environment():
    svc, sm, sv = _mock_service()
    svc.sm = sm
    svc.validator = sv
    result = svc.delete_environment('myenv')
    assert result.success is True


def test_delete_environment_invalid_name():
    svc, sm, sv = _mock_service()
    sv.validate_env_name.return_value = False
    svc.validator = sv
    result = svc.delete_environment('bad name!')
    assert result.success is False


def test_clone_environment():
    svc, sm, sv = _mock_service()
    svc.sm = sm
    svc.validator = sv
    result = svc.clone_environment('source', 'target')
    assert result.success is True


def test_clone_environment_invalid_source():
    svc, sm, sv = _mock_service()
    sv.validate_env_name.side_effect = lambda n: n == 'target'
    svc.validator = sv
    result = svc.clone_environment('bad!', 'target')
    assert result.success is False


def test_export_environment(tmp_path):
    svc, sm, sv = _mock_service()
    svc.sm = sm
    svc.validator = sv
    f = tmp_path / 'env.yml'
    result = svc.export_environment('myenv', str(f))
    assert result.success is True


def test_export_environment_invalid_filename():
    svc, sm, sv = _mock_service()
    sv.validate_filename.return_value = False
    svc.validator = sv
    result = svc.export_environment('myenv', '../bad/path')
    assert result.success is False


def test_import_environment(tmp_path):
    svc, sm, sv = _mock_service()
    svc.sm = sm
    f = tmp_path / 'env.yml'
    f.write_text('name: test')
    result = svc.import_environment(f)
    assert result.success is True


def test_import_environment_file_not_found(tmp_path):
    svc, sm, sv = _mock_service()
    svc.sm = sm
    from pathlib import Path
    result = svc.import_environment(Path('/nonexistent/file.yml'))
    assert result.success is False
    assert 'not found' in result.message


def test_run_diagnostics():
    svc, sm, sv = _mock_service()
    svc.sm = sm
    result = svc.run_diagnostics()
    assert result.success is True
    assert result.data['overall_security_score'] == 85


def test_run_diagnostics_handles_exception():
    svc, sm, sv = _mock_service()
    sm.run_security_diagnostics.side_effect = Exception('boom')
    svc.sm = sm
    result = svc.run_diagnostics()
    assert result.success is False
    assert 'boom' in result.message


def test_get_audit_trail():
    svc, sm, sv = _mock_service()
    sm.get_audit_trail.return_value = [{'action': 'test'}]
    svc.sm = sm
    result = svc.get_audit_trail()
    assert result.success is True
    assert len(result.data) == 1


def test_get_available_profiles():
    svc, sm, sv = _mock_service()
    svc.sm = sm
    profiles = svc.get_available_profiles()
    assert 'low' in profiles
    assert 'medium' in profiles
    assert 'high' in profiles


def test_change_security_level_valid():
    svc, sm, sv = _mock_service()
    svc.sm = sm
    result = svc.change_security_level('high')
    assert result.success is True


def test_change_security_level_invalid():
    svc, sm, sv = _mock_service()
    svc.sm = sm
    result = svc.change_security_level('paranoid')
    assert result.success is False
    assert 'Unknown' in result.message


def test_get_system_status():
    svc, sm, sv = _mock_service()
    svc.sm = sm
    status = svc.get_system_status()
    assert status['security_profile'] == 'medium'
    assert status['environments_count'] == 2


def test_unlock_credentials_delegates():
    svc, sm, sv = _mock_service()
    svc.sm = sm
    svc.unlock_credentials('mypass')
    sm.unlock_credentials.assert_called_once_with('mypass')


def test_unlock_secure_store_delegates():
    svc, sm, sv = _mock_service()
    svc.sm = sm
    svc.unlock_secure_store('mypass')
    sm.unlock_secure_store.assert_called_once_with('mypass')


def test_store_credential_delegates():
    svc, sm, sv = _mock_service()
    svc.sm = sm
    svc.store_credential('github', 'user', 'pass')
    sm.store_credential.assert_called_once_with('github', 'user', 'pass')


def test_get_credential_delegates():
    svc, sm, sv = _mock_service()
    svc.sm = sm
    sm.get_credential.return_value = {'username': 'u', 'password': 'p'}
    result = svc.get_credential('github')
    assert result['username'] == 'u'


def test_get_current_profile_name():
    svc, sm, sv = _mock_service()
    svc.sm = sm
    name = svc.get_current_profile_name()
    assert name is not None


def test_require_confirmation_delegates():
    svc, sm, sv = _mock_service()
    sm.require_confirmation_for.return_value = True
    svc.sm = sm
    assert svc.require_confirmation_for('delete', 'env1') is True
