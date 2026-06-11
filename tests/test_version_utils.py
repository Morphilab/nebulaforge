"""
Tests for utils/version_utils.py
"""

from nebulaforge.utils.version_utils import version_in_range


def test_less_than():
    assert version_in_range('1.0.0', '<2.0.0')


def test_less_than_false():
    assert not version_in_range('3.0.0', '<2.0.0')


def test_less_equal():
    assert version_in_range('1.0.0', '<=1.0.0')
    assert version_in_range('1.0.0', '<=2.0.0')


def test_less_equal_false():
    assert not version_in_range('2.0.0', '<=1.0.0')


def test_greater_than():
    assert version_in_range('2.0.0', '>1.0.0')


def test_greater_than_false():
    assert not version_in_range('1.0.0', '>2.0.0')


def test_greater_equal():
    assert version_in_range('2.0.0', '>=2.0.0')
    assert version_in_range('3.0.0', '>=2.0.0')


def test_equal():
    assert version_in_range('1.0.0', '==1.0.0')


def test_equal_false():
    assert not version_in_range('2.0.0', '==1.0.0')


def test_invalid_range_returns_false():
    assert not version_in_range('1.0.0', 'invalid')


def test_invalid_version_returns_false():
    assert not version_in_range('not-a-version', '<1.0.0')


def test_bare_version_exact_match():
    assert version_in_range('1.0.0', '1.0.0')


def test_bare_version_mismatch():
    assert not version_in_range('1.0.0', '2.0.0')


def test_bare_version_with_equals_prefix():
    assert version_in_range('1.0.0', '=1.0.0')
    assert not version_in_range('2.0.0', '=1.0.0')
