import os
import platform

import pytest

from awsprocesscreds.cache import JSONFileCache


@pytest.fixture
def file_cache(cache_dir):
    return JSONFileCache(cache_dir)


def test_supports_contains_check(file_cache):
    # By default the cache is empty because we're
    # using a new temp dir everytime.
    assert 'mykey' not in file_cache


def test_add_key_and_contains_check(file_cache):
    file_cache['mykey'] = {'spam': 'eggs'}
    assert 'mykey' in file_cache


def test_added_key_can_be_retrieved(file_cache):
    file_cache['mykey'] = {'spam': 'eggs'}
    assert file_cache['mykey'] == {'spam': 'eggs'}


def test_only_accepts_json_serializeable_data(file_cache):
    with pytest.raises(ValueError):
        file_cache['mykey'] = set()


def test_can_override_existing_values(file_cache):
    file_cache['mykey'] = {'spam': 'eggs'}
    file_cache['mykey'] = {'spamspam': 'spamspamspambaconspam'}
    assert file_cache['mykey'] == {'spamspam': 'spamspamspambaconspam'}


def test_can_add_multiple_keys(file_cache):
    file_cache['firstkey'] = {'spam': 'eggs'}
    file_cache['secondkey'] = {'spamspam': 'spamspamspambaconspam'}
    assert file_cache['firstkey'] == {'spam': 'eggs'}
    assert file_cache['secondkey'] == {'spamspam': 'spamspamspambaconspam'}


def test_working_dir_does_not_exist(cache_dir):
    working_dir = os.path.join(cache_dir, 'does-not-exist-yet')
    cache = JSONFileCache(working_dir)
    cache['spam'] = {'bacon': 'eggs'}
    assert cache['spam'] == {'bacon': 'eggs'}


def test_key_error_raised_when_cache_key_does_not_exist(file_cache):
    with pytest.raises(KeyError):
        file_cache['does-not-exist']


def test_file_is_truncated_before_writing(file_cache):
    file_cache['mykey'] = {
        'really long key in the cache': 'really long value in cache'
    }
    # Now overwrite it with a smaller value.
    file_cache['mykey'] = {'a': 'b'}
    assert file_cache['mykey'] == {'a': 'b'}


@pytest.mark.skipiff(
    platform.system() not in ['Darwin', 'Linux'],
    reason='File permissions tests not supported on Windows.'
)
def test_permissions_for_file_restricted(file_cache, cache_dir):
    file_cache['mykey'] = {'spam': 'eggs'}
    filename = os.path.join(cache_dir, 'mykey.json')
    assert os.stat(filename).st_mode & 0xFFF, 0o600
