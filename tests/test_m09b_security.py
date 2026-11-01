"""M09-B offline asset and local report API hardening regression tests."""
import io
from html.parser import HTMLParser
import stat
import zipfile
from pathlib import Path

import pytest

from ScoutSuite.output.html import safe_extract_report_assets
from ScoutSuite.core.server import Server, MAX_PAGE_SIZE


def archive_with(name, payload=b'ok', symlink=False):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w') as z:
        info = zipfile.ZipInfo(name)
        if symlink:
            info.create_system = 3
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
        z.writestr(info, payload)
    stream.seek(0)
    return zipfile.ZipFile(stream)


def test_approved_local_assets_extract(tmp_path):
    with archive_with('inc-fontawesome/css/all.min.css') as z:
        safe_extract_report_assets(z, tmp_path)
    assert (tmp_path / 'inc-fontawesome/css/all.min.css').read_bytes() == b'ok'


@pytest.mark.parametrize('path', [
    '../payload.txt', '/tmp/escape', 'inc-fontawesome/../../escape',
    'inc-fontawesome/../evil.txt', 'other-dir/file.txt',
    'inc-fontawesome\\css\\evil.txt', 'inc-fontawesome//double.txt',
])
def test_zip_traversal_and_unapproved_paths_are_rejected(tmp_path, path):
    with archive_with(path) as z:
        with pytest.raises(ValueError):
            safe_extract_report_assets(z, tmp_path)
    assert not list(tmp_path.iterdir())


def test_zip_symlink_and_existing_symlink_destinations_are_rejected(tmp_path):
    with archive_with('inc-jquery/evil', symlink=True) as z:
        with pytest.raises(ValueError):
            safe_extract_report_assets(z, tmp_path)
    outside = tmp_path.parent / 'outside-test'
    outside.mkdir(exist_ok=True)
    (tmp_path / 'inc-jquery').symlink_to(outside, target_is_directory=True)
    with archive_with('inc-jquery/file.js') as z:
        with pytest.raises(ValueError):
            safe_extract_report_assets(z, tmp_path)
    assert not (outside / 'file.js').exists()


@pytest.mark.parametrize('key', [
    '../secret', 'a¤..¤b', 'foo¤__class__', 'services¤constructor',
    'a¤prototype', 'a¤¤b', 'a\\\\secret', 'a/secret', 'x' * 2049,
])
def test_api_rejects_malformed_or_prototype_paths(key):
    import cherrypy
    with pytest.raises(cherrypy.HTTPError) as error:
        Server.get_item({'a': {'b': 1}}, key)
    assert error.value.status == 400


def test_api_rejects_missing_keys_and_invalid_array_indices():
    import cherrypy
    for key in ['missing', 'a¤9999']:
        with pytest.raises(cherrypy.HTTPError):
            Server.get_item({'a': [1]}, key)
    assert Server.get_item({'a': [1, 2]}, 'a¤1') == 2


@pytest.mark.parametrize('value', [
    '-1', '1e5', 'NaN', '3.0', '99999999999999999999999', 'abc', None,
])
def test_pagination_rejects_invalid_numbers(value):
    import cherrypy
    with pytest.raises(cherrypy.HTTPError):
        Server.parse_bounded_integer(value, MAX_PAGE_SIZE, minimum=1)
    assert Server.parse_bounded_integer('100', MAX_PAGE_SIZE, minimum=1) == 100


def test_report_has_no_remote_assets_or_unsafe_eval():
    root = Path(__file__).resolve().parents[1] / 'ScoutSuite/output/data'
    html = (root / 'html/report.html').read_text(encoding='utf-8')
    helper = (root / 'inc-scoutsuite/helpers.js').read_text(encoding='utf-8')
    script = (root / 'inc-scoutsuite/scoutsuite.js').read_text(encoding='utf-8')
    class RemoteResources(HTMLParser):
        def __init__(self):
            super().__init__()
            self.external = []

        def handle_starttag(self, tag, attrs):
            if tag in ('script', 'link'):
                self.external.extend(value for key, value in attrs
                                     if key in ('src', 'href') and value and
                                     value.startswith(('http://', 'https://')))

    parser = RemoteResources()
    parser.feed(html)
    assert parser.external == []
    assert 'eval(JSON.stringify(entities))' not in helper + script
    assert 'element.innerHTML = value' not in script
    assert "delete body['description']" not in helper
    assert "delete rule[attribute]" not in helper
