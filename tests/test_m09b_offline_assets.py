"""M09-B local assets: no remote runtime dependencies and hostile ZIP rejection."""
import io
import json
import re
import zipfile
from pathlib import Path

import pytest

from ScoutSuite.output.html import HTMLReport, validate_asset_archive
from tests.fixtures import ROOT


def bundle(files):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w') as archive:
        for path, content in files.items():
            archive.writestr(path, content)
    stream.seek(0)
    return zipfile.ZipFile(stream)


def test_bundled_vendor_assets_are_offline_and_valid(tmp_path):
    html = HTMLReport(report_name='test', report_dir=str(tmp_path))
    path = Path(html.scout_report_data_path) / 'includes.zip'
    assert path.is_file()
    with zipfile.ZipFile(path) as archive:
        validate_asset_archive(archive)
    html.prepare_html_report_dir()
    manifest_path = tmp_path / 'scoutsuite-assets-manifest.json'
    manifest = json.loads(manifest_path.read_text(encoding='utf8'))
    assert manifest['schema_version'] == 1
    assert len(manifest['archive_sha256']) == 64
    assert len(manifest['files']['inc-jquery/jquery-3.3.1.min.js']) == 64
    html.prepare_html_report_dir()
    assert json.loads(manifest_path.read_text(encoding='utf8')) == manifest
    for name in ('inc-jquery/jquery-3.3.1.min.js',
                 'inc-handlebars/handlebars-v3.0.0.js',
                 'inc-bootstrap/js/bootstrap.min.js',
                 'inc-fontawesome/css/all.min.css',
                 'inc-scoutsuite/scoutsuite.js'):
        assert (tmp_path / name).is_file()


@pytest.mark.parametrize('dangerous', [
    '../escape.js', '/tmp/escape.js', 'inc-jquery/../escape.js',
    'inc-bootstrap/../../escape.js', 'inc-jquery\\evil.js',
    'scoutsuite-results/scoutsuite_results.js', 'inc-scoutsuite/helpers.js',
    'inc-jquery/other:stream.js',
])
def test_zip_members_cannot_escape_or_replace_report_files(dangerous):
    files = {
        'inc-bootstrap/css/bootstrap.min.css': 'a',
        'inc-bootstrap/css/bootstrap-light.min.css': 'b',
        'inc-bootstrap/js/bootstrap.min.js': 'c',
        'inc-fontawesome/css/all.min.css': 'd',
        'inc-handlebars/handlebars-v3.0.0.js': 'e',
        'inc-jquery/jquery-3.3.1.min.js': 'f',
        dangerous: 'content',
    }
    with bundle(files) as archive, pytest.raises(ValueError):
        validate_asset_archive(archive)


def test_incomplete_vendor_zip_is_rejected_before_extraction():
    with bundle({'inc-jquery/jquery-3.3.1.min.js': 'ok'}) as archive:
        with pytest.raises(ValueError, match='missing'):
            validate_asset_archive(archive)


def test_no_network_dependency_in_report_shell():
    shell = (ROOT / 'ScoutSuite/output/data/html/report.html').read_text(encoding='utf8')
    assert not re.search(r'(?:src|href)\s*=\s*"https?://', shell, re.I)
    assert 'Content-Security-Policy' in shell
    assert "object-src 'none'" in shell
    assert "default-src 'none'" in shell
    assert "referrer" in shell

def test_existing_asset_root_symlink_does_not_redirect_extraction(tmp_path):
    outside = tmp_path / 'outside'
    outside.mkdir()
    report_dir = tmp_path / 'report'
    report_dir.mkdir()
    try:
        (report_dir / 'inc-jquery').symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip('Cannot create test symlink on this runner')
    html = HTMLReport(report_name='test', report_dir=str(report_dir))
    with pytest.raises(ValueError, match='destination'):
        html.prepare_html_report_dir()
    assert not (outside / 'jquery-3.3.1.min.js').exists()
