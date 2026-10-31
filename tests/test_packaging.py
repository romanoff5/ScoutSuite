"""Dependency contracts, checked without downloading or building in pytest."""

import importlib.metadata
import tomllib

from packaging.markers import default_environment
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

from tests.fixtures import ROOT


def requirements(path):
    result = []
    for line in path.read_text(encoding='utf-8').splitlines():
        line = line.strip()
        if line.startswith('-r '):
            result.extend(requirements(path.parent / line[3:]))
        elif line and not line.startswith('#'):
            result.append(Requirement(line))
    return result


def test_requirement_syntax_and_default_install_contract():
    default = requirements(ROOT / 'requirements.txt')
    assert len(default) == 49
    requirements(ROOT / 'dev-requirements.txt')
    core = requirements(ROOT / 'requirements-core.txt')
    aws = requirements(ROOT / 'requirements-aws.txt')
    declared = {canonicalize_name(req.name): req for req in default}
    for req in core + aws:
        assert req == declared[canonicalize_name(req.name)]
    assert 'policyuniverse' in {canonicalize_name(req.name) for req in core}
    metadata = tomllib.loads((ROOT / 'pyproject.toml').read_text())
    assert metadata['project']['scripts']['scout'] == 'ScoutSuite.__main__:run_from_cli'


def test_aws_core_constraints_cover_transitive_requirements():
    constraints = {canonicalize_name(req.name): req
                   for req in requirements(ROOT / 'constraints/aws-core-py311.txt')}
    # Check the installed platform's complete graph. The suite is run on both
    # Windows and Linux; foreign-platform distributions are not faked or skipped.
    env = dict(default_environment(), extra='')
    pending = requirements(ROOT / 'requirements-aws.txt')
    seen = set()
    while pending:
        req = pending.pop()
        if req.marker and not req.marker.evaluate(env):
            continue
        name = canonicalize_name(req.name)
        pinned = constraints[name]
        assert pinned.marker is None or pinned.marker.evaluate(env)
        specifier, = pinned.specifier
        assert specifier.operator == '==' and '*' not in specifier.version
        assert specifier.version in req.specifier
        if name not in seen:
            seen.add(name)
            pending.extend(Requirement(text) for text in importlib.metadata.requires(name) or [])
