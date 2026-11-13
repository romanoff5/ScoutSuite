"""P0: public EC2/443 candidate based on ENI + attached SG, with UNKNOWN gaps."""
import json
from pathlib import Path

from ScoutSuite.providers.aws.resources.ec2.direct_https import classify_direct_public_https
from ScoutSuite.core.rule_evidence import classify_ec2_direct_public_https


def _group(port='443', cidr='0.0.0.0/0', protocol='TCP'):
    return {'rules': {'ingress': {'protocols': {
        protocol: {'ports': {port: {'cidrs': [{'CIDR': cidr}]}}}
    }}}}


def _instance(public_ip=True, ipv6=None, sg='sg-test'):
    eni = {'Groups': [{'GroupId': sg}], 'Association': {
        'PublicIp': '198.51.100.10'} if public_ip else {}}
    if ipv6 is not None:
        eni['Ipv6Addresses'] = [{'Ipv6Address': ipv6}]
    return {'State': {'Name': 'running'}, 'network_interfaces': {'eni-test': eni}}


def test_world_open_https_including_ranges_and_all():
    for group in (_group(), _group('400-500'), _group('1-65535'),
                  _group('1-65535', protocol='ALL')):
        status = classify_direct_public_https(_instance(), {'sg-test': group})
        assert status == 'exposed'
        assert classify_ec2_direct_public_https({'public_https_status': status}) == 'insecure'


def test_public_ip_without_world_open_443_is_not_flagged():
    for group in (_group('22'), _group('443', '10.0.0.0/8'),
                  _group('443', '2001:db8::/32')):
        assert classify_direct_public_https(_instance(), {'sg-test': group}) == 'not_exposed'
    assert classify_direct_public_https(_instance(public_ip=False), {
        'sg-test': _group()}) == 'not_exposed'


def test_ipv6_public_exposure_and_private_ipv6():
    assert classify_direct_public_https(_instance(False, '2600:1::1'), {
        'sg-test': _group('443', '::/0')}) == 'exposed'
    assert classify_direct_public_https(_instance(False, 'fd00::1'), {
        'sg-test': _group('443', '::/0')}) == 'not_exposed'


def test_missing_groups_do_not_become_clean():
    instance = _instance()
    assert classify_direct_public_https(instance, {}) == 'unknown'
    assert classify_direct_public_https(instance, None) == 'unknown'
    assert classify_ec2_direct_public_https({'public_https_status': 'unknown'}) == 'unknown'


def test_p0_rule_is_in_default_profile():
    root = Path(__file__).resolve().parents[1] / 'ScoutSuite/providers/aws/rules'
    rule = json.loads((root / 'findings/ec2-public-instance-https-open-to-world.json').read_text())
    profile = json.loads((root / 'rulesets/default.json').read_text())
    assert rule['evidence_policy'] == 'ec2-direct-public-https-v1'
    assert profile['rules']['ec2-public-instance-https-open-to-world.json'][0]['enabled'] is True

def test_stopped_instance_not_reported_as_live_exposure():
    instance = _instance()
    instance['State'] = {'Name': 'stopped'}
    status = classify_direct_public_https(instance, {'sg-test': _group()})
    assert status == 'not_applicable'
    assert classify_ec2_direct_public_https({'public_https_status': status}) == 'not_applicable'
    instance['State'] = {'Name': 'pending'}
    assert classify_direct_public_https(instance, {'sg-test': _group()}) == 'unknown'
    del instance['State']
    assert classify_direct_public_https(instance, {'sg-test': _group()}) == 'unknown'
