"""M11: contracts against real installed SDK classes, without cloud credentials or HTTP."""

import asyncio
import inspect
from types import SimpleNamespace
from unittest.mock import Mock, patch

from azure.mgmt.sql import SqlManagementClient
from google.cloud import kms_v1, monitoring_v3

from ScoutSuite.output.result_encoder import ScoutResultEncoder
from ScoutSuite.providers.azure.facade.sqldatabase import SQLDatabaseFacade, _normalize_sql
from ScoutSuite.providers.azure.resources.sqldatabase.database_threat_detection_policies import (
    DatabaseThreatDetectionPolicies,
)
from ScoutSuite.providers.azure.resources.sqldatabase.server_security_alert_policies import (
    ServerSecurityAlertPolicies,
)
from ScoutSuite.providers.gcp.facade.kms import KMSFacade
from ScoutSuite.providers.gcp.facade.stackdrivermonitoring import StackdriverMonitoringFacade
from ScoutSuite.providers.gcp.resources.kms.keyrings import KeyRings
from ScoutSuite.providers.gcp.resources.stackdrivermonitoring.monitoring_alert_policies import (
    MonitoringAlertPolicies,
)


async def _immediate(func):
    return func()


def test_gcp_real_sdk_client_contracts_and_keyring_model():
    # Validate callable SDK symbols as well as actual collector arguments below.
    assert 'request' in inspect.signature(
        kms_v1.KeyManagementServiceClient.list_key_rings).parameters
    assert 'request' in inspect.signature(
        monitoring_v3.AlertPolicyServiceClient.list_alert_policies).parameters
    assert 'request' in inspect.signature(
        monitoring_v3.UptimeCheckServiceClient.list_uptime_check_configs).parameters
    key = kms_v1.types.KeyRing(name='projects/demo/locations/eu/keyRings/demo-ring')
    key_id, record = KeyRings._parse_keyring(None, key, 'eu')
    assert key_id == key.name
    assert record == {'id': key.name, 'name': 'demo-ring', 'location': 'eu'}


def test_gcp_kms_preserves_location_ids_and_pagination():
    facade = object.__new__(KMSFacade)
    client = Mock()
    client.list_key_rings.return_value = iter([
        kms_v1.types.KeyRing(name='projects/demo/locations/eu/keyRings/ring-1'),
        kms_v1.types.KeyRing(name='projects/demo/locations/eu/keyRings/ring-2'),
    ])
    facade.cloud_client = client

    async def locations(_project):
        return [{'locationId': 'eu'}]

    with patch.object(facade, 'get_locations', locations), patch(
        'ScoutSuite.providers.gcp.facade.kms.run_concurrently', _immediate
    ):
        result = asyncio.run(facade.list_key_rings('demo'))
    client.list_key_rings.assert_called_once_with(
        request={'parent': 'projects/demo/locations/eu'})
    assert len(result['eu']) == 2
    assert [entry.name.rsplit('/', 1)[-1] for entry in result['eu']] == ['ring-1', 'ring-2']


def test_gcp_monitoring_request_envelopes_and_bool_policy():
    facade = StackdriverMonitoringFacade()
    uptime = Mock()
    uptime.list_uptime_check_configs.return_value = iter([
        monitoring_v3.types.UptimeCheckConfig(display_name='web'),
    ])
    alerts = Mock()
    alerts.list_alert_policies.return_value = iter([
        monitoring_v3.types.AlertPolicy(enabled=True),
    ])
    with patch.object(facade, 'get_uptime_client', return_value=uptime), patch.object(
        facade, 'get_alerts_client', return_value=alerts
    ), patch('ScoutSuite.providers.gcp.facade.stackdrivermonitoring.run_concurrently',
             _immediate):
        checks = asyncio.run(facade.get_uptime_checks('demo'))
        policies = asyncio.run(facade.get_alert_policies('demo'))
    uptime.list_uptime_check_configs.assert_called_once_with(
        request={'parent': 'projects/demo'})
    alerts.list_alert_policies.assert_called_once_with(
        request={'name': 'projects/demo'})
    assert checks[0].display_name == 'web'
    assert policies[0].enabled is True
    collector = MonitoringAlertPolicies.__new__(MonitoringAlertPolicies)
    result = collector._parse_alert_policy(policies)
    assert len(result) == 8
    assert all(not enabled for enabled in result.values())


def test_azure_sql_real_operation_groups_and_credential_free_client():
    class NoToken:
        def get_token(self, *args, **kwargs):
            raise AssertionError('Authentication must not occur')

    client = SqlManagementClient(
        credential=NoToken(),
        subscription_id='00000000-0000-0000-0000-000000000000')
    try:
        # Bind the exact arguments made by the production facade to the SDK's
        # real bound method signatures, without making an HTTP request.
        operations = {
            'database_blob_auditing_policies': ('get', ('rg', 'server', 'db')),
            'database_security_alert_policies': ('get', ('rg', 'server', 'db', 'Default')),
            'databases': ('list_by_server', ('rg', 'server')),
            'replication_links': ('list_by_database', ('rg', 'server', 'db')),
            'server_azure_ad_administrators': ('list_by_server', ('rg', 'server')),
            'server_blob_auditing_policies': ('get', ('rg', 'server')),
            'server_security_alert_policies': ('get', ('rg', 'server', 'Default')),
            'servers': ('list', ()),
            'transparent_data_encryptions': ('get', ('rg', 'server', 'db', 'current')),
            'server_vulnerability_assessments': ('get', ('rg', 'server', 'default')),
            'encryption_protectors': ('get', ('rg', 'server', 'current')),
            'firewall_rules': ('list_by_server', ('rg', 'server')),
        }
        for group, (method, arguments) in operations.items():
            operation = getattr(getattr(client, group), method)
            assert callable(operation), group
            inspect.signature(operation).bind(*arguments)
    finally:
        client.close()


def test_azure_sql_sdk4_properties_are_flattened_and_reportable():
    raw = SimpleNamespace(id='arm-id', name='db', properties=SimpleNamespace(
        state='Enabled', disabled_alerts=[], email_addresses=['a@example.test'],
        email_account_admins=True, retention_days=30))
    model = _normalize_sql(raw)
    assert model.id == 'arm-id'
    assert model.email_addresses == ['a@example.test']
    assert 'properties' not in vars(model)
    facade = SQLDatabaseFacade(SimpleNamespace(get_credentials=lambda: object()))
    db = DatabaseThreatDetectionPolicies.__new__(DatabaseThreatDetectionPolicies)
    db.clear()
    db._parse_policies(model)
    assert dict(db) == {
        'threat_detection_enabled': True,
        'alerts_enabled': True,
        'send_alerts_enabled': True,
        'retention_days': 30,
    }
    server = ServerSecurityAlertPolicies.__new__(ServerSecurityAlertPolicies)
    server.clear()
    server._parse_policies(model)
    assert server['alerts_enabled'] is True
    assert ScoutResultEncoder.to_dict({'policy': model})['policy']['retention_days'] == 30

    client = Mock()
    client.database_security_alert_policies.get.return_value = raw
    with patch.object(facade, 'get_client', return_value=client), patch(
        'ScoutSuite.providers.azure.facade.sqldatabase.run_concurrently', _immediate
    ):
        result = asyncio.run(facade.get_database_threat_detection_policies(
            'rg', 'server', 'db', 'subscription'))
    client.database_security_alert_policies.get.assert_called_once_with(
        'rg', 'server', 'db', 'Default')
    assert result.retention_days == 30


def test_azure_sql_empty_alert_destinations_do_not_become_secure():
    model = _normalize_sql(SimpleNamespace(properties=SimpleNamespace(
        state='Disabled', disabled_alerts=['SQL_Injection'], email_addresses=[],
        email_account_admins=False, retention_days=0)))
    db = DatabaseThreatDetectionPolicies.__new__(DatabaseThreatDetectionPolicies)
    db.clear()
    db._parse_policies(model)
    assert db['threat_detection_enabled'] is False
    assert db['alerts_enabled'] is False
    assert db['send_alerts_enabled'] is False
