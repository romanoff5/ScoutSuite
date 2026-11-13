"""P2 Glue Data Catalog security configuration without retrieving sensitive data."""
from ScoutSuite.core.run_context import get_current_run_context
from ScoutSuite.providers.aws.facade.basefacade import AWSBaseFacade
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.utils import run_concurrently


class GlueAuditFacade(AWSBaseFacade):
    def _issue(self, code):
        ctx = get_current_run_context()
        if ctx is not None:
            ctx.record_collection_issue('partial', 'glue', code)

    async def inventory_catalog(self, region):
        client = AWSFacadeUtils.get_client('glue', self.session, region)
        if client is None:
            self._issue('GlueClientUnavailable')
            return {'status': 'unknown'}

        def collect():
            result = {'status': 'complete',
                      'catalog_encryption_status': 'unknown',
                      'connection_password_status': 'unknown',
                      'database_usage': 'unknown',
                      'connection_usage': 'unknown'}
            # Independent API outcomes: one denied inventory must not erase
            # evidence about another successfully inspected configuration.
            try:
                page = client.get_databases(MaxResults=1)
                rows = page.get('DatabaseList')
                if not isinstance(rows, list):
                    raise ValueError('MalformedGlueDatabaseInventory')
                result['database_usage'] = 'in_use' if rows else 'not_in_use'
            except Exception:
                result['status'] = 'partial'
            try:
                page = client.get_connections(MaxResults=1, HidePassword=True)
                rows = page.get('ConnectionList')
                if not isinstance(rows, list):
                    raise ValueError('MalformedGlueConnectionInventory')
                result['connection_usage'] = 'in_use' if rows else 'not_in_use'
            except Exception:
                result['status'] = 'partial'
            try:
                page = client.get_data_catalog_encryption_settings()
                config = page.get('DataCatalogEncryptionSettings')
                if not isinstance(config, dict):
                    raise ValueError('MalformedGlueCatalogEncryption')
                mode = (config.get('EncryptionAtRest') or {}).get('CatalogEncryptionMode')
                if mode in ('SSE-KMS', 'SSE-KMS-WITH-SERVICE-ROLE'):
                    result['catalog_encryption_status'] = 'kms_configured'
                elif mode == 'DISABLED':
                    # Glue still has AWS-managed encryption; this describes
                    # opt-in KMS configuration, not plaintext at rest.
                    result['catalog_encryption_status'] = 'kms_not_configured'
                else:
                    result['status'] = 'partial'
                password = (config.get('ConnectionPasswordEncryption') or {}).get(
                    'ReturnConnectionPasswordEncrypted')
                if password is True:
                    result['connection_password_status'] = 'encrypted_response'
                elif password is False:
                    result['connection_password_status'] = 'unencrypted_response'
                else:
                    result['status'] = 'partial'
            except Exception:
                result['status'] = 'partial'
            if result['database_usage'] == 'not_in_use':
                result['catalog_encryption_status'] = 'not_applicable'
            elif result['database_usage'] != 'in_use':
                result['catalog_encryption_status'] = 'unknown'
            if result['connection_usage'] == 'not_in_use':
                result['connection_password_status'] = 'not_applicable'
            elif result['connection_usage'] != 'in_use':
                result['connection_password_status'] = 'unknown'
            return result

        try:
            result = await run_concurrently(collect)
        except Exception as exc:
            AWSFacadeUtils.record_listing_failure('glue', exc, 'GetGlueCatalogSecurity')
            self._issue('GlueCatalogInventoryIncomplete')
            return {'status': 'unknown'}
        if result['status'] != 'complete':
            self._issue('GlueCatalogInventoryPartial')
        return result
