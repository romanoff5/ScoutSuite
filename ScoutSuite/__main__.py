"""CLI entry point for ScoutSuite.

This module provides both a synchronous CLI wrapper (run_from_cli) and an
explicit awaitable programmatic path (run_async).

M03: Python lifecycle and synchronous/async API contracts.
- Event loop ownership is explicit and per-run
- RunContext manages loop, executor, throttler, and cleanup
- --local mode triggers zero auth or SDK calls
- Collection/evaluation status metadata is tracked
"""

import asyncio
import os
import webbrowser
from typing import Any, Optional, Dict, List

from ScoutSuite import ERRORS_LIST
from ScoutSuite.core.cli_parser import ScoutSuiteArgumentParser
from ScoutSuite.core.console import set_logger_configuration, print_info, print_exception
from ScoutSuite.core.exceptions import RuleExceptions
from ScoutSuite.core.processingengine import ProcessingEngine
from ScoutSuite.core.ruleset import Ruleset
from ScoutSuite.core.run_context import RunContext
from ScoutSuite.core.server import Server
from ScoutSuite.output.html import ScoutReport
from ScoutSuite.output.utils import get_filename
from ScoutSuite.providers import get_provider
from ScoutSuite.providers.base.authentication_strategy_factory import get_authentication_strategy

# Dirty workaround for compatibility with Python >= 3.10
import collections
collections.Callable = collections.abc.Callable


def run_from_cli() -> int:
    """Synchronous CLI entry point.
    
    This creates a fresh event loop for the run and manages its lifecycle.
    A fresh Python 3.14 process can enter the CLI without depending on
    an implicitly created loop.
    
    Returns:
        int: Exit code (0 for success, non-zero for errors)
    """
    parser = ScoutSuiteArgumentParser()
    args = parser.parse_args()

    # Get the dictionary to get None instead of a crash
    args = args.__dict__

    try:
        # Use asyncio.run for CLI which creates and manages a fresh loop
        return asyncio.run(_run_sync(**_extract_run_args(args)))
    except KeyboardInterrupt:
        print_info('Exiting')
        return 130


async def run_async(provider: str,
                    # AWS
                    profile: Optional[str] = None,
                    aws_access_key_id: Optional[str] = None,
                    aws_secret_access_key: Optional[str] = None,
                    aws_session_token: Optional[str] = None,
                    # Azure
                    cli: bool = False,
                    user_account: bool = False,
                    user_account_browser: bool = False,
                    service_account: Optional[str] = None,
                    msi: bool = False,
                    service_principal: bool = False,
                    file_auth: Optional[str] = None,
                    client_id: Optional[str] = None,
                    client_secret: Optional[str] = None,
                    username: Optional[str] = None,
                    password: Optional[str] = None,
                    tenant_id: Optional[str] = None,
                    subscription_ids: Optional[List[str]] = None,
                    all_subscriptions: bool = False,
                    # GCP
                    project_id: Optional[str] = None,
                    folder_id: Optional[str] = None,
                    organization_id: Optional[str] = None,
                    all_projects: bool = False,
                    # Aliyun
                    access_key_id: Optional[str] = None,
                    access_key_secret: Optional[str] = None,
                    # Kubernetes
                    kubernetes_cluster_provider: Optional[str] = None,
                    kubernetes_config_file: Optional[str] = None,
                    kubernetes_context: Optional[str] = None,
                    kubernetes_persist_config: bool = True,
                    kubernetes_azure_subscription_id: Optional[str] = None,
                    # DigitalOcean
                    token: Optional[str] = None,
                    access_key: Optional[str] = None,
                    access_secret: Optional[str] = None,
                    # General
                    report_name: Optional[str] = None,
                    report_dir: Optional[str] = None,
                    timestamp: bool = False,
                    services: Optional[List[str]] = None,
                    skipped_services: Optional[List[str]] = None,
                    list_services: Optional[bool] = None,
                    result_format: str = 'json',
                    database_name: Optional[str] = None,
                    host_ip: str = '127.0.0.1',
                    host_port: int = 8000,
                    max_workers: int = 10,
                    regions: Optional[List[str]] = None,
                    excluded_regions: Optional[List[str]] = None,
                    fetch_local: bool = False,
                    update: bool = False,
                    max_rate: Optional[int] = None,
                    ip_ranges: Optional[List[str]] = None,
                    ip_ranges_name_key: str = 'name',
                    ruleset: str = 'default.json',
                    exceptions: Optional[str] = None,
                    force_write: bool = False,
                    debug: bool = False,
                    quiet: bool = False,
                    log_file: Optional[str] = None,
                    no_browser: bool = False,
                    programmatic_execution: bool = False,
                    strict_completeness: bool = False) -> int:
    """Run ScoutSuite as an async coroutine.
    
    This is the explicit awaitable programmatic entry point.
    Callers provide their own event loop or use asyncio.run().
    
    The caller manages their own loop lifecycle - we do not close it.
    """
    # Configure the debug level
    set_logger_configuration(debug, quiet, log_file)

    print_info('Launching Scout')
    
    # Create RunContext for this execution
    context = RunContext(
        provider=provider,
        max_workers=max_workers,
        max_rate=max_rate
    )
    context.setup()
    
    try:
        return await _run_impl(
            context=context,
            provider=provider,
            profile=profile,
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            aws_session_token=aws_session_token,
            cli=cli, user_account=user_account,
            user_account_browser=user_account_browser,
            msi=msi, service_principal=service_principal,
            file_auth=file_auth,
            tenant_id=tenant_id,
            subscription_ids=subscription_ids,
            all_subscriptions=all_subscriptions,
            client_id=client_id,
            client_secret=client_secret,
            username=username,
            password=password,
            service_account=service_account,
            project_id=project_id,
            folder_id=folder_id,
            organization_id=organization_id,
            all_projects=all_projects,
            access_key_id=access_key_id,
            access_key_secret=access_key_secret,
            kubernetes_cluster_provider=kubernetes_cluster_provider,
            kubernetes_config_file=kubernetes_config_file,
            kubernetes_context=kubernetes_context,
            kubernetes_persist_config=kubernetes_persist_config,
            kubernetes_azure_subscription_id=kubernetes_azure_subscription_id,
            token=token,
            access_key=access_key,
            access_secret=access_secret,
            report_name=report_name,
            report_dir=report_dir,
            timestamp=timestamp,
            services=services or [],
            skipped_services=skipped_services or [],
            list_services=list_services,
            result_format=result_format,
            database_name=database_name,
            host_ip=host_ip,
            host_port=host_port,
            regions=regions or [],
            excluded_regions=excluded_regions or [],
            fetch_local=fetch_local,
            update=update,
            ip_ranges=ip_ranges or [],
            ip_ranges_name_key=ip_ranges_name_key,
            ruleset=ruleset,
            exceptions=exceptions,
            force_write=force_write,
            debug=debug,
            quiet=quiet,
            log_file=log_file,
            no_browser=no_browser,
            programmatic_execution=programmatic_execution,
            strict_completeness=strict_completeness
        )
    finally:
        await context.aclose()


async def _run_sync(provider: str,
                    profile: Optional[str] = None,
                    aws_access_key_id: Optional[str] = None,
                    aws_secret_access_key: Optional[str] = None,
                    aws_session_token: Optional[str] = None,
                    cli: bool = False,
                    user_account: bool = False,
                    user_account_browser: bool = False,
                    msi: bool = False,
                    service_principal: bool = False,
                    file_auth: Optional[str] = None,
                    client_id: Optional[str] = None,
                    client_secret: Optional[str] = None,
                    username: Optional[str] = None,
                    password: Optional[str] = None,
                    tenant_id: Optional[str] = None,
                    subscription_ids: Optional[List[str]] = None,
                    all_subscriptions: bool = False,
                    service_account: Optional[str] = None,
                    project_id: Optional[str] = None,
                    folder_id: Optional[str] = None,
                    organization_id: Optional[str] = None,
                    all_projects: bool = False,
                    access_key_id: Optional[str] = None,
                    access_key_secret: Optional[str] = None,
                    kubernetes_cluster_provider: Optional[str] = None,
                    kubernetes_config_file: Optional[str] = None,
                    kubernetes_context: Optional[str] = None,
                    kubernetes_persist_config: bool = True,
                    kubernetes_azure_subscription_id: Optional[str] = None,
                    token: Optional[str] = None,
                    access_key: Optional[str] = None,
                    access_secret: Optional[str] = None,
                    report_name: Optional[str] = None,
                    report_dir: Optional[str] = None,
                    timestamp: bool = False,
                    services: Optional[List[str]] = None,
                    skipped_services: Optional[List[str]] = None,
                    list_services: Optional[bool] = None,
                    result_format: str = 'json',
                    database_name: Optional[str] = None,
                    host_ip: str = '127.0.0.1',
                    host_port: int = 8000,
                    max_workers: int = 10,
                    regions: Optional[List[str]] = None,
                    excluded_regions: Optional[List[str]] = None,
                    fetch_local: bool = False,
                    update: bool = False,
                    max_rate: Optional[int] = None,
                    ip_ranges: Optional[List[str]] = None,
                    ip_ranges_name_key: str = 'name',
                    ruleset: str = 'default.json',
                    exceptions: Optional[str] = None,
                    force_write: bool = False,
                    debug: bool = False,
                    quiet: bool = False,
                    log_file: Optional[str] = None,
                    no_browser: bool = False,
                    programmatic_execution: bool = False,
                    strict_completeness: bool = False) -> int:
    """Internal synchronous entry point that creates and manages its own loop.
    
    This is called by run_from_cli() after parsing arguments.
    It creates a fresh event loop and manages its lifecycle completely.
    """
    context = RunContext(
        provider=provider,
        max_workers=max_workers,
        max_rate=max_rate
    )
    
    context.setup()
    try:
        try:
            return await _run_impl(
                context=context,
                provider=provider,
                profile=profile,
                aws_access_key_id=aws_access_key_id,
                aws_secret_access_key=aws_secret_access_key,
                aws_session_token=aws_session_token,
                cli=cli, user_account=user_account,
                user_account_browser=user_account_browser,
                msi=msi, service_principal=service_principal,
                file_auth=file_auth,
                tenant_id=tenant_id,
                subscription_ids=subscription_ids,
                all_subscriptions=all_subscriptions,
                client_id=client_id, client_secret=client_secret,
                username=username, password=password,
                service_account=service_account,
                project_id=project_id,
                folder_id=folder_id,
                organization_id=organization_id,
                all_projects=all_projects,
                access_key_id=access_key_id,
                access_key_secret=access_key_secret,
                kubernetes_cluster_provider=kubernetes_cluster_provider,
                kubernetes_config_file=kubernetes_config_file,
                kubernetes_context=kubernetes_context,
                kubernetes_persist_config=kubernetes_persist_config,
                kubernetes_azure_subscription_id=kubernetes_azure_subscription_id,
                token=token,
                access_key=access_key,
                access_secret=access_secret,
                report_name=report_name,
                report_dir=report_dir,
                timestamp=timestamp,
                services=services or [],
                skipped_services=skipped_services or [],
                list_services=list_services,
                result_format=result_format,
                database_name=database_name,
                host_ip=host_ip,
                host_port=host_port,
                regions=regions or [],
                excluded_regions=excluded_regions or [],
                fetch_local=fetch_local,
                update=update,
                ip_ranges=ip_ranges or [],
                ip_ranges_name_key=ip_ranges_name_key,
                ruleset=ruleset,
                exceptions=exceptions,
                force_write=force_write,
                debug=debug,
                quiet=quiet,
                log_file=log_file,
                no_browser=no_browser,
                programmatic_execution=programmatic_execution,
                strict_completeness=strict_completeness
            )
        except (KeyboardInterrupt, SystemExit):
            print_info('Exiting')
            return 130
    finally:
        await context.aclose()


async def _run_impl(context: RunContext,
                    provider: str,
                    profile: Optional[str] = None,
                    aws_access_key_id: Optional[str] = None,
                    aws_secret_access_key: Optional[str] = None,
                    aws_session_token: Optional[str] = None,
                    cli: bool = False,
                    user_account: bool = False,
                    user_account_browser: bool = False,
                    msi: bool = False,
                    service_principal: bool = False,
                    file_auth: Optional[str] = None,
                    client_id: Optional[str] = None,
                    client_secret: Optional[str] = None,
                    username: Optional[str] = None,
                    password: Optional[str] = None,
                    tenant_id: Optional[str] = None,
                    subscription_ids: Optional[List[str]] = None,
                    all_subscriptions: bool = False,
                    service_account: Optional[str] = None,
                    project_id: Optional[str] = None,
                    folder_id: Optional[str] = None,
                    organization_id: Optional[str] = None,
                    all_projects: bool = False,
                    access_key_id: Optional[str] = None,
                    access_key_secret: Optional[str] = None,
                    kubernetes_cluster_provider: Optional[str] = None,
                    kubernetes_config_file: Optional[str] = None,
                    kubernetes_context: Optional[str] = None,
                    kubernetes_persist_config: bool = True,
                    kubernetes_azure_subscription_id: Optional[str] = None,
                    token: Optional[str] = None,
                    access_key: Optional[str] = None,
                    access_secret: Optional[str] = None,
                    report_name: Optional[str] = None,
                    report_dir: Optional[str] = None,
                    timestamp: bool = False,
                    services: Optional[List[str]] = None,
                    skipped_services: Optional[List[str]] = None,
                    list_services: Optional[bool] = None,
                    result_format: str = 'json',
                    database_name: Optional[str] = None,
                    host_ip: str = '127.0.0.1',
                    host_port: int = 8000,
                    regions: Optional[List[str]] = None,
                    excluded_regions: Optional[List[str]] = None,
                    fetch_local: bool = False,
                    update: bool = False,
                    ip_ranges: Optional[List[str]] = None,
                    ip_ranges_name_key: str = 'name',
                    ruleset: str = 'default.json',
                    exceptions: Optional[str] = None,
                    force_write: bool = False,
                    debug: bool = False,
                    quiet: bool = False,
                    log_file: Optional[str] = None,
                    no_browser: bool = False,
                    programmatic_execution: bool = False,
                    strict_completeness: bool = False) -> int:
    """Core implementation of the ScoutSuite run.
    
    M03: --local from synthetic fixtures triggers zero auth or SDK calls.
    """
    services = services or []
    skipped_services = skipped_services or []
    regions = regions or []
    excluded_regions = excluded_regions or []
    ip_ranges = ip_ranges or []

    # M03: In --local mode, skip authentication and provider network initialization
    if fetch_local:
        print_info('Using local data (offline mode)')
        credentials = None
    else:
        print_info('Authenticating to cloud provider')
        auth_strategy = get_authentication_strategy(provider)
        try:
            credentials = auth_strategy.authenticate(
                profile=profile,
                aws_access_key_id=aws_access_key_id,
                aws_secret_access_key=aws_secret_access_key,
                aws_session_token=aws_session_token,
                user_account=user_account,
                user_account_browser=user_account_browser,
                service_account=service_account,
                cli=cli,
                msi=msi,
                service_principal=service_principal,
                file_auth=file_auth,
                tenant_id=tenant_id,
                client_id=client_id,
                client_secret=client_secret,
                username=username,
                password=password,
                access_key_id=access_key_id,
                access_key_secret=access_key_secret,
                token=token,
                access_key=access_key,
                access_secret=access_secret,
                kubernetes_cluster_provider=kubernetes_cluster_provider,
                kubernetes_config_file=kubernetes_config_file,
                kubernetes_context=kubernetes_context,
                kubernetes_persist_config=kubernetes_persist_config,
                kubernetes_azure_subscription_id=kubernetes_azure_subscription_id,
                kubernetes_fetch_local=fetch_local
            )
            if not credentials:
                return 101
        except Exception as e:
            print_exception(f'Authentication failure: {e}')
            return 101

    # Create a cloud provider object
    try:
        cloud_provider = get_provider(
            provider=provider,
            profile=profile,
            subscription_ids=subscription_ids,
            all_subscriptions=all_subscriptions,
            project_id=project_id,
            folder_id=folder_id,
            organization_id=organization_id,
            all_projects=all_projects,
            kubernetes_config_file=kubernetes_config_file,
            kubernetes_context=kubernetes_context,
            kubernetes_cluster_provider=kubernetes_cluster_provider,
            report_dir=report_dir,
            timestamp=timestamp,
            services=services,
            skipped_services=skipped_services,
            programmatic_execution=programmatic_execution,
            credentials=credentials if credentials else {},
            **({'fetch_local': True} if provider == 'aws' and fetch_local else {})
        )
    except Exception as e:
        print_exception(f'Initialization failure: {e}')
        return 102

    # For local mode, we need to set account_id without making API calls
    if fetch_local:
        if not hasattr(cloud_provider, 'account_id') or not cloud_provider.account_id:
            cloud_provider.account_id = 'local-account-id'
        if not hasattr(cloud_provider, 'partition') or not cloud_provider.partition:
            cloud_provider.partition = 'aws'

    # M04: status metadata is additive and does not change legacy result fields.
    # Create a new report
    try:
        report_name = report_name if report_name else cloud_provider.get_report_name()
        report = ScoutReport(
            cloud_provider.provider_code,
            report_name,
            report_dir,
            timestamp,
            result_format=result_format
        )

        if database_name:
            database_file, _ = get_filename('RESULTS', report_name, report_dir, file_extension="db")
            Server.init(database_file, host_ip, host_port)
            return 0
    except Exception as e:
        print_exception('Report initialization failure: {}'.format(e))
        return 103

    # If this command, run and exit
    if list_services:
        available_services = [x for x in dir(cloud_provider.services) 
                             if not (x.startswith('_') or x in ['credentials', 'fetch'])]
        print_info('The available services are: "{}"'.format('", "'.join(available_services)))
        return 0

    # Complete run, including pulling data from provider
    if not fetch_local:
        try:
            print_info('Gathering data from APIs')
            await cloud_provider.fetch(regions=regions, excluded_regions=excluded_regions)
        except KeyboardInterrupt:
            print_info('Cancelled by user')
            context.cancel_all_tasks()
            return 130
        except Exception as e:
            print_exception('Unhandled exception thrown while gathering data: {}'.format(e))
            return 104

        if update:
            try:
                print_info('Updating existing data')
                last_run_dict = report.encoder.load_from_file('RESULTS')
                previous_services = [prev_service for prev_service in last_run_dict['service_list'] 
                                    if prev_service not in cloud_provider.service_list]
                for service in previous_services:
                    cloud_provider.service_list.append(service)
                    cloud_provider.services[service] = last_run_dict['services'][service]
            except Exception as e:
                print_exception('Failure while updating report: {}'.format(e))
    else:
        try:
            print_info('Using local data')
            last_run_dict = report.encoder.load_from_file('RESULTS')
            for key in last_run_dict:
                setattr(cloud_provider, key, last_run_dict[key])
        except Exception as e:
            print_exception('Failure while loading local data: {}'.format(e))
            return 104

    # Pre processing
    try:
        print_info('Running pre-processing engine')
        cloud_provider.preprocessing(ip_ranges, ip_ranges_name_key)
    except Exception as e:
        print_exception('Failure while running pre-processing engine: {}'.format(e))
        return 105

    # Analyze config
    try:
        print_info('Running rule engine')
        finding_rules = Ruleset(
            cloud_provider=cloud_provider.provider_code,
            environment_name=cloud_provider.environment,
            filename=ruleset,
            ip_ranges=ip_ranges,
            account_id=cloud_provider.account_id
        )
        processing_engine = ProcessingEngine(finding_rules)
        processing_engine.run(cloud_provider)
    except Exception as e:
        print_exception('Failure while running rule engine: {}'.format(e))
        return 106

    # Create display filters
    try:
        print_info('Applying display filters')
        filter_rules = Ruleset(
            cloud_provider=cloud_provider.provider_code,
            environment_name=cloud_provider.environment,
            filename='filters.json',
            rule_type='filters',
            account_id=cloud_provider.account_id
        )
        processing_engine = ProcessingEngine(filter_rules)
        processing_engine.run(cloud_provider)
    except Exception as e:
        print_exception('Failure while applying display filters: {}'.format(e))
        return 107

    # Handle exceptions
    if exceptions:
        print_info('Applying exceptions')
        try:
            exceptions = RuleExceptions(exceptions)
            exceptions.process(cloud_provider)
            exceptions = exceptions.exceptions
        except Exception as e:
            print_exception(f'Failed to load exceptions: {e}')
            exceptions = {}
    else:
        exceptions = {}

    # Count evaluated findings separately from collection success or failure.
    checked_items = sum(
        finding.get('checked_items', 0) or 0
        for service_data in cloud_provider.services.values()
        if isinstance(service_data, dict)
        for finding in service_data.get('findings', {}).values()
        if isinstance(finding, dict)
    ) if isinstance(cloud_provider.services, dict) else 0

    # Expose collection integrity in saved RESULTS, including successful empty runs.
    if not fetch_local or not isinstance(getattr(cloud_provider, 'collection_status', None), dict):
        cloud_provider.collection_status = context.collection_summary(checked_items)
    elif context.collection_issues or context.errors:
        previous = cloud_provider.collection_status.get('issues', [])
        current = context.collection_summary(checked_items)
        current['issues'] = previous + [
            issue for issue in current['issues'] if issue not in previous
        ]
        current['complete'] = not current['issues']
        current['status'] = 'success' if current['complete'] else 'partial'
        cloud_provider.collection_status = current

    # Finalize
    try:
        print_info('Running post-processing engine')
        run_parameters = {
            'services': services,
            'skipped_services': skipped_services,
            'regions': regions,
            'excluded_regions': excluded_regions,
        }
        cloud_provider.postprocessing(report.current_time, finding_rules, run_parameters)
    except Exception as e:
        print_exception('Failure while running post-processing engine: {}'.format(e))
        return 108

    # Post-processing can also emit errors; reflect those before serialization.
    if context.collection_issues or context.errors:
        cloud_provider.collection_status = context.collection_summary(checked_items)

    # Save config and create HTML report
    try:
        html_report_path = report.save(cloud_provider, exceptions, force_write, debug)
    except Exception as e:
        print_exception('Failure while generating HTML report: {}'.format(e))
        return 109

    # Open the report by default
    if not no_browser:
        try:
            print_info('Opening the HTML report')
            url = 'file://%s' % os.path.abspath(html_report_path)
            webbrowser.open(url, new=2)
        except Exception as e:
            print_exception('Failed to open browser: {}'.format(e))

    collection_status = getattr(cloud_provider, 'collection_status', None)
    if strict_completeness and (
        not isinstance(collection_status, dict)
        or not collection_status.get('complete', False)
        or not collection_status.get('evidence_evaluated', False)
    ):
        return 201
    errors = context.errors if context._token is not None else ERRORS_LIST
    if errors:
        return 200
    else:
        return 0


def run(provider,
        profile=None,
        aws_access_key_id=None,
        aws_secret_access_key=None,
        aws_session_token=None,
        cli=False,
        user_account=False,
        user_account_browser=False,
        msi=False,
        service_principal=False,
        file_auth=None,
        client_id=None,
        client_secret=None,
        username=None,
        password=None,
        tenant_id=None,
        subscription_ids=None,
        all_subscriptions=None,
        service_account=None,
        project_id=None,
        folder_id=None,
        organization_id=None,
        all_projects=False,
        access_key_id=None,
        access_key_secret=None,
        kubernetes_cluster_provider=None,
        kubernetes_config_file=None,
        kubernetes_context=None,
        kubernetes_persist_config=True,
        kubernetes_azure_subscription_id=None,
        token=None,
        access_key=None,
        access_secret=None,
        report_name=None, report_dir=None,
        timestamp=False,
        services=None, skipped_services=None,
        result_format='json',
        database_name=None, host_ip='127.0.0.1', host_port=8000,
        max_workers=10,
        regions=None,
        excluded_regions=None,
        fetch_local=False, update=False,
        max_rate=None,
        ip_ranges=None, ip_ranges_name_key='name',
        ruleset='default.json', exceptions=None,
        force_write=False,
        debug=False,
        quiet=False,
        log_file=None,
        no_browser=False,
        programmatic_execution=True,
        strict_completeness=False):
    """
    Run a scout job - backward compatible wrapper.
    
    M03: This function creates and manages its own event loop
    rather than modifying a caller's loop or relying on implicit loop creation.
    """
    # run() is a synchronous API. Async consumers must await run_async().
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        pass
    else:
        raise RuntimeError('run() cannot execute inside a running event loop; await run_async()')
    parameters = locals().copy()
    return asyncio.run(run_async(**parameters))



def _extract_run_args(args: dict) -> dict:
    """Extract run arguments from parsed CLI args dict."""
    return {
        'provider': args.get('provider'),
        'profile': args.get('profile'),
        'aws_access_key_id': args.get('aws_access_key_id'),
        'aws_secret_access_key': args.get('aws_secret_access_key'),
        'aws_session_token': args.get('aws_session_token'),
        'cli': args.get('cli'),
        'user_account': args.get('user_account'),
        'user_account_browser': args.get('user_account_browser'),
        'msi': args.get('msi'),
        'service_principal': args.get('service_principal'),
        'file_auth': args.get('file_auth'),
        'client_id': args.get('client_id'),
        'client_secret': args.get('client_secret'),
        'username': args.get('username'),
        'password': args.get('password'),
        'tenant_id': args.get('tenant_id'),
        'subscription_ids': args.get('subscription_ids'),
        'all_subscriptions': args.get('all_subscriptions'),
        'service_account': args.get('service_account'),
        'folder_id': args.get('folder_id'),
        'organization_id': args.get('organization_id'),
        'all_projects': args.get('all_projects'),
        'access_key_id': args.get('access_key_id'),
        'access_key_secret': args.get('access_key_secret'),
        'project_id': args.get('project_id'),
        'kubernetes_cluster_provider': args.get('kubernetes_cluster_provider'),
        'kubernetes_config_file': args.get('kubernetes_config_file'),
        'kubernetes_context': args.get('kubernetes_context'),
        'kubernetes_persist_config': args.get('kubernetes_persist_config'),
        'kubernetes_azure_subscription_id': args.get('kubernetes_azure_subscription_id'),
        'token': args.get('token'),
        'access_key': args.get('access_key'),
        'access_secret': args.get('access_secret'),
        'report_name': args.get('report_name'),
        'report_dir': args.get('report_dir'),
        'timestamp': args.get('timestamp'),
        'services': args.get('services'),
        'skipped_services': args.get('skipped_services'),
        'list_services': args.get('list_services'),
        'result_format': args.get('result_format'),
        'database_name': args.get('database_name'),
        'host_ip': args.get('host_ip'),
        'host_port': args.get('host_port'),
        'max_workers': args.get('max_workers'),
        'regions': args.get('regions'),
        'excluded_regions': args.get('excluded_regions'),
        'fetch_local': args.get('fetch_local'),
        'update': args.get('update'),
        'max_rate': args.get('max_rate'),
        'ip_ranges': args.get('ip_ranges'),
        'ip_ranges_name_key': args.get('ip_ranges_name_key'),
        'ruleset': args.get('ruleset'),
        'exceptions': args.get('exceptions'),
        'force_write': args.get('force_write'),
        'debug': args.get('debug'),
        'quiet': args.get('quiet'),
        'log_file': args.get('log_file'),
        'no_browser': args.get('no_browser'),
        'programmatic_execution': False,
        'strict_completeness': args.get('strict_completeness', False),
    }