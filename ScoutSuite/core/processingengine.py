from ScoutSuite.core.console import print_debug, print_exception
from ScoutSuite.core.run_context import get_current_run_context
from ScoutSuite.core.rule_evidence import evaluate_rule_evidence
from ScoutSuite.utils import manage_dictionary

from ScoutSuite.core.utils import recurse


class ProcessingEngine:
    """

    """

    def __init__(self, ruleset):
        # Organize rules by path
        self.ruleset = ruleset
        self.rules = {}
        for filename in self.ruleset.rules:
            for rule in self.ruleset.rules[filename]:
                if not rule.enabled:
                    continue
                try:
                    manage_dictionary(self.rules, rule.path, [])
                    self.rules[rule.path].append(rule)
                except Exception as e:
                    print_exception(f'Failed to create rule {rule.filename}: {e}')

    def run(self, cloud_provider, skip_dashboard=False):
        # Clean up existing findings
        for service in cloud_provider.services:
            cloud_provider.services[service][self.ruleset.rule_type] = {}

        # Process each rule
        for finding_path in self._filter_rules(self.rules, cloud_provider.service_list):
            for rule in self.rules[finding_path]:

                if not rule.enabled:  # or rule.service not in []: # TODO: handle this...
                    continue

                print_debug(f'Processing {rule.service} rule "{rule.description}" ({rule.filename})')
                finding_path = rule.path
                path = finding_path.split('.')
                service = path[0]
                manage_dictionary(cloud_provider.services[service], self.ruleset.rule_type, {})
                cloud_provider.services[service][self.ruleset.rule_type][rule.key] = {}
                cloud_provider.services[service][self.ruleset.rule_type][rule.key]['description'] = rule.description
                cloud_provider.services[service][self.ruleset.rule_type][rule.key]['path'] = rule.path
                for attr in ['level', 'id_suffix', 'class_suffix', 'display_path']:
                    if hasattr(rule, attr):
                        cloud_provider.services[service][self.ruleset.rule_type][rule.key][attr] = getattr(rule, attr)
                try:
                    setattr(rule, 'checked_items', 0)
                    cloud_provider.services[service][self.ruleset.rule_type][rule.key]['items'] = recurse(
                        cloud_provider.services, cloud_provider.services, path, [], rule, True)
                    if skip_dashboard:
                        continue
                    cloud_provider.services[service][self.ruleset.rule_type][rule.key]['dashboard_name'] = \
                        rule.dashboard_name
                    cloud_provider.services[service][self.ruleset.rule_type][rule.key]['checked_items'] = \
                        rule.checked_items
                    cloud_provider.services[service][self.ruleset.rule_type][rule.key]['flagged_items'] = \
                        len(cloud_provider.services[service][self.ruleset.rule_type][rule.key]['items'])
                    cloud_provider.services[service][self.ruleset.rule_type][rule.key]['service'] = rule.service
                    cloud_provider.services[service][self.ruleset.rule_type][rule.key]['rationale'] = \
                        rule.rationale if hasattr(rule, 'rationale') else None
                    cloud_provider.services[service][self.ruleset.rule_type][rule.key]['remediation'] = \
                        rule.remediation if hasattr(rule, 'remediation') else None
                    cloud_provider.services[service][self.ruleset.rule_type][rule.key]['compliance'] = \
                        rule.compliance if hasattr(rule, 'compliance') else None
                    cloud_provider.services[service][self.ruleset.rule_type][rule.key]['references'] = \
                        rule.references if hasattr(rule, 'references') else None
                    if self.ruleset.rule_type == 'findings':
                        finding = cloud_provider.services[service][self.ruleset.rule_type][rule.key]
                        evidence = evaluate_rule_evidence(rule, cloud_provider.services)
                        if evidence is not None:
                            finding['evaluation_summary'] = evidence
                            if evidence['assessment_status'] == 'incomplete':
                                finding['assessment_status'] = 'incomplete'
                            elif evidence['assessment_status'] == 'not_applicable':
                                finding['assessment_status'] = 'not_applicable'
                        profile_id = getattr(self.ruleset, 'profile_id', None)
                        if profile_id:
                            finding['policy_profile'] = {
                                'id': profile_id,
                                'version': self.ruleset.profile_version
                            }
                except Exception as e:
                    print_exception(f'Failed to process rule defined in {rule.filename}: {e}')
                    # Never encode a failed evaluation as an empty compliant result.
                    finding = cloud_provider.services[service][self.ruleset.rule_type][rule.key]
                    finding['items'] = []
                    finding['checked_items'] = 0
                    finding['flagged_items'] = 0
                    finding['assessment_status'] = 'incomplete'
                    context = get_current_run_context()
                    if context is not None:
                        context.record_collection_issue('failed', service, 'RuleEvaluation')
                else:
                    context = get_current_run_context()
                    issues = context.collection_issues if context is not None else (
                        getattr(cloud_provider, 'collection_status', {}) or {}
                    ).get('issues', [])
                    if self.ruleset.rule_type == 'findings' and any(
                        issue['scope'] in (service, 'assessment') for issue in issues
                    ):
                        cloud_provider.services[service][self.ruleset.rule_type][rule.key][
                            'assessment_status'] = 'incomplete'

    @staticmethod
    def _filter_rules(rules, services):
        return {rule_name: rule for rule_name, rule in rules.items() if rule_name.split('.')[0] in services}
