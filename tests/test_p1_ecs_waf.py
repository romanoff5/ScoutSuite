"""P1 ECS and WAF rule coverage using real normalizer and rule traversal."""
import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from ScoutSuite.providers.aws.resources.ecs_public.task_definitions import TaskDefinitions
from ScoutSuite.providers.aws.resources.wafv2.web_acls import WebACLs
from ScoutSuite.core.rule_evidence import evaluate_rule_evidence
from ScoutSuite.core.utils import recurse

ROOT = Path(__file__).resolve().parents[1] / 'ScoutSuite/providers/aws/rules'

def run(name, services):
    spec = json.loads((ROOT/'findings'/name).read_text())
    rule = SimpleNamespace(filename=name, path=spec['path'], conditions=spec['conditions'],
                           evidence_policy=spec['evidence_policy'], checked_items=0)
    return (recurse(services, services, rule.path.split('.'), [], rule, True),
            evaluate_rule_evidence(rule, services))

def test_ecs_writable_root_including_missing_default():
    async def fetch(region):
        return [{'taskDefinitionArn':'arn:aws:ecs:eu-central-1:123:task-definition/web:1',
                'status':'ACTIVE','containerDefinitions':[{'name':'web'}]}]
    obj = TaskDefinitions.__new__(TaskDefinitions)
    obj.facade=SimpleNamespace(ecs=SimpleNamespace(get_task_definitions=fetch))
    obj.region='eu-central-1'
    asyncio.run(obj.fetch_all())
    item=next(iter(obj.values()))
    assert item['writable_root_filesystem_status']=='writable'
    hits, ev=run('ecs-task-definition-writable-root.json',
        {'ecs':{'regions':{'eu-central-1':{'task_definitions':{'task':item}}}}})
    assert len(hits)==1 and ev['counts']['insecure']==1
    item['writable_root_filesystem_status']='read_only'
    assert run('ecs-task-definition-writable-root.json',
        {'ecs':{'regions':{'eu-central-1':{'task_definitions':{'task':item}}}}})[0]==[]

def test_waf_managed_group_without_explicit_rate_is_review():
    obj=WebACLs.__new__(WebACLs)
    obj.region='eu-central-1'
    raw={'arn':'arn:aws:wafv2:eu-central-1:123:regional/webacl/test/uuid',
         'name':'test','scope':'REGIONAL','default_action':{'Allow':{}},
         'rules':[{'Name':'managed','Statement':{'ManagedRuleGroupStatement':
                   {'VendorName':'AWS','Name':'CoreRuleSet'}}}],
         'managed_by_firewall_manager':False,'associated_resources':[],
         'association_scope_complete':False,'association_status':'unknown'}
    acl=obj._normalize(raw)[1]
    assert acl['explicit_rate_based_rule_status']=='not_present'
    hits, ev=run('wafv2-web-acl-no-explicit-rate-based-rule.json',
            {'wafv2':{'regions':{'eu-central-1':{'web_acls':{'acl':acl}}}}})
    assert len(hits)==1 and ev['counts']['insecure']==1
    raw['rules'].append({'Name':'Rate','Statement':{'RateBasedStatement':
              {'Limit':100,'AggregateKeyType':'IP'}}})
    assert obj._normalize(raw)[1]['explicit_rate_based_rule_status']=='present'
    raw['rules']=[{'Name':'Malformed','Statement':None}]
    assert obj._normalize(raw)[1]['explicit_rate_based_rule_status']=='unknown'
