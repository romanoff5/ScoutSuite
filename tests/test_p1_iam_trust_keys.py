"""P1 IAM service trust and persistent access key review."""
import json
from pathlib import Path
from types import SimpleNamespace
from ScoutSuite.core.rule_evidence import evaluate_rule_evidence
from ScoutSuite.core.utils import recurse
from ScoutSuite.providers.aws.resources.iam.trust_review import review_trust
from ScoutSuite.providers.aws.resources.iam.users import Users
ROOT=Path(__file__).resolve().parents[1]/'ScoutSuite/providers/aws/rules'

def run(name, service):
    definition=json.loads((ROOT/'findings'/name).read_text())
    rule=SimpleNamespace(filename=name,path=definition['path'],
        conditions=definition['conditions'],evidence_policy=definition['evidence_policy'],
        checked_items=0)
    return (recurse(service,service,rule.path.split('.'),[],rule,True),
            evaluate_rule_evidence(rule,service))

def trust(statement):
    return review_trust({'PolicyDocument':{'Statement':statement}})
def stmt(service, condition=None):
    x={'Effect':'Allow','Principal':{'Service':service},'Action':'sts:AssumeRole'}
    if condition is not None:x['Condition']=condition
    return x

def test_service_trust_scope_presence_and_unsupported_principal():
    assert trust(stmt('ecs-tasks.amazonaws.com'))=='missing'
    assert trust(stmt('ecs-tasks.amazonaws.com',{'StringEquals':{'aws:SourceAccount':'123456789012'}}))=='scoped'
    assert trust(stmt('codedeploy.amazonaws.com',{'ArnLike':{'aws:SourceArn':'arn:aws:codedeploy:*:123456789012:*'}}))=='scoped'
    assert trust(stmt('lambda.amazonaws.com'))=='not_applicable'
    assert trust(stmt('ecs-tasks.amazonaws.com',{'StringEquals':{'aws:SourceAccount':'*'}}))=='missing'
    assert trust([stmt('ecs-tasks.amazonaws.com',
                      {'StringEquals':{'aws:SourceAccount':'123456789012'}}),
                  stmt('ecs-tasks.amazonaws.com')])=='missing'

def test_service_trust_rule_traversal():
    role={'service_trust_scope_status':'missing'}
    matches,evidence=run('iam-role-service-trust-missing-source-scope.json',{'iam':{'roles':{'r':role}}})
    assert len(matches)==1 and evidence['counts']['insecure']==1

def test_short_lived_active_key_is_still_long_lived_credential():
    parser=Users.__new__(Users)
    raw={'UserId':'AIDA','UserName':'pipeline','Arn':'arn:aws:iam::123:user/pipeline',
         'tags':{'Tags':[]}, 'AccessKeys':[{'Status':'Active','CreateDate':'2026-11-12'}]}
    _, user=parser._parse_user(raw)
    assert user['persistent_key_review_status']=='active'
    matches,evidence=run('iam-user-active-persistent-access-key-review.json',
                         {'iam':{'users':{'user':user}}})
    assert len(matches)==1 and evidence['counts']['insecure']==1
    _, unknown=parser._parse_user({'UserId':'B','UserName':'other','Arn':'arn:aws:iam::123:user/other',
                                  'tags':{'Tags':[]}})
    assert unknown['persistent_key_review_status']=='unknown'

def test_source_scope_wildcard_or_wrong_account_cannot_prove_bound_trust():
    arn='arn:aws:iam::123456789012:role/service'
    def scoped(condition):
        return review_trust({'PolicyDocument':{'Statement':
                            stmt('ecs-tasks.amazonaws.com',condition)}}, arn)
    assert scoped({'ArnLike':{'aws:SourceArn':'arn:aws:ecs:*:*:task/*'}})=='missing'
    assert scoped({'StringEquals':{'aws:SourceAccount':['123456789012','*']}})=='missing'
    assert scoped({'StringEquals':{'aws:SourceAccount':'999999999999'}})=='unknown'
    assert scoped({'StringEquals':{'aws:SourceAccount':'123456789012'}})=='scoped'
    assert scoped({'ArnLike':{'aws:SourceArn':
                   'arn:aws:ecs:*:123456789012:task/*'}})=='scoped'
