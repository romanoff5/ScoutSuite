"""P1 cross-service AWS Backup evidence against exact EC2/RDS resource ARNs."""
import json
from pathlib import Path
from types import SimpleNamespace
from ScoutSuite.providers.aws.resources.coverage_reconciliation_deep import enrich_backup_workload_coverage
from ScoutSuite.core.utils import recurse
from ScoutSuite.core.rule_evidence import evaluate_rule_evidence

REGION='eu-central-1'
ACCOUNT='123456789012'
EC2=f'arn:aws:ec2:{REGION}:{ACCOUNT}:instance/i-123'
RDS=f'arn:aws:rds:{REGION}:{ACCOUNT}:cluster:prod'
DB=f'arn:aws:rds:{REGION}:{ACCOUNT}:db:db1'
ROOT=Path(__file__).resolve().parents[1]/'ScoutSuite/providers/aws/rules/findings'

def sample(complete=True, protected=None):
    return {
     'backup':{'regions':{REGION:{'backup_inventory_status':{
         'protected_resources':'complete' if complete else 'partial'},
         'protected_resources':{str(i):{'ResourceArn':arn} for i,arn in enumerate(protected or [])}}}},
     'ec2':{'regions':{REGION:{'vpcs':{'v':{'instances':{
         'ec2':{'arn':EC2,'State':{'Name':'running'}},
         'stopped':{'arn':EC2+'x','State':{'Name':'stopped'}}}}}}}},
     'rds':{'regions':{REGION:{'clusters':{'db':{'DBClusterArn':RDS}},
         'vpcs':{'v':{'instances':{
           'standalone':{'arn':DB,'DBClusterIdentifier':None},
           'member':{'arn':DB+'member','DBClusterIdentifier':'prod'}}}}}}}
    }

def test_complete_empty_inventory_reports_only_applicable_missing_records():
    data=sample()
    result=enrich_backup_workload_coverage(data,{'backup','ec2','rds'})
    assert result['not_reported']==3 and result['not_applicable']==2
    assert data['rds']['regions'][REGION]['clusters']['db']['p1_backup_evidence_status']=='not_reported'
    assert data['ec2']['regions'][REGION]['vpcs']['v']['instances']['stopped']['p1_backup_evidence_status']=='not_applicable'
    for name,services in (
      ('ec2-instance-without-aws-backup-resource-record.json',data),
      ('rds-cluster-without-aws-backup-resource-record.json',data),
      ('rds-instance-without-aws-backup-resource-record.json',data)):
        spec=json.loads((ROOT/name).read_text())
        rule=SimpleNamespace(filename=name,conditions=spec['conditions'],path=spec['path'],
                             evidence_policy=spec['evidence_policy'],checked_items=0)
        hits=recurse(services,services,rule.path.split('.'),[],rule,True)
        assert len(hits)==1
        assert evaluate_rule_evidence(rule,services)['counts']['insecure']==1

def test_protected_record_and_incomplete_inventory_not_marked_missing():
    verified=sample(protected=[EC2,RDS,DB])
    assert enrich_backup_workload_coverage(verified,{'backup','ec2','rds'})['not_reported']==0
    assert verified['rds']['regions'][REGION]['clusters']['db']['p1_backup_evidence_status']=='protected_record_observed'
    partial=sample(complete=False)
    assert enrich_backup_workload_coverage(partial,{'backup','ec2','rds'})['not_reported']==0
    assert partial['ec2']['regions'][REGION]['vpcs']['v']['instances']['ec2']['p1_backup_evidence_status']=='unknown'

def test_skipped_backup_service_no_negative_finding():
    data=sample()
    assert enrich_backup_workload_coverage(data,{'ec2','rds'})['not_reported']==0
