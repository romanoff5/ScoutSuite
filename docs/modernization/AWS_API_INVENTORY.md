# AWS SDK operation inventory

Date: 2026-10-30. Source revision: `7909f2fc6186063e5c9e7ddef8c4d7d1072c8f3d`. Local SDK model: **botocore 1.43.123**, paired with boto3 1.43.123 in the minimal validation environment.

Static extraction recognized **129 distinct service/operation pairs across 29 SDK services** in public AWS facade files. The extraction maps local variables assigned by `AWSFacadeUtils.get_client('literal-service', ...)`, their method references (including callbacks passed to executors), and literal paginator operations passed to the shared helpers. All listed operations are present in the selected SDK's local service models; no request, session authentication or endpoint contact was needed. The non-operation `client.exceptions` attribute was excluded.

This is a reproducible scope summary, not a complete call graph. Dynamic `getattr` operations (notably IAM policy enumeration), calls outside these facades, SDK internals, region discovery, and absent private plugins need separate review. STS `get_caller_identity` in `aws/utils.py` and Security Hub `batch_import_findings` in the export tool are outside the extracted set; the latter is a write and must never run in offline tests. Operation presence does not validate request shapes, paginator names, permissions, response completeness, lifecycle support or rule accuracy.

| SDK service | Recognized operations (boto3 spelling) | Facade source |
| --- | --- | --- |
| acm | `describe_certificate`, `list_certificates` | [acm.py](../../ScoutSuite/providers/aws/facade/acm.py) |
| cloudformation | `describe_stacks`, `get_stack_policy`, `get_template`, `list_stacks` | [cloudformation.py](../../ScoutSuite/providers/aws/facade/cloudformation.py) |
| cloudfront | `list_distributions` | [cloudfront.py](../../ScoutSuite/providers/aws/facade/cloudfront.py) |
| cloudtrail | `describe_trails`, `get_event_selectors`, `get_trail_status` | [cloudtrail.py](../../ScoutSuite/providers/aws/facade/cloudtrail.py) |
| cloudwatch | `describe_alarms` | [cloudwatch.py](../../ScoutSuite/providers/aws/facade/cloudwatch.py) |
| codebuild | `batch_get_projects`, `list_projects` | [codebuild.py](../../ScoutSuite/providers/aws/facade/codebuild.py) |
| config | `describe_config_rules`, `describe_configuration_recorder_status`, `describe_configuration_recorders` | [config.py](../../ScoutSuite/providers/aws/facade/config.py) |
| directconnect | `describe_connections` | [directconnect.py](../../ScoutSuite/providers/aws/facade/directconnect.py) |
| dynamodb | `describe_continuous_backups`, `describe_table`, `list_backups`, `list_tables`, `list_tags_of_resource` | [dynamodb.py](../../ScoutSuite/providers/aws/facade/dynamodb.py) |
| ec2 | `describe_flow_logs`, `describe_images`, `describe_instance_attribute`, `describe_instances`, `describe_network_acls`, `describe_network_interfaces`, `describe_route_tables`, `describe_security_groups`, `describe_snapshot_attribute`, `describe_snapshots`, `describe_subnets`, `describe_volumes`, `describe_vpc_peering_connections`, `describe_vpcs`, `get_ebs_default_kms_key_id`, `get_ebs_encryption_by_default` | [ec2.py](../../ScoutSuite/providers/aws/facade/ec2.py) |
| efs | `describe_file_systems`, `describe_mount_target_security_groups`, `describe_mount_targets`, `describe_tags` | [efs.py](../../ScoutSuite/providers/aws/facade/efs.py) |
| elasticache | `describe_cache_clusters`, `describe_cache_parameter_groups`, `describe_cache_security_groups`, `describe_cache_subnet_groups` | [elasticache.py](../../ScoutSuite/providers/aws/facade/elasticache.py) |
| elb | `describe_load_balancer_attributes`, `describe_load_balancer_policies`, `describe_load_balancers`, `describe_tags` | [elb.py](../../ScoutSuite/providers/aws/facade/elb.py) |
| elbv2 | `describe_listeners`, `describe_load_balancer_attributes`, `describe_load_balancers`, `describe_tags` | [elbv2.py](../../ScoutSuite/providers/aws/facade/elbv2.py) |
| emr | `describe_cluster`, `list_clusters` | [emr.py](../../ScoutSuite/providers/aws/facade/emr.py) |
| iam | `generate_credential_report`, `get_account_password_policy`, `get_credential_report`, `get_group`, `get_login_profile`, `get_policy`, `get_policy_version`, `get_role`, `list_access_keys`, `list_attached_role_policies`, `list_entities_for_policy`, `list_groups`, `list_groups_for_user`, `list_instance_profiles_for_role`, `list_mfa_devices`, `list_policies`, `list_role_tags`, `list_roles`, `list_user_tags`, `list_users`, `list_virtual_mfa_devices` | [awslambda.py](../../ScoutSuite/providers/aws/facade/awslambda.py), [iam.py](../../ScoutSuite/providers/aws/facade/iam.py) |
| kms | `describe_key`, `get_key_policy`, `get_key_rotation_status`, `list_aliases`, `list_grants`, `list_keys` | [ec2.py](../../ScoutSuite/providers/aws/facade/ec2.py), [kms.py](../../ScoutSuite/providers/aws/facade/kms.py) |
| lambda | `get_function_configuration`, `get_policy`, `list_functions` | [awslambda.py](../../ScoutSuite/providers/aws/facade/awslambda.py) |
| logs | `describe_metric_filters` | [cloudwatch.py](../../ScoutSuite/providers/aws/facade/cloudwatch.py) |
| rds | `describe_db_cluster_snapshot_attributes`, `describe_db_cluster_snapshots`, `describe_db_clusters`, `describe_db_instances`, `describe_db_parameter_groups`, `describe_db_parameters`, `describe_db_security_groups`, `describe_db_snapshot_attributes`, `describe_db_snapshots`, `describe_db_subnet_groups`, `list_tags_for_resource` | [rds.py](../../ScoutSuite/providers/aws/facade/rds.py) |
| redshift | `describe_cluster_parameter_groups`, `describe_cluster_parameters`, `describe_cluster_security_groups`, `describe_clusters` | [redshift.py](../../ScoutSuite/providers/aws/facade/redshift.py) |
| route53 | `list_hosted_zones`, `list_resource_record_sets` | [route53.py](../../ScoutSuite/providers/aws/facade/route53.py) |
| route53domains | `list_domains` | [route53.py](../../ScoutSuite/providers/aws/facade/route53.py) |
| s3 | `get_bucket_acl`, `get_bucket_encryption`, `get_bucket_location`, `get_bucket_logging`, `get_bucket_policy`, `get_bucket_tagging`, `get_bucket_versioning`, `get_bucket_website`, `get_object_acl`, `get_public_access_block`, `list_buckets` | [s3.py](../../ScoutSuite/providers/aws/facade/s3.py) |
| s3control | `get_public_access_block` | [s3.py](../../ScoutSuite/providers/aws/facade/s3.py) |
| secretsmanager | `describe_secret`, `get_resource_policy`, `list_secrets` | [secretsmanager.py](../../ScoutSuite/providers/aws/facade/secretsmanager.py) |
| ses | `get_identity_dkim_attributes`, `get_identity_policies`, `list_identities`, `list_identity_policies` | [ses.py](../../ScoutSuite/providers/aws/facade/ses.py) |
| sns | `get_topic_attributes`, `list_subscriptions`, `list_topics` | [sns.py](../../ScoutSuite/providers/aws/facade/sns.py) |
| sqs | `get_queue_attributes`, `list_queues` | [sqs.py](../../ScoutSuite/providers/aws/facade/sqs.py) |

## Required follow-up

- Replace EFS `describe_tags`; AWS explicitly deprecates it in favor of `list_tags_for_resource`. [EFS API notice](https://docs.aws.amazon.com/efs/latest/APIReference/API_DescribeTags.html).
- S3 `list_buckets`, CloudFront `list_distributions` and SQS `list_queues` are present APIs whose current use here lacks continuation handling. Prioritize completeness rather than treating them as removed APIs. S3 requires pagination for accounts with bucket quotas above the documented threshold. [S3 pagination contract](https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListBuckets.html).
- Preserve `AdvancedEventSelectors` from CloudTrail `get_event_selectors`; its presence in the model does not mean this collector currently uses it. [Response contract](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_GetEventSelectors.html).
- Treat RDS/ElastiCache/Redshift Classic security-group surfaces as legacy compatibility work. Do not infer removal of an API from platform retirement or a method's age.
- Build request and paginator-model checks from a reviewed explicit operation manifest in M05. Capture dynamic IAM calls, default filters, permissions, optional fields and result schemas. Additions require strict offline stub cases, not just a successful model lookup.

See [baseline](BASELINE.md) for service coverage gaps and [M05/M06 in the roadmap](ROADMAP.md) for acceptance criteria.
