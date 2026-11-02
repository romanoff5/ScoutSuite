# M10-R — Amazon Bedrock security inventory

Bedrock is included in the default AWS scan and can be selected or excluded
with the standard service flags. The implementation uses regional read-only
clients for **bedrock** and **bedrock-agent**, and never invokes a model or agent.

## Configuration coverage

- Account/Region model invocation logging: enabled modalities, S3 destination,
  CloudWatch log group, delivery role, and explicit verification status.
- Guardrails: identifiers, versions, status, KMS key and presence of policy
  types; account-level enforced Guardrails (separately enumerated).
- Agents: identifiers, names, role ARN, encryption key, attached Guardrail,
  DRAFT action-group summaries, alias summaries and per-call completeness.
- Knowledge Bases: names, types, roles, storage types, data-source metadata,
  S3 bucket ARNs and ingestion prefixes. No document retrieval.
- Flows, Prompts, inference profiles, provisioned model throughputs and model
  customization jobs: metadata only. No prompt templates or model inputs.
- Every list operation uses bounded pagination, detects token loops, and
  reports denied, unsupported, failed or partially collected operations.
  Denial never yields a clean empty result.

## Finding semantics

- **Invocation logging review**: enabled Bedrock resources were enumerated,
  and successfully read regional logging configuration has no modality
  enabled. Configured resources do not establish actual inference activity.
  Other logging such as CloudTrail must be evaluated separately.
- **Agent explicit Guardrail review**: a verified Agent has no attached
  Guardrail and verified account-enforced Guardrail inventory is empty.
  Neither absence of other runtime protections nor actual unsafe inference
  is asserted.

Amazon Bedrock invocation logging can contain model input and output.
Configure retention, encryption and least privilege before enabling it.
Logging via bedrock-runtime is not exhaustive of other endpoints.

## Privileges and limits

AWS managed **SecurityAudit** often provides many Bedrock read operations.
Verify the policy version and effective permissions. For full coverage,
the role needs the relevant read-only actions, including:

- bedrock:GetModelInvocationLoggingConfiguration
- bedrock:ListGuardrails, bedrock:GetGuardrail,
  bedrock:ListEnforcedGuardrailsConfiguration
- bedrock:ListAgents, bedrock:GetAgent, bedrock:ListAgentAliases,
  bedrock:ListAgentActionGroups
- bedrock:ListKnowledgeBases, bedrock:GetKnowledgeBase,
  bedrock:ListDataSources, bedrock:GetDataSource
- bedrock:ListFlows, bedrock:ListPrompts,
  bedrock:ListInferenceProfiles, bedrock:ListProvisionedModelThroughputs,
  bedrock:ListModelCustomizationJobs

This is a per-account, per-Region configuration scan, not a proof of
Guardrail enforcement on every model invocation or coverage of all linked
accounts. Usage/role trust, S3/KMS destination controls and access to
Knowledge Base backing stores require separate cross-service assessment.

Validation: python -m pytest -q tests/test_m10_bedrock.py tests/test_m10_default_services.py
and the repository's guarded Windows/Ubuntu offline CI.
