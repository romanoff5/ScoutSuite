# M04-D — opt-in strict completeness and finite AWS SDK timeouts

Base: `63ed73a0d82108d0f1b659279a7f4f3d5f1b10d6`. Scope is the AWS client factory and CLI/runtime integrity
contract. Default exit codes remain backward compatible. `--strict-completeness`
returns exit code **201** if the saved result is marked incomplete or no finding
evaluated any resources (zero checked items). Otherwise the normal 0/200
behavior applies. Strict mode does not change findings or authorize cloud writes.

AWS clients built through `AWSFacadeUtils.get_client` use botocore
`Config(connect_timeout=5, read_timeout=30,
retries={'mode':'standard','total_max_attempts':3})`. The separate
application-level throttle retry path defaults to a single attempt, avoiding
multiplication of retry layers. Other SDK constructors and dynamically
configured timeouts require a separate inventory; this is not a universal
end-to-end request deadline.

Remaining: HTML completeness banner (M09), broader AWS timeout coverage and
full real-runtime fresh-process/long-running scale evidence. CI gates must
pass before this branch may be integrated to master.
