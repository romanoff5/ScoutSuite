from ScoutSuite.providers.aws.facade.base import AWSFacade
from ScoutSuite.providers.aws.resources.base import AWSResources
from ScoutSuite.providers.utils import get_non_provider_id
from ScoutSuite.core.rule_evidence import classify_lambda_runtime
from ScoutSuite.core.run_context import get_current_run_context
from ScoutSuite.providers.aws.resources.secret_detection import DETECTOR_VERSION, detect_in_variables, summarize_variable


class Functions(AWSResources):
    def __init__(self, facade: AWSFacade, region: str):
        super().__init__(facade)
        self.region = region

    async def fetch_all(self):
        raw_functions = await self.facade.awslambda.get_functions(self.region)
        for raw_function in raw_functions:
            name, resource = await self._parse_function(raw_function)
            self[name] = resource

    async def _parse_function(self, raw_function):

        function_dict = {}
        function_dict['name'] = raw_function.get('FunctionName')
        function_dict['arn'] = raw_function.get('FunctionArn')
        function_dict['runtime'] = raw_function.get('Runtime')
        function_dict['package_type'] = raw_function.get('PackageType')
        function_dict['runtime_lifecycle_status'] = {
            'secure': 'supported', 'insecure': 'deprecated',
            'not_applicable': 'image', 'unknown': 'unknown'
        }[classify_lambda_runtime(function_dict)]
        function_dict['handler'] = raw_function.get('Handler')
        function_dict['code_size'] = raw_function.get('CodeSize')
        function_dict['description'] = raw_function.get('Description')
        function_dict['timeout'] = raw_function.get('Timeout')
        function_dict['memory_size'] = raw_function.get('MemorySize')
        function_dict['last_modified'] = raw_function.get('LastModified')
        function_dict['code_sha256'] = raw_function.get('CodeSha256')
        function_dict['version'] = raw_function.get('Version')
        function_dict['tracing_config'] = raw_function.get('TracingConfig')
        function_dict['revision_id'] = raw_function.get('RevisionId')

        await self._add_role_information(function_dict, raw_function.get('Role'))
        await self._add_access_policy_information(function_dict)
        self._add_env_variables(function_dict, raw_function.get('Environment'))

        return get_non_provider_id(function_dict['name']), function_dict

    async def _add_role_information(self, function_dict, role_id):
        # Make it easier to build rules based on policies attached to execution roles
        function_dict['role_arn'] = role_id
        role_name = role_id.split("/")[-1]
        function_dict['execution_role'] = await self.facade.awslambda.get_role_with_managed_policies(role_name)
        if function_dict.get('execution_role'):
            statements = []
            for policy in function_dict['execution_role'].get('policies'):
                if 'Document' in policy and 'Statement' in policy['Document']:
                    statements += policy['Document']['Statement']
            function_dict['execution_role']['policy_statements'] = statements

    async def _add_access_policy_information(self, function_dict):
        access_policy = await self.facade.awslambda.get_access_policy(function_dict['name'], self.region)

        if access_policy:
            function_dict['access_policy'] = access_policy
        else:
            # If there's no policy, set an empty one
            function_dict['access_policy'] = {'Version': '2012-10-17',
                                              'Id': 'default',
                                              'Statement': []}

    @staticmethod
    def _add_env_variables(function_dict, environment):
        """RC9: keep variable names, secret references and masked detections, never literal values.

        ListFunctions returns the Environment block; an Error there (e.g. a KMS key
        the scanner cannot use) leaves the evidence UNKNOWN.
        """
        function_dict['secret_detector_version'] = DETECTOR_VERSION
        variables = environment.get('Variables') if isinstance(environment, dict) else None
        error = environment.get('Error') if isinstance(environment, dict) else None
        if error or (environment is not None and not isinstance(environment, dict)) or                 (variables is not None and not isinstance(variables, dict)):
            context = get_current_run_context()
            if context is not None:
                context.record_collection_issue('partial', 'lambda', 'EnvironmentVariablesUnreadable')
            function_dict['env_variables_status'] = 'unknown'
            function_dict['env_variables_error_code'] = error.get('ErrorCode') if isinstance(error, dict) else None
            function_dict['env_variable_names'] = []
            function_dict['env_variables'] = {}
            function_dict['env_secret_detections'] = []
            function_dict['env_secret_status'] = 'unknown'
            return
        variables = variables or {}
        function_dict['env_variables_status'] = 'complete'
        function_dict['env_variable_names'] = list(variables.keys())
        function_dict['env_variables'] = {name: summarize_variable(value) for name, value in variables.items()}
        function_dict['env_secret_detections'] = detect_in_variables(variables.items())
        function_dict['env_secret_status'] = ('detected' if function_dict['env_secret_detections'] else
                                              'none' if variables else 'no_variables')
