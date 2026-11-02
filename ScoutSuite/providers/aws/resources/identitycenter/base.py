"""Regional IAM Identity Center instances and account access."""
from ScoutSuite.providers.aws.resources.regions import Regions

from .instances import Instances


class IdentityCenter(Regions):
    _children = [(Instances, 'instances')]

    def __init__(self, facade):
        super().__init__('sso-admin', facade)
