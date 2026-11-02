"""AWS WAFv2 regional Web ACLs and CloudFront global scope."""
from ScoutSuite.providers.aws.resources.regions import Regions

from .web_acls import WebACLs


class WAFv2Public(Regions):
    _children = [(WebACLs, 'web_acls')]

    def __init__(self, facade):
        super().__init__('wafv2', facade)
