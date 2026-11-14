"""Default VPC with IGW and no observed ENIs is a candidate, not proof of abandonment."""
def classify_default_vpc_gateway(is_default, observation):
    if is_default is False:
        return 'not_applicable'
    if is_default is not True or not isinstance(observation, dict):
        return 'unknown'
    if observation.get('status') != 'complete':
        return 'unknown'
    igws, enis = observation.get('igw_count'), observation.get('eni_count')
    if type(igws) is not int or type(enis) is not int or igws < 0 or enis < 0:
        return 'unknown'
    if igws == 0:
        return 'not_applicable'
    return 'unused_candidate' if enis == 0 else 'in_use'
