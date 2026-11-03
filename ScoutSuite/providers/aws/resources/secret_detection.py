"""Masked secret detection for configuration text and environment variables (RC9).

Detections carry a type, a location and a preview that never contains the
secret value: AWS access key IDs are identifiers and are kept so the key can be
located and rotated; private keys show only their PEM header; everything else
is reduced to its length. Raw input text is never returned.
"""
import re

from ScoutSuite.providers.utils import secret_patterns

DETECTOR_VERSION = 'rc9-secret-detection-v1'

ACCESS_KEY_ID = re.compile(r'(?<![A-Z0-9])((?:AKIA|ASIA)[A-Z0-9]{16})(?![A-Z0-9])')
# 40-character AWS secret access keys are base64-like; require mixed case or
# '/'/'+' so SHA-1 hex digests and repeated characters are not reported.
SECRET_ACCESS_KEY = re.compile(r'(?<![0-9a-zA-Z/+])([0-9a-zA-Z/+]{40})(?![0-9a-zA-Z/+=])')
PRIVATE_KEY = re.compile(r'-----BEGIN ((?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY)-----')
URL_CREDENTIALS = re.compile(r'([a-zA-Z][a-zA-Z0-9+.-]{1,20})://([^/\s:@]{1,128}):([^@\s/]{1,256})@([^/\s:@]{1,253})')
ASSIGNMENT = re.compile(
    r'(?i)\b(password|passwd|pwd|secret|client_secret|aws_secret_access_key|aws_session_token|api_key|apikey|'
    r'access_token|auth_token|token)\b["\']?\s*[:=]\s*["\']?([^\s"\'$`{(<][^\s"\'`]{3,})')
SENSITIVE_NAME = re.compile(r'(?i)(pass(word|wd|phrase)?|pwd|secret|token|api_?key|private_?key|access_?key|'
                            r'credential|auth_?key|signing_?key)')
NON_SECRET_NAME_SUFFIX = re.compile(r'(?i)_(arn|name|id|path|param|parameter|url|endpoint|region|ttl|timeout|'
                                    r'enabled|file|header|length|expiry|expiration|type)$')
REFERENCE_VALUE = re.compile(r'^(arn:aws[a-zA-Z-]*:(secretsmanager|ssm|kms):|\{\{resolve:|ssm:|secretsmanager:)')
PLACEHOLDER_VALUE = re.compile(r'(?i)^(true|false|none|null|changeme|redacted|\*+|x+|-?\d{1,6})$')
# Catalog entries covered above, or bare words ("password") that match any script.
SKIPPED_CATALOG = frozenset(('AWS key', 'Generic Password', 'Generic Secret', 'PKCS8 private key', 'RSA private key',
                             'SSH (DSA) private key', 'SSH (EC) private key', 'SSH private key'))


def _redacted(value):
    return '[redacted: %d chars]' % len(value)


def _add(found, kind, location, preview):
    row = {'type': kind, 'location': location, 'preview': preview}
    if row not in found:
        found.append(row)


def _scan(text, location, found):
    for match in ACCESS_KEY_ID.finditer(text):
        _add(found, 'AWS access key ID', location, match.group(1))
    for match in SECRET_ACCESS_KEY.finditer(text):
        value = match.group(1)
        if ('/' in value or '+' in value) or (re.search('[a-z]', value) and re.search('[A-Z]', value)
                                              and re.search('[0-9]', value)):
            _add(found, 'Possible AWS secret access key', location, _redacted(value))
    for match in PRIVATE_KEY.finditer(text):
        _add(found, 'Private key', location, '-----BEGIN %s-----' % match.group(1))
    for match in URL_CREDENTIALS.finditer(text):
        _add(found, 'Credentials in URL', location, '%s://%s:%s@%s' % (
            match.group(1), match.group(2), _redacted(match.group(3)), match.group(4)))
    for match in ASSIGNMENT.finditer(text):
        _add(found, 'Secret assignment (%s)' % match.group(1).lower(), location, _redacted(match.group(2)))
    for name, pattern in secret_patterns.items():
        if name not in SKIPPED_CATALOG and pattern.search(text):
            _add(found, name, location, '[redacted]')


def detect_in_text(text):
    """Scan multi-line text (e.g. user data); locations are 1-based line numbers."""
    found = []
    if not isinstance(text, str) or not text:
        return found
    # PEM blocks span lines; report them at their first line.
    for match in PRIVATE_KEY.finditer(text):
        _add(found, 'Private key', 'line %d' % (text.count('\n', 0, match.start()) + 1),
             '-----BEGIN %s-----' % match.group(1))
    for number, line in enumerate(text.splitlines(), 1):
        if 'PRIVATE KEY-----' in line:
            continue
        _scan(line, 'line %d' % number, found)
    return found


def is_reference(value):
    return isinstance(value, str) and REFERENCE_VALUE.match(value) is not None


def detect_in_variables(variables):
    """Scan name/value pairs; the location is the variable name, never its value."""
    found = []
    for name, value in variables:
        if not isinstance(name, str) or not isinstance(value, str) or not value or is_reference(value):
            continue
        location = 'environment: %s' % name
        before = len(found)
        _scan(value, location, found)
        if len(found) == before and SENSITIVE_NAME.search(name) and not NON_SECRET_NAME_SUFFIX.search(name) \
                and not PLACEHOLDER_VALUE.match(value.strip()):
            _add(found, 'Sensitive variable name with literal value', location, _redacted(value))
    return found


def summarize_variable(value):
    """Displayable stand-in for an environment value: references are kept, literals are not."""
    if not isinstance(value, str):
        return '[redacted]'
    return value if is_reference(value) else _redacted(value)
