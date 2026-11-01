"""Restricted decoder for SQLite report values stored with historical pickle format.

SqliteDict's default decoder is pickle.loads; never use it with untrusted
report files. Keep legacy pickle wire compatibility for JSON-like values only.
"""
import io
import math
import pickle


class UnsafeReportValue(ValueError):
    """A report value is not safe to deserialize as JSON-compatible data."""


class _RestrictedUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        raise pickle.UnpicklingError('Global references are forbidden in report data')

    def persistent_load(self, pid):
        raise pickle.UnpicklingError('Persistent objects are forbidden in report data')


def _validate_report_value(value, depth, budget):
    if depth > 64:
        raise UnsafeReportValue('Report value nesting exceeds security limit')
    budget[0] -= 1
    if budget[0] < 0:
        raise UnsafeReportValue('Report value exceeds item count limit')
    if value is None or type(value) in (bool, int, str):
        return
    if type(value) is float and math.isfinite(value):
        return
    if type(value) is list:
        for item in value:
            _validate_report_value(item, depth + 1, budget)
        return
    if type(value) is dict:
        for key, item in value.items():
            if type(key) is not str:
                raise UnsafeReportValue('Report mapping keys must be strings')
            _validate_report_value(item, depth + 1, budget)
        return
    raise UnsafeReportValue('Report contains unsupported object type')


def decode_report_pickle(data):
    """Load historical SqliteDict BLOBs without importing/calling globals."""
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise UnsafeReportValue('Report SQLite values must be BLOBs')
    if len(data) > 512 * 1024 * 1024:
        raise UnsafeReportValue('Report SQLite entry exceeds size limit')
    try:
        stream = io.BytesIO(data)
        value = _RestrictedUnpickler(stream).load()
        if stream.read(1):
            raise UnsafeReportValue('Trailing data in pickled report value')
        _validate_report_value(value, 0, [2_000_000])
        return value
    except (pickle.UnpicklingError, EOFError, RecursionError, OverflowError,
            TypeError, AttributeError) as error:
        raise UnsafeReportValue('Unsafe or corrupted report SQLite value') from error
