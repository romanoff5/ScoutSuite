"""Read legacy SqliteDict report values without allowing pickle to resolve code.

Existing report databases contain pickle-encoded JSON-compatible objects. New
writes remain compatible with the legacy format; reads always use this decoder.
This is not a general-purpose deserializer of arbitrary Python objects.
"""
import io
import pickle


MAX_SQLITE_VALUE_BYTES = 128 * 1024 * 1024
MAX_SQLITE_DEPTH = 96
MAX_SQLITE_NODES = 2_000_000


class _DataOnlyUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        raise pickle.UnpicklingError('Global objects are forbidden in report data')

    def persistent_load(self, identifier):
        raise pickle.UnpicklingError('Persistent pickle references are forbidden')


def decode_sqlite_value(blob):
    """Decode only JSON-compatible, bounded primitive trees from legacy files."""
    if not isinstance(blob, (bytes, bytearray, memoryview)):
        raise pickle.UnpicklingError('Invalid SQLite report value')
    if len(blob) > MAX_SQLITE_VALUE_BYTES:
        raise pickle.UnpicklingError('SQLite report value exceeds size limit')
    value = _DataOnlyUnpickler(io.BytesIO(blob)).load()
    pending = [(value, 0)]
    nodes = 0
    while pending:
        item, depth = pending.pop()
        nodes += 1
        if nodes > MAX_SQLITE_NODES or depth > MAX_SQLITE_DEPTH:
            raise pickle.UnpicklingError('SQLite report nesting or object count exceeds limit')
        if type(item) is dict:
            for key, child in item.items():
                if type(key) is not str:
                    raise pickle.UnpicklingError('Non-string SQLite report object key')
                pending.append((child, depth + 1))
        elif type(item) is list:
            pending.extend((child, depth + 1) for child in item)
        elif type(item) not in (str, int, float, bool, type(None)):
            raise pickle.UnpicklingError('Unsupported SQLite report value type')
    return value
