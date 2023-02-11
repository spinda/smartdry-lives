import re
import struct
import zlib

class _EntrySchema:
    __slots__ = ('decode_value', 'empty_value', 'encode_value', 'key', 'key_bytes', 'sig', 'value_len')

    _HEADER_PREFIX_FORMAT = '<4s'
    _HEADER_PREFIX_LEN = struct.calcsize(_HEADER_PREFIX_FORMAT)
    _HEADER_PREFIX_END = _HEADER_PREFIX_LEN

    _HEADER_CRC_START = _HEADER_PREFIX_END
    _HEADER_CRC_FORMAT = '<I'
    _HEADER_CRC_LEN = struct.calcsize(_HEADER_CRC_FORMAT)
    _HEADER_CRC_END = _HEADER_CRC_START + _HEADER_CRC_LEN
    _HEADER_CRC_BASE = 0xffffffff

    _HEADER_KEY_START = _HEADER_CRC_END
    _HEADER_KEY_FORMAT = '<16s'
    _HEADER_KEY_LEN = struct.calcsize(_HEADER_KEY_FORMAT)
    _HEADER_KEY_END = _HEADER_KEY_START + _HEADER_KEY_LEN

    _HEADER_VALUE_SIZE_START = _HEADER_KEY_END
    _HEADER_VALUE_SIZE_FORMAT = '<H'
    _HEADER_VALUE_SIZE_LEN = struct.calcsize(_HEADER_VALUE_SIZE_FORMAT)
    _HEADER_VALUE_SIZE_PADDING = 2
    _HEADER_VALUE_SIZE_END = _HEADER_VALUE_SIZE_START + _HEADER_VALUE_SIZE_LEN + _HEADER_VALUE_SIZE_PADDING

    _HEADER_VALUE_CRC_START = _HEADER_VALUE_SIZE_END
    _HEADER_VALUE_CRC_FORMAT = '<I'
    _HEADER_VALUE_CRC_LEN = struct.calcsize(_HEADER_VALUE_CRC_FORMAT)
    _HEADER_VALUE_CRC_END = _HEADER_VALUE_CRC_START + _HEADER_VALUE_CRC_LEN
    _HEADER_VALUE_CRC_BASE = _HEADER_CRC_BASE

    _HEADER_END = _HEADER_VALUE_CRC_END
    _HEADER_LEN = _HEADER_END

    _VALUE_START = _HEADER_END

    def __init__(self, *, key, value_len, encode_value, decode_value):
        self.key = key
        self.value_len = value_len
        self.encode_value = encode_value
        self.decode_value = decode_value

        self.key_bytes = self.key.encode('ascii')
        self.empty_value = b'\xff' * self.value_len
        self.sig = self._generate_sig()

    def _generate_sig(self):
        sig = bytearray(b'\xff' * (self._HEADER_VALUE_CRC_START - self._HEADER_KEY_START))
        struct.pack_into(self._HEADER_KEY_FORMAT, sig, 0, self.key_bytes)
        struct.pack_into(self._HEADER_VALUE_SIZE_FORMAT, sig, self._HEADER_VALUE_SIZE_START - self._HEADER_KEY_START, self.value_len)
        return bytes(sig)

    @classmethod
    def compile_scanner_re(cls, schemas):
        return re.compile(
            b'.' * cls._HEADER_KEY_START +
            b'(?P<sig>' + b'|'.join(re.escape(schema.sig) for schema in schemas) + b')'
        )

    def extract_value(self, buf, offset):
        value_start = offset + self._VALUE_START
        value_end = value_start + self.value_len
        if buf[value_start:value_end] == self.empty_value:
            return None
        return self.decode_value(buf, value_start)

    def patch_value(self, buf, offset, value):
        self.encode_value(buf, offset + self._VALUE_START, value)

        value_start = offset + self._VALUE_START
        value_end = value_start + self.value_len
        value_crc = zlib.crc32(buf[value_start:value_end], self._HEADER_VALUE_CRC_BASE)
        struct.pack_into(self._HEADER_VALUE_CRC_FORMAT, buf, offset + self._HEADER_VALUE_CRC_START, value_crc)

        header_crc_input = bytearray(self._HEADER_LEN - self._HEADER_CRC_LEN)
        header_crc_input[:self._HEADER_CRC_START] = buf[offset:offset + self._HEADER_CRC_START]
        header_crc_input[self._HEADER_CRC_START:] = buf[offset + self._HEADER_CRC_END:offset + self._HEADER_END]
        header_crc = zlib.crc32(header_crc_input, self._HEADER_CRC_BASE)
        struct.pack_into(self._HEADER_CRC_FORMAT, buf, offset + self._HEADER_CRC_START, header_crc)

_SCHEMAS = []

def _encode_null_terminated_bytes(fmt, buf, offset, value):
    struct.pack_into(fmt, buf, offset, value)

def _decode_null_terminated_bytes(fmt, buf, offset):
    value_raw, = struct.unpack_from(fmt, buf, offset)
    try:
        null_terminator_index = value_raw.index(0)
    except ValueError:
        return value_raw
    return value_raw[:null_terminator_index]

# SSID Entries

_SSID_VALUE_FORMAT = '<I32s'

def _encode_ssid_value(buf, offset, ssid):
    struct.pack_into(_SSID_VALUE_FORMAT, buf, offset, len(ssid), ssid)

def _decode_ssid_value(buf, offset):
    ssid_size, ssid_raw = struct.unpack_from(_SSID_VALUE_FORMAT, buf, offset)
    return ssid_raw[:ssid_size]

_SSID_SCHEMA = _EntrySchema(
    key='sta.ssid',
    value_len=struct.calcsize(_SSID_VALUE_FORMAT),
    encode_value=_encode_ssid_value,
    decode_value=_decode_ssid_value,
)
_SCHEMAS.append(_SSID_SCHEMA)

# Password Entries

_PASSWORD_VALUE_FORMAT = '<65s'

def _encode_password_value(buf, offset, password):
    _encode_null_terminated_bytes(_PASSWORD_VALUE_FORMAT, buf, offset, password)

def _decode_password_value(buf, offset):
    return _decode_null_terminated_bytes(_PASSWORD_VALUE_FORMAT, buf, offset)

_PASSWORD_SCHEMA = _EntrySchema(
    key='sta.pswd',
    value_len=struct.calcsize(_PASSWORD_VALUE_FORMAT),
    encode_value=_encode_password_value,
    decode_value=_decode_password_value,
)
_SCHEMAS.append(_PASSWORD_SCHEMA)

# AP Info Entries

_AP_INFO_RECORD_COUNT = 5

_AP_INFO_RECORD_FLAGS_FORMAT = '<I'
_AP_INFO_RECORD_FLAGS_LEN = struct.calcsize(_AP_INFO_RECORD_FLAGS_FORMAT)
_AP_INFO_RECORD_FLAGS_END = _AP_INFO_RECORD_FLAGS_LEN

_AP_INFO_RECORD_SSID_START = _AP_INFO_RECORD_FLAGS_END
_AP_INFO_RECORD_SSID_FORMAT = '<32s'
_AP_INFO_RECORD_SSID_LEN = struct.calcsize(_AP_INFO_RECORD_SSID_FORMAT)
_AP_INFO_RECORD_SSID_END = _AP_INFO_RECORD_SSID_START + _AP_INFO_RECORD_SSID_LEN

def _encode_ap_info_record_ssid(buf, offset, ssid):
    _encode_null_terminated_bytes(_AP_INFO_RECORD_SSID_FORMAT, buf, offset, ssid)

def _decode_ap_info_record_ssid(buf, offset):
    return _decode_null_terminated_bytes(_AP_INFO_RECORD_SSID_FORMAT, buf, offset)

_AP_INFO_RECORD_PASSWORD_START = _AP_INFO_RECORD_SSID_END
_AP_INFO_RECORD_PASSWORD_END = _AP_INFO_RECORD_PASSWORD_START + _PASSWORD_SCHEMA.value_len

_AP_INFO_RECORD_CHANNEL_START = _AP_INFO_RECORD_PASSWORD_END
_AP_INFO_RECORD_CHANNEL_FORMAT = '<B'
_AP_INFO_RECORD_CHANNEL_LEN = struct.calcsize(_AP_INFO_RECORD_CHANNEL_FORMAT)
_AP_INFO_RECORD_CHANNEL_END = _AP_INFO_RECORD_CHANNEL_START + _AP_INFO_RECORD_CHANNEL_LEN

_AP_INFO_RECORD_PADDING = 38
_AP_INFO_RECORD_END = _AP_INFO_RECORD_CHANNEL_END + _AP_INFO_RECORD_PADDING
_AP_INFO_RECORD_LEN = _AP_INFO_RECORD_END

_AP_INFO_VALUE_LEN = _AP_INFO_RECORD_COUNT * _AP_INFO_RECORD_LEN

def _encode_ap_info_value(buf, offset, ap_info):
    for record_index in range(0, min(len(ap_info), _AP_INFO_RECORD_COUNT)):
        record_offset = offset + record_index * _AP_INFO_RECORD_LEN
        ssid, password = ap_info[record_index]

        ssid_offset = record_offset + _AP_INFO_RECORD_SSID_START
        _encode_ap_info_record_ssid(buf, ssid_offset, ssid)

        password_offset = record_offset + _AP_INFO_RECORD_PASSWORD_START
        _PASSWORD_SCHEMA.encode_value(buf, password_offset, password)

def _decode_ap_info_value(buf, offset):
    ap_info = [None,] * _AP_INFO_RECORD_COUNT

    for record_index in range(0, _AP_INFO_RECORD_COUNT):
        record_offset = offset + record_index * _AP_INFO_RECORD_LEN

        ssid_offset = record_offset + _AP_INFO_RECORD_SSID_START
        ssid = _decode_ap_info_record_ssid(buf, ssid_offset)

        password_offset = record_offset + _AP_INFO_RECORD_PASSWORD_START
        password = _PASSWORD_SCHEMA.decode_value(buf, password_offset)

        ap_info[record_index] = (ssid, password)

    return ap_info

_AP_INFO_SCHEMA = _EntrySchema(
    key='sta.apinfo',
    value_len=_AP_INFO_VALUE_LEN,
    encode_value=_encode_ap_info_value,
    decode_value=_decode_ap_info_value,
)
_SCHEMAS.append(_AP_INFO_SCHEMA)

_SCANNER_RE = _EntrySchema.compile_scanner_re(_SCHEMAS)
_SIG_TO_SCHEMA_MAP = dict((schema.sig, schema) for schema in _SCHEMAS)

def extract_wifi_data(image, new_wifi_data):
    ssid = new_wifi_data['ssid']
    password = new_wifi_data['password']
    ap_info = [(ssid, password)] * _AP_INFO_RECORD_COUNT

    for scanner_match in _SCANNER_RE.finditer(image):
        print()
        offset = scanner_match.start()
        sig = scanner_match['sig']
        schema = _SIG_TO_SCHEMA_MAP[sig]
        print(f'{schema.key} @ {offset}')

        value = schema.extract_value(image, offset)
        if value is not None:
            print(f'=> {value}')

        if schema == _SSID_SCHEMA:
            new_value = ssid
        elif schema == _PASSWORD_SCHEMA:
            new_value = password
        elif schema == _AP_INFO_SCHEMA:
            new_value = ap_info
        else:
            continue
        print(f'patching to: {new_value}')
        schema.patch_value(image, offset, new_value)

    return image
