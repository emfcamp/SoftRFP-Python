"""
AaMiDe protocol message definitions.

Implements the message types used in the DECT OMM <-> RFP communication protocol.
"""

import enum
import hashlib
import struct
from typing import Optional

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .hex_encoding import byte_to_hex


class MsgType(enum.IntEnum):
    """AaMiDe message type codes."""
    ACK = 0x0001
    NACK = 0x0002
    HEARTBEAT = 0x0003

    SYS_IP_OPTIONS = 0x0101
    SYS_LED = 0x0102
    SYS_INFO = 0x0103
    SYS_SPY = 0x0104
    SYS_HEARTBEAT_INTERVAL = 0x0105
    SYS_RSX = 0x0106
    SYS_SYSLOG = 0x0107
    SYS_MAX_CHANNELS = 0x0108
    SYS_HTTP_SET = 0x0109
    SYS_PASSWD = 0x010A
    SYS_CRYPTED_PACKET = 0x010B
    SYS_OMM_CONTROL = 0x010C
    SYS_STATE_DUMP = 0x010D
    SYS_RPING = 0x010E
    SYS_STATE_DUMP_REQ = 0x010F
    SYS_STATE_DUMP_RES = 0x0110
    SYS_NEW_SW = 0x0111
    SYS_AUDIO_LOG = 0x0112
    SYS_USB_OVERLOAD = 0x0113
    SYS_SW_CONTAINER = 0x0115
    SYS_CORE_DUMP = 0x0116
    SYS_VSNTP_TIME = 0x0117
    SYS_RANDOM_VALUE = 0x0118
    SYS_UPDATE_802_1X_SUPPLICANT = 0x0119
    SYS_INIT = 0x0120
    SYS_RESET = 0x0121
    SYS_SUPPLICANT_MD5 = 0x0122
    SYS_STREAM_INFO = 0x0123
    SYS_RFP_AUTH_KEY = 0x0124
    SYS_RFP_RE_ENROLEMENT = 0x0125
    SYS_ENCRYPTION_CONF = 0x0126
    SYS_FIRMWARE_UPDATE = 0x0127
    SYS_COUNTRY_TAG = 0x0128
    SYS_PING = 0x0129
    SYS_AUTHENTICATE = 0x012D
    SYS_LICENSE_TIMER = 0x0134

    MEDIA_OPEN = 0x0200
    MEDIA_CONF = 0x0201
    MEDIA_CLOSE = 0x0202
    MEDIA_START = 0x0203
    MEDIA_STOP = 0x0204
    MEDIA_STATISTICS = 0x0205
    MEDIA_REDIRECT_START = 0x0206
    MEDIA_REDIRECT_STOP = 0x0207
    MEDIA_RESTART = 0x0208
    MEDIA_DTMF = 0x0209
    MEDIA_DSP_CLOSE = 0x020A
    MEDIA_TONE2 = 0x020B
    MEDIA_BANDWIDTH_SWO = 0x020C
    MEDIA_MUTE = 0x020D
    MEDIA_G729_USED = 0x020E
    MEDIA_TRACE_PPN = 0x020F
    MEDIA_EOS_DETECT = 0x0210
    MEDIA_AUDIO_STATISTICS = 0x0211
    MEDIA_VIDEO_STATE = 0x0212
    MEDIA_CHANNEL_MOD_INFO = 0x0213

    DNM = 0x0301
    SYNC = 0x0302

    SNMP_RFP_UPDATE = 0x0501

    SYS_LICENSE_TIMER_QUERY = 0xFFFF  # internal sentinel


class RfpCapabilities(enum.IntFlag):
    """RFP capability flags."""
    NONE = 0
    NORMAL_TX = 0x00000008
    INDOOR = 0x00000010
    WLAN = 0x00000020
    ENCRYPTION = 0x00000100
    FREQUENCY_SHIFT = 0x00000200
    LOW_TX = 0x00000400
    WLAN_DFS_SUPPORTED = 0x00010000
    ADVANCED_FEATURE = 0x0000F000  # Reserved12 | Reserved14 | Reserved15 | Reserved16


class RfpType(enum.IntEnum):
    """RFP hardware types."""
    RFP31 = 0x01
    RFP33 = 0x02
    RFP41 = 0x03
    RFP32 = 0x04
    RFP32US = 0x05
    RFP34 = 0x06
    RFP34US = 0x07
    RFP42 = 0x08
    RFP42US = 0x09
    RFP35 = 0x0B
    RFP36 = 0x0C
    RFP43 = 0x0D
    RFP37 = 0x0E
    RFP44 = 0x10
    RFP45 = 0x11
    RFP47 = 0x12
    RFP48 = 0x13
    PC_ECM = 0x14
    PC = 0x15
    # License RFP variants (0x1000 + base type)
    RFPL31 = 0x1001
    RFPL33 = 0x1002
    RFPL41 = 0x1003
    RFPL32US = 0x1005
    RFPL34 = 0x1006
    RFPL34US = 0x1007
    RFPL42 = 0x1008
    RFPL42US = 0x1009
    RFPL35 = 0x100B
    RFPL36 = 0x100C
    RFPL43 = 0x100D
    RFPL37 = 0x100E
    # Software License RFP variants (0x2000 + base type)
    RFPSL35 = 0x200B
    RFPSL36 = 0x200C
    RFPSL43 = 0x200D
    RFPSL37 = 0x200E


# --- Base Message ---

class AaMiDeMessage:
    """Base class for all AaMiDe protocol messages."""

    def __init__(self, msg_type: MsgType, data: Optional[bytes] = None):
        self.type = msg_type
        self._raw_length = 0
        self.raw = b''
        if data is not None:
            self._raw_length = struct.unpack_from('>H', data, 2)[0]
            self.raw = bytes(data[4:4 + self._raw_length])

    @property
    def message_length(self) -> int:
        """Total length of the original packet (header + payload)."""
        return self._raw_length + 4

    @property
    def length(self) -> int:
        """Total serialization length (header + payload)."""
        return 4

    def serialize(self) -> bytearray:
        """Serialize the message to bytes."""
        size = self.length
        data = bytearray(size)
        struct.pack_into('>HH', data, 0, int(self.type), size - 4)
        return data

    def log(self) -> str:
        """Return a log string for this message."""
        name = self.type.name if isinstance(self.type, MsgType) else f"0x{int(self.type):04x}"
        s = f"{name:<22}({self._raw_length:4}) "
        if self.raw:
            s += f"Raw({byte_to_hex(self.raw)}) "
        return s

    @staticmethod
    def create(data: bytes) -> 'AaMiDeMessage':
        """Factory method to create the appropriate message subclass."""
        msg_type_val = struct.unpack_from('>H', data, 0)[0]
        try:
            msg_type = MsgType(msg_type_val)
        except ValueError:
            return AaMiDeMessage(MsgType(msg_type_val), data)

        if msg_type == MsgType.SYS_HEARTBEAT_INTERVAL:
            return SysHeartbeatIntervalMessage(data)
        elif msg_type == MsgType.SYS_LICENSE_TIMER:
            return SysLicenseTimerMessage(data)
        elif msg_type == MsgType.HEARTBEAT:
            return HeartbeatMessage(data=data)
        elif msg_type == MsgType.SYS_INIT:
            return SysInitMessage(data=data)
        elif msg_type == MsgType.SYS_ENCRYPTION_CONF:
            return SysEncryptionConf(data=data)
        else:
            return AaMiDeMessage(msg_type, data)


# --- Specific Messages ---

class HeartbeatMessage(AaMiDeMessage):
    """Heartbeat message carrying uptime information."""

    NANOSECONDS_PER_TICK = 100  # 1000000 / 10000 (TimeSpan.TicksPerMillisecond)

    def __init__(self, uptime_ms: float = 0.0, uptime_ns: int = 0, data: Optional[bytes] = None):
        if data is not None:
            super().__init__(MsgType.HEARTBEAT, data)
            span = self.raw
            self.uptime_ms = struct.unpack_from('<I', span, 0)[0]
            self.uptime_ns = struct.unpack_from('<I', span, 4)[0]
        else:
            super().__init__(MsgType.HEARTBEAT)
            self.uptime_ms = int(uptime_ms)
            self.uptime_ns = uptime_ns

    @classmethod
    def from_seconds(cls, total_seconds: float) -> 'HeartbeatMessage':
        """Create a heartbeat message from a total seconds value."""
        ms = int(total_seconds * 1000)
        remainder_s = total_seconds - (ms / 1000.0)
        ns = int(remainder_s * 1_000_000_000)
        if ns < 0:
            ns = 0
        return cls(uptime_ms=ms, uptime_ns=ns)

    @property
    def length(self) -> int:
        return super().length + 8

    def serialize(self) -> bytearray:
        data = bytearray(self.length)
        struct.pack_into('>HH', data, 0, int(self.type), self.length - 4)
        struct.pack_into('<I', data, 4, self.uptime_ms & 0xFFFFFFFF)
        struct.pack_into('<I', data, 8, self.uptime_ns & 0xFFFFFFFF)
        return data

    def log(self) -> str:
        s = super().log()
        total_s = self.uptime_ms / 1000.0
        s += f"Uptime({total_s:.3f}s)"
        return s


class SysHeartbeatIntervalMessage(AaMiDeMessage):
    """System heartbeat interval configuration message."""

    def __init__(self, data: bytes):
        super().__init__(MsgType.SYS_HEARTBEAT_INTERVAL, data)
        self.interval_seconds = self.raw[0] if self.raw else 0

    def log(self) -> str:
        s = super().log()
        s += f"Interval({self.interval_seconds}s)"
        return s


class SysLicenseTimerMessage(AaMiDeMessage):
    """System license timer message."""

    def __init__(self, data: Optional[bytes] = None, grace_period_minutes: int = 0,
                 md5: bytes = b''):
        if data is not None:
            super().__init__(MsgType.SYS_LICENSE_TIMER, data)
            self.grace_period_minutes = struct.unpack_from('>I', self.raw, 0)[0]
            self.md5 = bytes(self.raw[4:20])
        else:
            super().__init__(MsgType.SYS_LICENSE_TIMER)
            self.grace_period_minutes = grace_period_minutes
            self.md5 = md5

    @property
    def length(self) -> int:
        return super().length + 20

    def serialize(self) -> bytearray:
        data = bytearray(self.length)
        struct.pack_into('>HH', data, 0, int(self.type), self.length - 4)
        struct.pack_into('>I', data, 4, self.grace_period_minutes)
        data[8:8 + len(self.md5)] = self.md5[:16]
        return data

    def log(self) -> str:
        s = super().log()
        if self.grace_period_minutes > 0x7FFFFFFF:
            s += "Query "
        else:
            s += f"Grace Period({self.grace_period_minutes}min) "
        s += f"Md5({byte_to_hex(self.md5)})"
        return s


class SysEncryptionConf(AaMiDeMessage):
    """System encryption confirmation message (empty payload)."""

    def __init__(self, data: Optional[bytes] = None):
        if data is not None:
            super().__init__(MsgType.SYS_ENCRYPTION_CONF, data)
        else:
            super().__init__(MsgType.SYS_ENCRYPTION_CONF)


class SysInitMessage(AaMiDeMessage):
    """System init message with RFP capabilities, AES-encrypted metadata, and MD5 signature."""

    AES_KEY = bytes([
        0xe7, 0x05, 0xbc, 0x1a, 0x92, 0x41, 0x2f, 0x32,
        0x62, 0xc5, 0x47, 0xf8, 0x79, 0x46, 0x93, 0x69,
        0x97, 0xe6, 0x90, 0xad, 0xa4, 0x6f, 0xad, 0x25,
        0xbb, 0xc6, 0x26, 0xf6, 0xf5, 0xa5, 0xa6, 0xce,
    ])

    SIGNATURE_KEY = bytes.fromhex(
        "e7adda3adb0521f3d3fbdf3a18ee8648"
        "b47398b1570c2b45ef8d2a9180a1a32c"
        "69284a9c97d444abf87f5c578f942821"
        "4dd0183cba969dc5"
    )

    CRC_TABLE = [
        0x00000000, 0xB71DC104, 0x6E3B8209, 0xD926430D,
        0xDC760413, 0x6B6BC517, 0xB24D861A, 0x0550471E,
        0xB8ED0826, 0x0FF0C922, 0xD6D68A2F, 0x61CB4B2B,
        0x649B0C35, 0xD386CD31, 0x0AA08E3C, 0xBDBD4F38,
        0x70DB114C, 0xC7C6D048, 0x1EE09345, 0xA9FD5241,
        0xACAD155F, 0x1BB0D45B, 0xC2969756, 0x758B5652,
        0xC836196A, 0x7F2BD86E, 0xA60D9B63, 0x11105A67,
        0x14401D79, 0xA35DDC7D, 0x7A7B9F70, 0xCD665E74,
        0xE0B62398, 0x57ABE29C, 0x8E8DA191, 0x39906095,
        0x3CC0278B, 0x8BDDE68F, 0x52FBA582, 0xE5E66486,
        0x585B2BBE, 0xEF46EABA, 0x3660A9B7, 0x817D68B3,
        0x842D2FAD, 0x3330EEA9, 0xEA16ADA4, 0x5D0B6CA0,
        0x906D32D4, 0x2770F3D0, 0xFE56B0DD, 0x494B71D9,
        0x4C1B36C7, 0xFB06F7C3, 0x2220B4CE, 0x953D75CA,
        0x28803AF2, 0x9F9DFBF6, 0x46BBB8FB, 0xF1A679FF,
        0xF4F63EE1, 0x43EBFFE5, 0x9ACDBCE8, 0x2DD07DEC,
        0x77708634, 0xC06D4730, 0x194B043D, 0xAE56C539,
        0xAB068227, 0x1C1B4323, 0xC53D002E, 0x7220C12A,
        0xCF9D8E12, 0x78804F16, 0xA1A60C1B, 0x16BBCD1F,
        0x13EB8A01, 0xA4F64B05, 0x7DD00808, 0xCACDC90C,
        0x07AB9778, 0xB0B6567C, 0x69901571, 0xDE8DD475,
        0xDBDD936B, 0x6CC0526F, 0xB5E61162, 0x02FBD066,
        0xBF469F5E, 0x085B5E5A, 0xD17D1D57, 0x6660DC53,
        0x63309B4D, 0xD42D5A49, 0x0D0B1944, 0xBA16D840,
        0x97C6A5AC, 0x20DB64A8, 0xF9FD27A5, 0x4EE0E6A1,
        0x4BB0A1BF, 0xFCAD60BB, 0x258B23B6, 0x9296E2B2,
        0x2F2BAD8A, 0x98366C8E, 0x41102F83, 0xF60DEE87,
        0xF35DA999, 0x4440689D, 0x9D662B90, 0x2A7BEA94,
        0xE71DB4E0, 0x500075E4, 0x892636E9, 0x3E3BF7ED,
        0x3B6BB0F3, 0x8C7671F7, 0x555032FA, 0xE24DF3FE,
        0x5FF0BCC6, 0xE8ED7DC2, 0x31CB3ECF, 0x86D6FFCB,
        0x8386B8D5, 0x349B79D1, 0xEDBD3ADC, 0x5AA0FBD8,
        0xEEE00C69, 0x59FDCD6D, 0x80DB8E60, 0x37C64F64,
        0x3296087A, 0x858BC97E, 0x5CAD8A73, 0xEBB04B77,
        0x560D044F, 0xE110C54B, 0x38368646, 0x8F2B4742,
        0x8A7B005C, 0x3D66C158, 0xE4408255, 0x535D4351,
        0x9E3B1D25, 0x2926DC21, 0xF0009F2C, 0x471D5E28,
        0x424D1936, 0xF550D832, 0x2C769B3F, 0x9B6B5A3B,
        0x26D61503, 0x91CBD407, 0x48ED970A, 0xFFF0560E,
        0xFAA01110, 0x4DBDD014, 0x949B9319, 0x2386521D,
        0x0E562FF1, 0xB94BEEF5, 0x606DADF8, 0xD7706CFC,
        0xD2202BE2, 0x653DEAE6, 0xBC1BA9EB, 0x0B0668EF,
        0xB6BB27D7, 0x01A6E6D3, 0xD880A5DE, 0x6F9D64DA,
        0x6ACD23C4, 0xDDD0E2C0, 0x04F6A1CD, 0xB3EB60C9,
        0x7E8D3EBD, 0xC990FFB9, 0x10B6BCB4, 0xA7AB7DB0,
        0xA2FB3AAE, 0x15E6FBAA, 0xCCC0B8A7, 0x7BDD79A3,
        0xC660369B, 0x717DF79F, 0xA85BB492, 0x1F467596,
        0x1A163288, 0xAD0BF38C, 0x742DB081, 0xC3307185,
        0x99908A5D, 0x2E8D4B59, 0xF7AB0854, 0x40B6C950,
        0x45E68E4E, 0xF2FB4F4A, 0x2BDD0C47, 0x9CC0CD43,
        0x217D827B, 0x9660437F, 0x4F460072, 0xF85BC176,
        0xFD0B8668, 0x4A16476C, 0x93300461, 0x242DC565,
        0xE94B9B11, 0x5E565A15, 0x87701918, 0x306DD81C,
        0x353D9F02, 0x82205E06, 0x5B061D0B, 0xEC1BDC0F,
        0x51A69337, 0xE6BB5233, 0x3F9D113E, 0x8880D03A,
        0x8DD09724, 0x3ACD5620, 0xE3EB152D, 0x54F6D429,
        0x7926A9C5, 0xCE3B68C1, 0x171D2BCC, 0xA000EAC8,
        0xA550ADD6, 0x124D6CD2, 0xCB6B2FDF, 0x7C76EEDB,
        0xC1CBA1E3, 0x76D660E7, 0xAFF023EA, 0x18EDE2EE,
        0x1DBDA5F0, 0xAAA064F4, 0x738627F9, 0xC49BE6FD,
        0x09FDB889, 0xBEE0798D, 0x67C63A80, 0xD0DBFB84,
        0xD58BBC9A, 0x62967D9E, 0xBBB03E93, 0x0CADFF97,
        0xB110B0AF, 0x060D71AB, 0xDF2B32A6, 0x6836F3A2,
        0x6D66B4BC, 0xDA7B75B8, 0x035D36B5, 0xB440F7B1,
    ]

    MAGIC = 0x00037a20000529d9

    def __init__(self, mac: bytes = b'', capabilities: int = 0, data: Optional[bytes] = None):
        if data is not None:
            # Parse received message
            super().__init__(MsgType.SYS_INIT, data)
            # Parse fields from raw payload - used for logging received SYS_INIT
            self.mac = mac
            self.capabilities = capabilities
            self.signature = b''
        else:
            # Construct message for sending
            super().__init__(MsgType.SYS_INIT)
            self.mac = mac  # 6 bytes
            self.hardware = RfpType.RFP35
            self.capabilities = capabilities
            self.magic = self.MAGIC
            self.protocol = 0x00080201  # 8.1 (from rfpproxy test data)
            self.sw_version = "SIP-DECT 8.1SP3-FK24"
            self.signature = b'\x00' * 16

    @property
    def length(self) -> int:
        return super().length + 0x110

    def _calculate_crc32(self, data: bytes) -> int:
        result = 0
        for b in data:
            result = self.CRC_TABLE[b ^ (result & 0xFF)] ^ (result >> 8)
        result = self.CRC_TABLE[len(data) ^ (result & 0xFF)] ^ (result >> 8)
        # Reverse endianness and NOT
        result = ~result & 0xFFFFFFFF
        # Reverse byte order (ReverseEndianness)
        result = struct.unpack('<I', struct.pack('>I', result))[0]
        return result

    def _aes_encrypt(self, plain: bytes) -> bytes:
        cipher = Cipher(algorithms.AES(self.AES_KEY), modes.ECB())
        enc = cipher.encryptor()
        return enc.update(plain) + enc.finalize()

    def _aes_decrypt(self, crypted: bytes) -> bytes:
        cipher = Cipher(algorithms.AES(self.AES_KEY), modes.ECB())
        dec = cipher.decryptor()
        return dec.update(crypted) + dec.finalize()

    def serialize(self) -> bytearray:
        data = bytearray(self.length)
        # Header
        struct.pack_into('>HH', data, 0, int(self.type), self.length - 4)
        payload = memoryview(data)[4:]

        # Hardware type
        struct.pack_into('>i', payload, 0, int(self.hardware))
        # Reserved1 (4 bytes) - zeros
        # MAC (6 bytes at offset 0x08)
        payload[0x08:0x08 + 6] = self.mac[:6]
        # Reserved2 (6 bytes) - zeros
        # Capabilities (4 bytes at offset 0x14)
        struct.pack_into('>I', payload, 0x14, self.capabilities)

        # Build the AES plaintext (64 bytes)
        plain = bytearray(0x40)
        struct.pack_into('>Q', plain, 0, self.magic)
        plain[8:14] = self.mac[:6]  # Mac2
        struct.pack_into('<H', plain, 14, 0)  # Branding
        # Reserved3 (44 bytes) - zeros
        crc = self._calculate_crc32(bytes(plain[:60]))
        struct.pack_into('>I', plain, 60, crc)

        # AES encrypt
        crypted = self._aes_encrypt(bytes(plain))
        payload[0x18:0x18 + 0x40] = crypted

        # Protocol version
        struct.pack_into('>I', payload, 0x58, self.protocol)
        # Reserved4 (8 bytes) - zeros
        # SwVersion at offset 0x70 (null-terminated string, 0x90 bytes field)
        sw_bytes = self.sw_version.encode('ascii')
        payload[0x70:0x70 + len(sw_bytes)] = sw_bytes

        # Signature at offset 0x100 (16 bytes) - will be filled by sign()
        payload[0x100:0x110] = self.signature[:16]

        return data

    def sign(self, sys_auth: bytes) -> None:
        """Sign the message with the authentication data from the OMM.

        Hash input: auth[4:] + full_serialized_message[:-16] + signature_key
        Note: The full serialized message INCLUDING the 4-byte header is used,
        only the 16-byte signature at the end is excluded.
        """
        auth_data = sys_auth[4:]  # Skip first 4 bytes of auth packet

        # Serialize without signature first (signature field is zeros)
        serialized = self.serialize()

        # MD5(auth_data + full_message_without_signature + signature_key)
        # C#: Length - 0x10 = total packet size minus 16 (signature)
        to_hash = bytearray()
        to_hash.extend(auth_data)
        # Full serialized message INCLUDING header, minus the 16-byte signature
        to_hash.extend(serialized[:len(serialized) - 16])
        to_hash.extend(self.SIGNATURE_KEY)

        md5_hash = hashlib.md5(to_hash).digest()
        self.signature = md5_hash

    def log(self) -> str:
        s = super().log()
        s += f"MAC({byte_to_hex(self.mac)}) "
        s += f"Capabilities(0x{self.capabilities:08x}) "
        return s
