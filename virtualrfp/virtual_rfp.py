"""
Virtual RFP client - connects to a Mitel OMM and simulates an RFP device.

Handles the full connection lifecycle:
1. TCP connect to OMM on port 16321
2. Receive authentication packet
3. Send SYS_INIT with capabilities and MD5 signature
4. Negotiate encryption (Blowfish CBC)
5. Process encrypted messages (heartbeat, license timer, etc.)
"""

import asyncio
import hashlib
import json
import logging
import os
import struct
import time
from pathlib import Path
from typing import Callable, Optional

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .blowfish import BlowFish, xor_block
from .hex_encoding import byte_to_hex, hex_to_byte, swap_endianness
from .messages import (
    AaMiDeMessage,
    HeartbeatMessage,
    MsgType,
    RfpCapabilities,
    RfpType,
    SysEncryptionConf,
    SysHeartbeatIntervalMessage,
    SysInitMessage,
    SysLicenseTimerMessage,
)
from .omm_conf_reader import OmmConfReader

logger = logging.getLogger(__name__)

OMM_PORT = 16321


class VirtualRfp:
    """Virtual DECT RFP client that connects to an OMM."""

    def __init__(self, mac: str, omm: str):
        self._mac = mac.upper()
        self._omm = omm
        self._rfpa: bytes = b''
        self._auth: bytes = b''
        self._rx_iv: bytes = b''
        self._tx_iv: bytes = b''
        self._decipher: Optional[BlowFish] = None
        self._encipher: Optional[BlowFish] = None
        self._reader: Optional[asyncio.StreamReader] = None
        self._writer: Optional[asyncio.StreamWriter] = None
        self._boot_timestamp = time.monotonic()
        self._heartbeat_task: Optional[asyncio.Task] = None
        self._heartbeat_interval: float = 0
        self._license_grace_period_minutes: int = 0xFFFF  # UInt16.MaxValue

        self.omm_conf_path: str = "/opt/SIP-DECT/tmp/omm_conf_8.3SP5.txt"
        self.key_store_path: str = os.path.join(os.getcwd(), ".virtualrfp_keys.json")
        self.root_password_hash: str = ""
        self.force_enroll: bool = False
        self.hw_type_override: str = ""  # Override hardware type (e.g. "RFP32", "RFPL35")
        self.debug: bool = False
        self.sw_version: str = ""  # Auto-detected from omm_conf.txt if empty
        self.on_message: Optional[Callable[[AaMiDeMessage], None]] = None

    @property
    def rfpa(self) -> str:
        """Get the RFPA key as a hex string."""
        return byte_to_hex(self._rfpa)

    @rfpa.setter
    def rfpa(self, value: str) -> None:
        """Set the RFPA key from a hex string."""
        if value:
            self._rfpa = bytes(hex_to_byte(value))
        else:
            self._rfpa = b''

    async def run_async(self) -> None:
        """Main connection loop with auto-reconnect on SYS_RESET."""
        max_retries = 5
        retry_delay = 3  # seconds

        for attempt in range(1, max_retries + 1):
            result = await self._connect_once()
            if result == 'connected':
                # Successfully connected and ran encrypted session
                return
            elif result == 'reconnect':
                # Got SYS_RESET, try again after a delay
                if attempt < max_retries:
                    logger.info(f"Reconnecting in {retry_delay}s (attempt {attempt}/{max_retries})...")
                    await asyncio.sleep(retry_delay)
                    # Reset state for new connection
                    self._rfpa = b''
                    self._auth = b''
                else:
                    logger.error(f"Failed after {max_retries} attempts")
                    return
            else:
                # Failed or cancelled
                return

    async def _connect_once(self) -> str:
        """Single connection attempt.

        Returns:
            'connected' - encryption started and message loop ran
            'reconnect' - got SYS_RESET, should reconnect
            'failed'    - unrecoverable failure
        """
        self._reader, self._writer = await asyncio.open_connection(self._omm, OMM_PORT)
        try:
            # Receive authentication packet
            self._auth = await self._read_packet()
            if not self._auth:
                return 'failed'

            # SYS_INIT handshake
            init_result = await self._init()
            if init_result == 'reconnect':
                return 'reconnect'
            if not init_result:
                return 'failed'

            # Try to load key from local store or config file
            if not self._rfpa:
                self._try_load_rfpa()

            # If we still don't have a key, wait for the OMM to send one
            if not self._rfpa:
                result = await self._wait_for_rfpa()
                if result == 'reconnect':
                    return 'reconnect'
                if not self._rfpa:
                    return 'failed'

            # Start encryption
            await self._start_encryption()

            # Run message processing
            await self._read_messages()
            return 'connected'
        finally:
            self._cancel_heartbeat()
            if self._writer:
                self._writer.close()
                try:
                    await self._writer.wait_closed()
                except Exception:
                    pass

    def send_message(self, message: AaMiDeMessage) -> None:
        """Send an encrypted message to the OMM."""
        data = message.serialize()
        if self.debug:
            logger.info(f"> {byte_to_hex(data)}")

        crypted = self._encipher.encrypt_cbc(self._tx_iv, bytes(data))
        self._tx_iv = crypted[len(crypted) - 8:]
        self._writer.write(crypted)
        # Don't await drain here to match C# synchronous Send behavior

    def _detect_sw_version(self) -> str:
        """Auto-detect the OMM software version from the config file header."""
        if self.sw_version:
            return self.sw_version
        if self.omm_conf_path and os.path.exists(self.omm_conf_path):
            try:
                with open(self.omm_conf_path, 'r', encoding='utf-8-sig') as f:
                    first_line = f.readline().strip()
                # Format: "OpenMobility Manager (FFSIP/SDC)SIP-DECT 8.1SP3-FK24"
                idx = first_line.find('SIP-DECT')
                if idx >= 0:
                    version = first_line[idx:]
                    logger.info(f"Auto-detected SW version from config: {version}")
                    return version
            except Exception as e:
                logger.warning(f"Failed to detect SW version from config: {e}")
        return "SIP-DECT 8.1SP3-FK24"

    @staticmethod
    def _parse_protocol_version(sw_version: str) -> int:
        """Parse the protocol version from a SIP-DECT version string.

        Known mappings (from rfpproxy test data and source):
          SIP-DECT 8.0     -> 0x00080000
          SIP-DECT 8.1SPx  -> 0x00080201  (SP doesn't affect protocol)
          SIP-DECT 8.3     -> 0x00080303
          SIP-DECT 9.2     -> 0x00080500
        """
        import re
        m = re.search(r'SIP-DECT\s+(\d+)\.(\d+)', sw_version)
        if not m:
            return 0x00080201  # Default for 8.1
        major = int(m.group(1))
        minor = int(m.group(2))

        # Known protocol versions from rfpproxy source
        known = {
            (8, 0): 0x00080000,
            (8, 1): 0x00080201,
            (8, 3): 0x00080303,
            (9, 2): 0x00080500,
        }
        return known.get((major, minor), (major << 16) | (minor << 8) | minor)

    async def _init(self):
        """Perform SYS_INIT handshake.

        Returns:
            True  - init succeeded (may or may not have key)
            False - unrecoverable failure
            'reconnect' - OMM sent SYS_RESET, should reconnect
        """
        logger.info(f"Auth packet ({len(self._auth)} bytes): {byte_to_hex(self._auth)}")
        caps = RfpCapabilities.INDOOR | RfpCapabilities.ENCRYPTION | RfpCapabilities.ADVANCED_FEATURE
        mac_bytes = hex_to_byte(self._mac)
        init_msg = SysInitMessage(mac=bytes(mac_bytes), capabilities=int(caps))

        # Determine hardware type
        if self.hw_type_override:
            try:
                hw = RfpType[self.hw_type_override.upper()]
                init_msg.hardware = hw
                logger.info(f"Hardware type override: {hw.name} (0x{hw:04x})")
            except KeyError:
                # Try as integer
                try:
                    hw_val = int(self.hw_type_override, 0)
                    init_msg.hardware = hw_val
                    logger.info(f"Hardware type override: 0x{hw_val:04x}")
                except ValueError:
                    logger.error(f"Unknown hardware type: {self.hw_type_override}")
                    logger.info(f"Valid types: {', '.join(t.name for t in RfpType)}")
                    return False
        detected_version = self._detect_sw_version()
        init_msg.sw_version = detected_version
        init_msg.protocol = self._parse_protocol_version(detected_version)
        logger.info(f"Using SW version: {detected_version}, protocol: 0x{init_msg.protocol:08x}")
        if self.force_enroll:
            logger.info("Force enroll: sending SYS_INIT with invalid signature")
            # Leave signature as zeros to trigger re-enrollment
        else:
            init_msg.sign(self._auth)
        logger.info(f"Sending SYS_INIT ({init_msg.length} bytes) hw={init_msg.hardware}")
        if self.debug:
            raw = init_msg.serialize()
            logger.info(f"> SYS_INIT: {byte_to_hex(raw)}")
        await self._send_packet(init_msg)

        ack = await self._read_packet()
        if not ack:
            logger.error("Connection closed after SYS_INIT (no response)")
            return False

        ptype = struct.unpack_from('>H', ack, 0)[0]
        plen = len(ack)
        logger.info(f"Init response: 0x{ptype:04x} ({plen} bytes) {byte_to_hex(ack[:min(32, plen)])}...")

        # Check for immediate rejection
        if ptype == 0x0002:
            logger.error("Received NACK - OMM rejected SYS_INIT")
            return False
        if ptype == 0x0121:
            logger.info("Received SYS_RESET as init response - will reconnect")
            return 'reconnect'

        if ack[0] == 0x01:
            if ack[1] == 0x24:
                # SYS_RFP_AUTH_KEY - received new RFPA
                self._rfpa = bytes(ack[4:])
                logger.info(f"new RFPA: {byte_to_hex(self._rfpa)}")
                self._save_rfpa_to_store()
            elif ack[1] == 0x25:
                # SYS_RFP_RE_ENROLEMENT
                logger.info("Received SYS_RFP_RE_ENROLEMENT")
                self._rfpa = self._handle_re_enrollment(ack)
                if not self._rfpa:
                    return False
                self._save_rfpa_to_store()
            elif ptype == 0x010c:
                # SYS_OMM_CONTROL - OMM expects encryption immediately
                logger.info("Received SYS_OMM_CONTROL - OMM expects encryption (RFP already enrolled)")
                return True
            else:
                logger.warning(f"Unexpected init packet 0x{ptype:04x}")
                return True

            # After auth key or re-enrollment, read the actual ACK
            ack = await self._read_packet()
            if not ack:
                logger.warning("Connection closed after receiving auth key (no ACK)")
                # We still got the key, so continue
                return True
            ptype2 = struct.unpack_from('>H', ack, 0)[0]
            logger.info(f"Post-key packet: 0x{ptype2:04x} ({len(ack)} bytes)")

        return True

    def _load_root_password_hash(self) -> Optional[str]:
        """Load the OMM root password hash from omm_conf.txt UA section."""
        if not self.omm_conf_path or not os.path.exists(self.omm_conf_path):
            return None
        try:
            reader = OmmConfReader(self.omm_conf_path)
            user = reader.get_value("UA", "user", "root")
            if user is not None:
                pw = user.get("password")
                if pw:
                    logger.info(f"Loaded root password hash from config: {pw}")
                    return pw
        except Exception as e:
            logger.warning(f"Failed to read root password from config: {e}")
        return None

    def _handle_re_enrollment(self, packet: bytes) -> bytes:
        """Handle SYS_RFP_RE_ENROLEMENT (0x0125).

        The OMM sends the RFPA encrypted with AES-256-ECB using a key derived
        from auth_data[4:] (32 bytes) with the root password hash overlaid.
        A SHA-256 checksum of (auth_data[4:] + pw_hash + crypted) is appended.
        """
        if not self.root_password_hash:
            # Try to auto-read from omm_conf.txt
            pw_hash = self._load_root_password_hash()
            if pw_hash:
                self.root_password_hash = pw_hash
            else:
                logger.error(
                    "SYS_RFP_RE_ENROLEMENT requires the OMM root password hash.\n"
                    "Use --root-pw-hash to provide it (e.g. '$1$$juPq1oleiGg7WHdZ5itlC/').\n"
                    "Alternatively, delete the RFP from the OMM and reconnect for fresh enrollment."
                )
                return b''

        crypted = bytes(packet[4:0x44])       # 64 bytes encrypted RFPA
        checksum = bytes(packet[0x44:0x64])    # 32 bytes SHA-256

        auth_data = self._auth[4:]             # skip first 4 bytes of auth packet
        pw_bytes = self.root_password_hash.encode('ascii')

        # Verify SHA-256 checksum: hash(auth_data[4:] + pw_bytes + crypted)
        sha_input = bytearray()
        sha_input.extend(auth_data[:0x20])
        sha_input.extend(pw_bytes[:0x1a])
        sha_input.extend(crypted)
        expected_hash = hashlib.sha256(sha_input).digest()

        if checksum != expected_hash:
            logger.error("Re-enrollment checksum mismatch - wrong root password hash?")
            return b''

        # Decrypt: AES key = auth_data[4:36] with pw_bytes overlaid at start
        aes_key = bytearray(auth_data[:0x20])
        aes_key[:len(pw_bytes)] = pw_bytes[:0x20]

        cipher = Cipher(algorithms.AES(bytes(aes_key)), modes.ECB())
        dec = cipher.decryptor()
        rfpa = dec.update(crypted) + dec.finalize()

        logger.info(f"Re-enrollment successful, RFPA: {byte_to_hex(rfpa)}")
        return rfpa

    def _try_load_rfpa(self) -> bool:
        """Try to load the RFPA key from local store or config file.

        Returns True if key was found.
        """
        if self._rfpa:
            return True

        logger.info("No RFPA from init, trying local key store...")
        self._rfpa = self._load_rfpa_from_store() or b''
        if self._rfpa:
            return True

        logger.info("No RFPA in key store, trying config file...")
        if self.omm_conf_path and os.path.exists(self.omm_conf_path):
            crypted = self._load_rfpa()
            if crypted:
                logger.info(f"Loaded encrypted RFPA from config: {crypted[:32]}...")
                self._rfpa = bytes(self._decrypt_rfpa_internal(crypted))
                return True
            else:
                logger.info("No RFPA entry found in config for this MAC")
        else:
            logger.info(f"Config file not found: {self.omm_conf_path}")

        return False

    async def _wait_for_rfpa(self):
        """Wait for the OMM to send a SYS_RFP_AUTH_KEY (0x0124) or
        SYS_RFP_RE_ENROLEMENT (0x0125) packet.

        Keeps the connection open and reads unencrypted packets until
        the key arrives, a SYS_RESET triggers reconnect, or the connection closes.

        Returns:
            'reconnect' if SYS_RESET received (caller should reconnect)
            Sets self._rfpa and returns None on success
            Returns None with empty _rfpa on failure
        """
        logger.info("")
        logger.info("=" * 60)
        logger.info("No RFPA key available. Keeping connection open.")
        logger.info("Waiting for OMM to send key (0x0124 or 0x0125)...")
        logger.info("Trigger re-enrollment from the OMM management interface.")
        logger.info("=" * 60)
        logger.info("")

        try:
            while True:
                try:
                    packet = await self._read_packet()
                except asyncio.IncompleteReadError:
                    logger.info("Connection closed by OMM while waiting for key")
                    return None

                if not packet:
                    logger.info("Connection closed by OMM while waiting for key")
                    return None

                ptype = struct.unpack_from('>H', packet, 0)[0]
                logger.info(f"Received packet 0x{ptype:04x} ({len(packet)} bytes): {byte_to_hex(packet[:min(32, len(packet))])}...")

                if packet[0] == 0x01 and packet[1] == 0x24:
                    # SYS_RFP_AUTH_KEY - received new RFPA
                    self._rfpa = bytes(packet[4:])
                    logger.info(f"Received SYS_RFP_AUTH_KEY! RFPA: {byte_to_hex(self._rfpa)}")
                    self._save_rfpa_to_store()
                    return None

                elif packet[0] == 0x01 and packet[1] == 0x25:
                    # SYS_RFP_RE_ENROLEMENT
                    logger.info("Received SYS_RFP_RE_ENROLEMENT")
                    self._rfpa = self._handle_re_enrollment(packet)
                    if self._rfpa:
                        self._save_rfpa_to_store()
                        return None
                    else:
                        logger.error("Re-enrollment failed, continuing to wait...")

                elif ptype == 0x010c:
                    logger.info("Received SYS_OMM_CONTROL - OMM expects encryption to start")

                elif ptype == 0x0121:
                    logger.info("Received SYS_RESET - will reconnect after reset")
                    return 'reconnect'

                else:
                    logger.info(f"Ignoring packet 0x{ptype:04x}, still waiting for key...")

        except asyncio.CancelledError:
            logger.info("Cancelled while waiting for key")
            return None

    async def _start_encryption(self) -> None:
        """Initialize Blowfish encryption and send encryption confirmation."""
        # Set up ciphers with different key slices
        self._decipher = BlowFish(self._rfpa[0:56])
        self._encipher = BlowFish(self._rfpa[8:64])

        # Derive IVs from hardcoded constants XORed with auth data
        tx_iv = bytearray(hex_to_byte("68e8364be9c234c1"))
        xor_block(tx_iv, self._auth[11:19])
        self._tx_iv = bytes(tx_iv)

        rx_iv = bytearray(hex_to_byte("dfe66571fac45a42"))
        xor_block(rx_iv, self._auth[27:35])
        self._rx_iv = bytes(rx_iv)

        # Send encryption confirmation (this is the first encrypted message)
        self.send_message(SysEncryptionConf())

    def _save_rfpa_to_store(self) -> None:
        """Save the current RFPA key to the local key store file."""
        store = {}
        if os.path.exists(self.key_store_path):
            try:
                with open(self.key_store_path, 'r') as f:
                    store = json.load(f)
            except Exception:
                pass
        store[self._mac] = byte_to_hex(self._rfpa)
        try:
            with open(self.key_store_path, 'w') as f:
                json.dump(store, f, indent=2)
            logger.info(f"Saved RFPA to {self.key_store_path}")
        except Exception as e:
            logger.warning(f"Failed to save RFPA to key store: {e}")

    def _load_rfpa_from_store(self) -> Optional[bytes]:
        """Load RFPA key from the local key store file."""
        if not os.path.exists(self.key_store_path):
            return None
        try:
            with open(self.key_store_path, 'r') as f:
                store = json.load(f)
            hex_key = store.get(self._mac)
            if hex_key:
                logger.info(f"Loaded RFPA from key store for {self._mac}")
                return bytes(hex_to_byte(hex_key))
        except Exception as e:
            logger.warning(f"Failed to load from key store: {e}")
        return None

    def _load_rfpa(self) -> Optional[str]:
        """Load RFPA from OMM configuration file."""
        try:
            reader = OmmConfReader(self.omm_conf_path)
            rfp = reader.get_value("RFP", "mac", self._mac)
            if rfp is not None:
                rfp_id = rfp["id"]
                rfpa = reader.get_value("RFPA", "id", rfp_id)
                if rfpa is not None:
                    return rfpa[1]
        except Exception as e:
            logger.warning(f"Failed to load RFPA from config: {e}")
        return None

    def _decrypt_rfpa_internal(self, rfpa_hex: str) -> bytes:
        """Decrypt RFPA using MAC as key (instance method)."""
        return VirtualRfp.decrypt_rfpa(rfpa_hex, self._mac)

    @staticmethod
    def decrypt_rfpa(rfpa_hex: str, mac: str) -> bytes:
        """Decrypt RFPA using MAC address as Blowfish ECB key."""
        data = bytearray(hex_to_byte(rfpa_hex))
        swap_endianness(data)
        key = (mac + '\0').lower().encode('ascii')
        bf = BlowFish(key)
        plain = bytearray(bf.decrypt_ecb(bytes(data)))
        swap_endianness(plain)
        return bytes(plain)

    async def _read_packet(self) -> bytes:
        """Read a single unencrypted packet from the socket."""
        try:
            header = await self._reader.readexactly(4)
        except asyncio.IncompleteReadError:
            return b''
        if not header:
            return b''
        length = struct.unpack_from('>H', header, 2)[0]
        try:
            payload = await self._reader.readexactly(length)
        except asyncio.IncompleteReadError:
            return b''
        return header + payload

    async def _send_packet(self, packet: AaMiDeMessage) -> None:
        """Send an unencrypted packet."""
        data = packet.serialize()
        self._writer.write(bytes(data))
        await self._writer.drain()

    async def _read_messages(self) -> None:
        """Main encrypted message processing loop."""
        buffer = bytearray()
        try:
            while True:
                # Read data from socket
                chunk = await self._reader.read(4096)
                if not chunk:
                    break
                buffer.extend(chunk)

                # Process complete messages
                while len(buffer) >= 8:
                    # Decrypt first 8-byte block to read header
                    block = bytes(buffer[:8])
                    plain = self._decipher.decrypt_cbc(self._rx_iv, block)
                    length = struct.unpack_from('>H', plain, 2)[0]

                    if length > 4:
                        # Multi-block message
                        crypted_length = (length + 4 + 7) & ~7  # Round up to 8-byte boundary
                        if len(buffer) < crypted_length:
                            break  # Need more data
                        block = bytes(buffer[:crypted_length])
                        plain = self._decipher.decrypt_cbc(self._rx_iv, block)
                    else:
                        if len(buffer) < 8:
                            break
                        block = bytes(buffer[:8])
                        # plain already computed above

                    # Update RX IV from last 8 bytes of ciphertext
                    self._rx_iv = block[len(block) - 8:]

                    # Process the decrypted message
                    msg_data = plain[:length + 4]
                    self._on_message(msg_data)

                    # Consume processed bytes
                    buffer = buffer[len(block):]
        except asyncio.CancelledError:
            logger.info("Message processing cancelled")
        except asyncio.IncompleteReadError:
            logger.info("Connection closed")
        except Exception as e:
            logger.error(f"Error in message processing: {e}")

    def _on_message(self, data: bytes) -> None:
        """Dispatch a received message."""
        if self.debug:
            logger.info(f"< {byte_to_hex(data)}")

        try:
            message = AaMiDeMessage.create(data)
        except Exception as e:
            logger.warning(f"Failed to parse message: {e}")
            return

        # Handle specific message types
        if message.type == MsgType.SYS_HEARTBEAT_INTERVAL:
            self._on_heartbeat_interval(message)
        elif message.type == MsgType.SYS_LICENSE_TIMER:
            self._on_license_timer(message)

        # Fire callback
        if self.on_message:
            self.on_message(message)

    # --- Heartbeat ---

    def _send_heartbeat(self) -> None:
        """Send a heartbeat message with current uptime."""
        uptime = time.monotonic() - self._boot_timestamp
        heartbeat = HeartbeatMessage.from_seconds(uptime)
        try:
            self.send_message(heartbeat)
        except Exception as e:
            logger.error(f"Failed to send heartbeat: {e}")

    def _on_heartbeat_interval(self, message: SysHeartbeatIntervalMessage) -> None:
        """Handle heartbeat interval configuration from OMM."""
        self._heartbeat_interval = message.interval_seconds
        self._cancel_heartbeat()
        if self._heartbeat_interval > 0:
            self._heartbeat_task = asyncio.ensure_future(
                self._heartbeat_loop(self._heartbeat_interval)
            )

    async def _heartbeat_loop(self, interval: float) -> None:
        """Periodically send heartbeat messages."""
        try:
            while True:
                await asyncio.sleep(interval)
                self._send_heartbeat()
        except asyncio.CancelledError:
            pass

    def _cancel_heartbeat(self) -> None:
        """Cancel the heartbeat timer task."""
        if self._heartbeat_task and not self._heartbeat_task.done():
            self._heartbeat_task.cancel()
            self._heartbeat_task = None

    # --- License Timer ---

    def _on_license_timer(self, message: SysLicenseTimerMessage) -> None:
        """Handle license timer messages from OMM."""
        if message.grace_period_minutes > 0x7FFFFFFF:
            # Query - respond with stored grace period
            response = SysLicenseTimerMessage(
                grace_period_minutes=self._license_grace_period_minutes,
                md5=message.md5,
            )
            self.send_message(response)
        else:
            # Update stored grace period
            self._license_grace_period_minutes = message.grace_period_minutes
