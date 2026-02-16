"""
Virtual RFP - CLI entry point.

Usage:
    python -m virtualrfp -o <OMM_IP> [-m <MAC>] [-k <RFPA_KEY>] [-c <CONFIG>] [-d]

Arguments:
    -m, --mac       RFP MAC address (optional - reads license RFPs from omm_conf.txt if omitted)
    -o, --omm       OMM IP address (required)
    -k, --key       RFPA (blowfish key) in hex (optional)
    -c, --config    omm_conf.txt path (default: ../omm_conf.txt)
    -d, --debug     Dump raw packets in hex
    -h, --help      Show this help message
"""

import argparse
import asyncio
import logging
import signal
import sys
from datetime import datetime

from .hex_encoding import byte_to_hex
from .messages import AaMiDeMessage, MsgType
from .omm_conf_reader import OmmConfReader
from .virtual_rfp import VirtualRfp

logging.basicConfig(
    level=logging.INFO,
    format='%(message)s',
)
logger = logging.getLogger(__name__)


QUIET_MSG_TYPES = {MsgType.HEARTBEAT, MsgType.SYS_LED}


def make_on_message(label: str, debug: bool = False):
    """Create a message callback that prefixes output with a label."""
    def on_message(message: AaMiDeMessage) -> None:
        if not debug and message.type in QUIET_MSG_TYPES:
            return
        timestamp = datetime.now().isoformat()
        print(f"{timestamp} [{label}] {message.log()}")
    return on_message


def load_license_macs(config_path: str) -> list[str]:
    """Read license RFP MAC addresses from the LIC section of omm_conf.txt."""
    try:
        reader = OmmConfReader(config_path)
        lic_entries = reader.get_section("LIC")
        if not lic_entries:
            return []
        entry = lic_entries[0]
        macs = []
        # LIC row has fields: park, rfp1, rfp2, rfp3, system, messaging, ...
        for field in ("rfp1", "rfp2", "rfp3"):
            mac = entry.get(field)
            if mac and mac.strip():
                macs.append(mac.strip().upper())
        return macs
    except Exception as e:
        logger.error(f"Failed to read license MACs from config: {e}")
        return []


def create_client(mac: str, args) -> VirtualRfp:
    """Create and configure a VirtualRfp client for a given MAC."""
    client = VirtualRfp(mac, args.omm)
    client.omm_conf_path = args.config
    client.debug = args.debug
    client.force_enroll = args.force_enroll
    if args.hw_type:
        client.hw_type_override = args.hw_type
    if args.root_pw_hash:
        client.root_password_hash = args.root_pw_hash
    if args.sw_version:
        client.sw_version = args.sw_version
    if args.key:
        decrypted = VirtualRfp.decrypt_rfpa(args.key, mac)
        client.rfpa = byte_to_hex(decrypted)
    return client


def main() -> None:
    parser = argparse.ArgumentParser(
        prog='virtualrfp',
        description='Virtual DECT RFP simulator for Mitel OMM',
    )
    parser.add_argument(
        '-m', '--mac', default=None,
        help='RFP MAC address (if omitted, reads license RFP MACs from omm_conf.txt)',
    )
    parser.add_argument('-o', '--omm', required=True, help='OMM IP address')
    parser.add_argument('-k', '--key', default=None, help='RFPA (blowfish key) in hex')
    parser.add_argument(
        '-c', '--config',
        default='../omm_conf.txt',
        help='omm_conf.txt path',
    )
    parser.add_argument('-d', '--debug', action='store_true', help='Dump raw packets')
    parser.add_argument(
        '--force-enroll', action='store_true',
        help='Send invalid signature to force re-enrollment',
    )
    parser.add_argument(
        '--root-pw-hash', default=None,
        help='OMM root password hash for re-enrollment (e.g. "$1$$juPq1oleiGg7WHdZ5itlC/")',
    )
    parser.add_argument(
        '--sw-version', default=None,
        help='Software version string (auto-detected from omm_conf.txt if not set)',
    )
    parser.add_argument(
        '--hw-type', default=None,
        help='Hardware type to report (e.g. RFP35, RFP32, RFPL35, PC). Default: RFP35',
    )

    args = parser.parse_args()

    # Determine MAC(s) to connect
    if args.mac:
        macs = [args.mac.upper()]
    else:
        # Auto-read license RFP MACs from omm_conf.txt
        macs = load_license_macs(args.config)
        if not macs:
            logger.error(
                "No MAC specified and no license RFP MACs found in config.\n"
                "Use -m to specify a MAC, or -c to point to a valid omm_conf.txt."
            )
            sys.exit(1)
        logger.info(f"Read {len(macs)} license RFP MAC(s) from config: {', '.join(macs)}")

    # Create clients
    clients = []
    for mac in macs:
        client = create_client(mac, args)
        short_mac = mac[-4:]
        client.on_message = make_on_message(short_mac, debug=args.debug)
        clients.append((mac, client))

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    # Handle Ctrl+C gracefully
    tasks = []

    def signal_handler():
        for task in tasks:
            if not task.done():
                task.cancel()

    if sys.platform != 'win32':
        loop.add_signal_handler(signal.SIGINT, signal_handler)
        loop.add_signal_handler(signal.SIGTERM, signal_handler)

    try:
        for mac, client in clients:
            logger.info(f"Starting virtual RFP: {mac}")
            task = loop.create_task(client.run_async())
            tasks.append(task)

        # Wait for all tasks to complete
        loop.run_until_complete(asyncio.gather(*tasks, return_exceptions=True))
    except asyncio.CancelledError:
        pass
    except KeyboardInterrupt:
        pass
    except ConnectionRefusedError:
        logger.error(f"Connection refused to {args.omm}:{16321}")
        sys.exit(1)
    except OSError as e:
        logger.error(f"Socket error: {e}")
        sys.exit(1)
    finally:
        loop.close()


if __name__ == '__main__':
    main()
