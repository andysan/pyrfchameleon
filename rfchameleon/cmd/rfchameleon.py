#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: Copyright 2024 Andreas Sandberg <andreas@sandberg.uk>
#
# SPDX-License-Identifier: Apache-2.0
#

import errno
import logging
import pathlib
from dataclasses import dataclass
from datetime import datetime
from functools import wraps
from typing import (
    Callable,
    Optional,
    Sequence,
    TypeVar,
)

import click
import usb.core  # type: ignore
from typing_extensions import (
    Concatenate,
    ParamSpec,
)

from rfchameleon import (
    CommandError,
    NoDeviceError,
    RadioErrno,
    TransportTimeoutError,
)
from rfchameleon.db import (
    PacketDatabase,
    RawPacket,
)
from rfchameleon.radio import (
    Radio,
    RadioPreset,
)
from rfchameleon.transport import (
    BootloaderType,
    RadioPresetDesc,
    RadioTransport,
    RxInfo,
)
from rfchameleon.usb import (
    RFCH_PID,
    RFCH_VID,
    UsbTransport,
)

P = ParamSpec("P")
R = TypeVar("R")

logger = logging.getLogger(__name__)


@dataclass
class RadioContext:
    transport: Optional[RadioTransport] = None
    radio: Optional[Radio] = None
    usb_dev: Optional[usb.core.Device] = None


def with_radio(func: Callable[Concatenate[Radio, P], R]) -> Callable[P, R]:
    @wraps(func)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
        ctx = click.get_current_context()
        radio = ctx.ensure_object(RadioContext).radio
        if radio is None:
            ctx.fail("Failed to find RF Chameleon.")

        return func(radio, *args, **kwargs)

    return wrapper


def packet_handler_print(packet: RawPacket) -> None:
    rx_info = packet.rx_info
    meta = []

    if rx_info.crc_ok is not None:
        meta.append("CRC_OK" if rx_info.crc_ok else "CRC_ERROR")

    if rx_info.rssi is not None:
        meta.append(f"RSSI: {rx_info.rssi:.1f}")

    if rx_info.channel is not None:
        meta.append(f"CHANNEL: {rx_info.rssi:.1f}")

    ts = datetime.fromtimestamp(packet.ts).isoformat()
    print(ts, packet.payload.hex(), ", ".join(meta))


@click.group()
@click.pass_context
@click.option("--debug", is_flag=True)
def cli(
    ctx: click.Context,
    debug: bool,
) -> None:
    if debug:
        logging.basicConfig(level=logging.DEBUG)

    obj = RadioContext()
    ctx.obj = obj

    try:
        transport = ctx.with_resource(UsbTransport.open())
        obj.transport = transport
        obj.usb_dev = transport.usb_dev
        obj.radio = Radio(transport)
    except NoDeviceError:
        pass


@cli.command()
@with_radio
@click.pass_context
def info(ctx: click.Context, radio: Radio) -> None:
    """Print device information."""

    obj = ctx.ensure_object(RadioContext)

    usb_dev = obj.usb_dev
    assert usb_dev is not None

    print("USB information:")
    print(f"\tManufacturer: {usb_dev.manufacturer}")
    print(f"\tProduct: {usb_dev.product}")
    print(f"\tSerial number: {usb_dev.serial_number}")
    print()

    prot = radio.protocol_info
    print("Protocol:")
    print(f"\tUUID: {prot.uuid}")
    print(f"\tVersion: {prot.version}")
    print(f"\tMaximum payload size: {prot.max_payload}")
    print()

    print("Firmware:")
    print(f"\tVersion: {radio.firmware_info.version}")
    print()

    print("Bootloaders:")
    for bl in radio.bootloader_info:
        try:
            print(f"\t{BootloaderType(bl.type).name} (0x{bl.type:02x}):")
        except ValueError:
            print(f"\tUnknown (0x{bl.type:02x}):")

        print(f"\t\tFlags: {bl.flags}")
        print(f"\t\tVersion: {bl.version}")
    print()

    board = radio.board_info
    print("Board:")
    print(f"\tCompatible: {board.compatible}")
    print(f"\tVariant: 0x{board.variant}")
    print(f"\tRevision: {board.revision}")
    print()

    print("Radio configurations:")
    for idx, preset in enumerate(radio.radio_preset_descs):
        try:
            known_preset = RadioPreset(preset.uuid)
            print(f"\t{idx}: {preset.uuid}: {known_preset.long_name}")
        except ValueError:
            print(f"\t{idx}: {preset.uuid}")


bootloader_types = {
    "reboot": BootloaderType.REBOOT,
    "rom": BootloaderType.ROM,
    "mcuboot": BootloaderType.MCUBOOT,
}


@cli.command()
@with_radio
@click.pass_context
@click.option(
    "--type", "-t", type=click.Choice(list(bootloader_types.keys())), default="reboot"
)
def reboot(ctx: click.Context, radio: Radio, type: str) -> None:
    """Reboot the device. The type parameter can be used to enter the
    built-in bootloader on supported devices.

    """

    bl = bootloader_types[type]
    radio.reboot(bl)


@cli.group()
def test() -> None:
    """General firmware and hardware test functionality."""

    pass


@test.command()
@with_radio
@click.pass_context
def ping(ctx: click.Context, radio: Radio) -> None:
    """Transport layer ping test. This test sends a series of ping
    requests with different payload sizes. This test is designed to
    exercise various fragmentation scenarios and payload overflows.

    """

    def ping_data(length: int) -> bytes:
        return bytes((i % 0xFF for i in range(length)))

    max_payload = radio.protocol_info.max_payload

    print("Testing ping...")

    print("No payload")
    radio.ping(b"")

    print(f"{max_payload} bytes (maximum) of payload...")
    radio.ping(ping_data(max_payload))

    try:
        print(f"{max_payload + 1} bytes (maximum + 1) of payload...")
        radio.ping(ping_data(max_payload + 1))
        assert False, "Firmware didn't detect overflow"
    except CommandError as e:
        assert e.error == RadioErrno.ENOMEM, "Unexpected error code"

    try:
        print(f"{2 * max_payload} bytes (2 * maximum) of payload...")
        radio.ping(ping_data(2 * max_payload))
        assert False, "Firmware didn't detect overflow"
    except CommandError as e:
        assert e.error == RadioErrno.ENOMEM, "Unexpected error code"


@test.command()
@with_radio
@click.pass_context
def loopback(ctx: click.Context, radio: Radio) -> None:
    """Test radio RX/TX using a special loopback protocol preset. This
    currently requires a firmware compiled with a special test radio
    backend.

    """

    try:
        radio.set_active_preset(RadioPreset.TEST_LOOPBACK)
    except KeyError:
        ctx.fail("Device not running test firmware")

    radio.send(b"Test")
    with radio.rx_enabled():
        print(radio.recv())


def _rx(
    ctx: click.Context,
    radio: Radio,
    preset_desc: RadioPresetDesc,
    handlers: Sequence[Callable[[RawPacket], None]],
) -> None:

    radio.set_active_preset(preset_desc.uuid)

    with radio.rx_enabled():
        while True:
            try:
                rx_info, payload = radio.recv()
                packet = RawPacket.from_packet(preset_desc, rx_info, payload)
            except TransportTimeoutError:
                continue

            for handler in handlers:
                handler(packet)


@cli.command()
@with_radio
@click.pass_context
@click.option("--preset", "-p", type=int, default=0)
@click.option(
    "--database",
    "-d",
    type=click.Path(dir_okay=False, writable=True, path_type=pathlib.Path),
    default=None,
)
def rx(
    ctx: click.Context, radio: Radio, preset: int, database: Optional[pathlib.Path]
) -> None:
    """Receive packets. The default behavior is to print packets on
    the console.

    Received packets can, optionally, be stored in an sqlite3
    database. Databases are automatically created if they don't
    exist. Packets are appended to existing databases.

    """

    try:
        preset_desc = radio.radio_preset_descs[preset]
    except IndexError:
        ctx.fail("Invalid preset")

    handlers = [
        packet_handler_print,
    ]

    if database is not None:
        db = ctx.with_resource(PacketDatabase.open(database))

        def db_handler(packet: RawPacket) -> None:
            with db.transaction():
                db.add_packet(packet)

        with db.transaction():
            db.create_or_upgrade_tables()
            db.update_protocols(radio.radio_preset_descs)

        handlers.append(db_handler)

    _rx(ctx, radio, preset_desc, handlers)


if __name__ == "__main__":
    cli()
