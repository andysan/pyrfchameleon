#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: Copyright 2024 Andreas Sandberg <andreas@sandberg.uk>
#
# SPDX-License-Identifier: Apache-2.0
#

import errno
import importlib
import importlib.metadata
import importlib.util
import logging
import pathlib
import sys
import types
from dataclasses import dataclass
from functools import wraps
from typing import (
    Callable,
    List,
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
from rfchameleon.packets import (
    AutoPacketPrinter,
    PacketDBDump,
    PacketHandler,
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

packet_handler_names: List[str] = []


@dataclass
class RadioContext:
    plugins: List[types.ModuleType]
    transport: Optional[RadioTransport] = None
    radio: Optional[Radio] = None
    usb_dev: Optional[usb.core.Device] = None
    db: Optional[PacketDatabase] = None


def with_radio(func: Callable[Concatenate[Radio, P], R]) -> Callable[P, R]:
    @wraps(func)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
        ctx = click.get_current_context()
        radio = ctx.ensure_object(RadioContext).radio
        if radio is None:
            ctx.fail("Failed to find RF Chameleon.")

        return func(radio, *args, **kwargs)

    return wrapper


def with_database(func: Callable[Concatenate[PacketDatabase, P], R]) -> Callable[P, R]:
    @wraps(func)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
        ctx = click.get_current_context()
        db = ctx.ensure_object(RadioContext).db
        if db is None:
            ctx.fail("No database specified")

        return func(db, *args, **kwargs)

    return wrapper


@click.group()
@click.pass_context
@click.option("--debug", is_flag=True)
@click.option(
    "--no-plugins",
    is_flag=True,
    help="Disable plugins",
)
@click.option(
    "--module",
    "-m",
    multiple=True,
    type=str,
    help="Additional module to load",
)
@click.option(
    "--plugin",
    "-p",
    multiple=True,
    type=click.Path(
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
        path_type=pathlib.Path,
    ),
    help="Additional module to load",
)
def cli(
    ctx: click.Context,
    debug: bool,
    module: List[str],
    plugin: List[pathlib.Path],
    no_plugins: bool,
) -> None:
    if debug:
        logging.basicConfig(level=logging.DEBUG)

    obj = RadioContext(plugins=[])
    ctx.obj = obj

    if not no_plugins:
        for ep in importlib.metadata.entry_points(group="rfchameleon.plugins.cli"):
            logger.debug("Loading plugin '%s' as '%s'", ep.value, ep.name)
            obj.plugins.append(ep.load())

    for name in module:
        logger.debug("Loading plugin module '%s'", name)
        try:
            mod = importlib.import_module(name)
        except ImportError:
            ctx.fail(f"Failed to import {name}")

        obj.plugins.append(mod)

    for path in plugin:
        module_name = f"rfchameleon.plugins.{path.stem}"
        logger.debug("Loading plugin '%s' as %s", path, module_name)

        spec = importlib.util.spec_from_file_location(module_name, path)
        assert spec is not None
        assert spec.loader is not None
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        sys.modules[module_name] = mod
        obj.plugins.append(mod)

    # Create the list of valid packet handlers after plugins have been
    # loaded.
    packet_handler_names.extend(PacketHandler.simple_packet_handlers.keys())

    try:
        transport = ctx.with_resource(UsbTransport.open())
        obj.transport = transport
        obj.usb_dev = transport.usb_dev
        obj.radio = Radio(transport)
    except NoDeviceError:
        pass


@cli.group()
@click.pass_context
@click.option(
    "--database",
    "-d",
    type=click.Path(dir_okay=False, writable=True, path_type=pathlib.Path),
    required=True,
)
def db(ctx: click.Context, database: Optional[pathlib.Path]) -> None:
    """Database operations."""

    obj = ctx.ensure_object(RadioContext)
    if database is not None:
        obj.db = ctx.with_resource(PacketDatabase.open(database))


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


@db.command()
@with_database
@click.pass_context
@click.option(
    "--packet-handler",
    "-p",
    type=click.Choice(packet_handler_names),
    multiple=True,
    default=[],
)
def dump_packets(
    ctx: click.Context,
    database: PacketDatabase,
    packet_handler: List[str] = [],
) -> None:
    """Print the packets in the database"""

    handlers = [PacketHandler.simple_packet_handlers[n]() for n in packet_handler]
    if not handlers:
        handlers.append(AutoPacketPrinter())

    with database.transaction():
        for _, packet in database.raw_packets():
            for handler in handlers:
                handler.raw_packet(packet)


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
    handlers: Sequence[PacketHandler],
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
                handler.raw_packet(packet)


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
@click.option(
    "--packet-handler",
    "-p",
    type=click.Choice(packet_handler_names),
    multiple=True,
    default=[],
)
def rx(
    ctx: click.Context,
    radio: Radio,
    preset: int,
    database: Optional[pathlib.Path],
    packet_handler: List[str] = [],
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

    handlers = [PacketHandler.simple_packet_handlers[n]() for n in packet_handler]
    if not handlers:
        handlers.append(AutoPacketPrinter())

    if database is not None:
        db = ctx.with_resource(PacketDatabase.open(database))
        with db.transaction():
            db.create_or_upgrade_tables()
            db.update_protocols(radio.radio_preset_descs)

        handlers.append(PacketDBDump(db))

    _rx(ctx, radio, preset_desc, handlers)


if __name__ == "__main__":
    cli()
