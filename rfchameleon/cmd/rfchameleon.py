#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: Copyright 2024 Andreas Sandberg <andreas@sandberg.uk>
#
# SPDX-License-Identifier: Apache-2.0
#

import errno
import logging
from dataclasses import dataclass
from typing import Optional

import click
import usb.core  # type: ignore

from rfchameleon import (
    CommandError,
    NoDeviceError,
    RadioErrno,
)
from rfchameleon.radio import (
    Radio,
    RadioPreset,
)
from rfchameleon.transport import (
    BootloaderType,
    RadioTransport,
)
from rfchameleon.usb import (
    RFCH_PID,
    RFCH_VID,
    UsbTransport,
)

logger = logging.getLogger(__name__)


@dataclass
class RadioContext:
    transport: RadioTransport
    radio: Radio
    usb_dev: usb.core.Device


@click.group()
@click.pass_context
@click.option("--debug", is_flag=True)
def cli(
    ctx: click.Context,
    debug: bool,
) -> None:
    if debug:
        logging.basicConfig(level=logging.DEBUG)

    try:
        transport = ctx.with_resource(UsbTransport.open())
    except NoDeviceError:
        ctx.fail("Failed to find RF Chameleon.")

    radio = Radio(transport)

    ctx.obj = RadioContext(
        usb_dev=transport.usb_dev,
        transport=transport,
        radio=radio,
    )


@cli.command()
@click.pass_context
def info(ctx: click.Context) -> None:
    """Print device information."""

    obj = ctx.ensure_object(RadioContext)

    usb_dev = obj.usb_dev

    print("USB information:")
    print(f"\tManufacturer: {usb_dev.manufacturer}")
    print(f"\tProduct: {usb_dev.product}")
    print(f"\tSerial number: {usb_dev.serial_number}")
    print()

    prot = obj.radio.protocol_info
    print("Protocol:")
    print(f"\tUUID: {prot.uuid}")
    print(f"\tVersion: {prot.version}")
    print(f"\tMaximum payload size: {prot.max_payload}")
    print()

    print("Firmware:")
    print(f"\tVersion: {obj.radio.firmware_info.version}")
    print()

    print("Bootloaders:")
    for bl in obj.radio.bootloader_info:
        try:
            print(f"\t{BootloaderType(bl.type).name} (0x{bl.type:02x}):")
        except ValueError:
            print(f"\tUnknown (0x{bl.type:02x}):")

        print(f"\t\tFlags: {bl.flags}")
        print(f"\t\tVersion: {bl.version}")
    print()

    board = obj.radio.board_info
    print("Board:")
    print(f"\tCompatible: {board.compatible}")
    print(f"\tVariant: 0x{board.variant}")
    print(f"\tRevision: {board.revision}")
    print()

    print("Radio configurations:")
    for preset in obj.radio.radio_preset_descs:
        try:
            known_preset = RadioPreset(preset.uuid)
            print(f"\t{preset.uuid}: {known_preset.long_name}")
        except ValueError:
            print(f"\t{preset.uuid}")


bootloader_types = {
    "reboot": BootloaderType.REBOOT,
    "rom": BootloaderType.ROM,
    "mcuboot": BootloaderType.MCUBOOT,
}


@cli.command()
@click.pass_context
@click.option(
    "--type", "-t", type=click.Choice(list(bootloader_types.keys())), default="reboot"
)
def reboot(ctx: click.Context, type: str) -> None:
    """Reboot the device. The type parameter can be used to enter the
    built-in bootloader on supported devices.

    """

    obj = ctx.ensure_object(RadioContext)

    bl = bootloader_types[type]
    obj.radio.reboot(bl)


@cli.group()
def test() -> None:
    """General firmware and hardware test functionality."""

    pass


@test.command()
@click.pass_context
def ping(ctx: click.Context) -> None:
    """Transport layer ping test. This test sends a series of ping
    requests with different payload sizes. This test is designed to
    exercise various fragmentation scenarios and payload overflows.

    """

    obj = ctx.ensure_object(RadioContext)
    radio = obj.radio

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
@click.pass_context
def loopback(ctx: click.Context) -> None:
    """Test radio RX/TX using a special loopback protocol preset. This
    currently requires a firmware compiled with a special test radio
    backend.

    """

    obj = ctx.ensure_object(RadioContext)
    radio = obj.radio

    try:
        radio.set_active_preset(RadioPreset.TEST_LOOPBACK)
    except KeyError:
        ctx.fail("Device not running test firmware")

    radio.send(b"Test")
    with radio.rx_enabled():
        print(radio.recv())


@test.command()
@click.pass_context
def rx(ctx: click.Context):
    pass


if __name__ == "__main__":
    cli()
