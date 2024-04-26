#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: Copyright 2024 Andreas Sandberg <andreas@sandberg.uk>
#
# SPDX-License-Identifier: Apache-2.0
#

import inspect
from abc import (
    ABC,
    abstractmethod,
)
from datetime import datetime
from typing import (
    Any,
    Dict,
    List,
    Set,
    Tuple,
    Type,
    Union,
)
from uuid import UUID

from rfchameleon.db import (
    PacketDatabase,
    RawPacket,
)
from rfchameleon.radio import RadioPreset


def _is_simple_class(cls: Any) -> bool:
    """Check if something is a class that can be instantiated without arguments."""

    try:
        inspect.signature(cls).bind()
        return True
    except TypeError:
        return False


class PacketHandler(ABC):
    simple_packet_handlers: Dict[str, Type["PacketHandler"]] = {}

    @classmethod
    def __init_subclass__(cls, /, **kwargs) -> None:
        super().__init_subclass__(**kwargs)

        if _is_simple_class(cls):
            PacketHandler.simple_packet_handlers[cls.__name__] = cls

    @abstractmethod
    def raw_packet(self, packet: RawPacket) -> None:
        pass


class PacketPrinter(PacketHandler):
    simple_packet_printers: Dict[str, Type["PacketPrinter"]] = {}
    protocol_printers: Dict[UUID, List[Type["PacketPrinter"]]] = {}

    protocol_uuids: Union[UUID, Set[UUID]] = set()

    @classmethod
    def __init_subclass__(cls, /, **kwargs) -> None:
        super().__init_subclass__(**kwargs)

        if _is_simple_class(cls):
            PacketPrinter.simple_packet_printers[cls.__name__] = cls
            supported_uuids = (
                cls.protocol_uuids
                if isinstance(cls.protocol_uuids, set)
                else {cls.protocol_uuids}
            )
            for uuid in supported_uuids:
                try:
                    PacketPrinter.protocol_printers[uuid].append(cls)
                except KeyError:
                    PacketPrinter.protocol_printers[uuid] = [
                        cls,
                    ]

    @classmethod
    def compatible_printers(
        cls, preset: Union[UUID, RadioPreset]
    ) -> List[Type["PacketPrinter"]]:
        uuid = preset.value if isinstance(preset, RadioPreset) else preset
        try:
            return cls.protocol_printers[uuid]
        except KeyError:
            return []

    @classmethod
    def from_preset(cls, preset: Union[UUID, RadioPreset]) -> "PacketPrinter":
        printers = cls.compatible_printers(preset)
        return printers[0]() if printers else RawPacketPrinter()

    def _format_meta(self, packet: RawPacket) -> Tuple[str, str]:
        rx_info = packet.rx_info
        meta = []

        if rx_info.crc_ok is not None:
            meta.append("CRC_OK" if rx_info.crc_ok else "CRC_ERROR")

        if rx_info.rssi is not None:
            meta.append(f"RSSI: {rx_info.rssi:.1f}")

        if rx_info.channel is not None:
            meta.append(f"CHANNEL: {rx_info.rssi:.1f}")

        ts = datetime.fromtimestamp(packet.ts).isoformat()

        return ts, ", ".join(meta)

    @abstractmethod
    def raw_packet(self, packet: RawPacket) -> None:
        prefix, rx_meta = self._format_meta(packet)

        print(f"{prefix}\t{packet.payload.hex()}\t{rx_meta}")


class RawPacketPrinter(PacketPrinter):
    def raw_packet(self, packet: RawPacket) -> None:
        super().raw_packet(packet)


class AutoPacketPrinter(PacketHandler):
    packet_printers: Dict[UUID, PacketPrinter]

    def __init__(self):
        self.packet_printers = {}

    def get_printer(
        self, preset_or_packet: Union[UUID, RadioPreset, RawPacket]
    ) -> PacketPrinter:
        if isinstance(preset_or_packet, UUID):
            uuid = preset_or_packet
        elif isinstance(preset_or_packet, RadioPreset):
            uuid = preset_or_packet.value
        else:
            uuid = preset_or_packet.preset_uuid

        try:
            printer = self.packet_printers[uuid]
        except KeyError:
            printer = PacketPrinter.from_preset(uuid)
            self.packet_printers[uuid] = printer

        return printer

    def raw_packet(self, packet: RawPacket) -> None:
        return self.get_printer(packet).raw_packet(packet)


class PacketDBDump(PacketHandler):
    def __init__(self, db: PacketDatabase):
        assert db is not None
        self.db = db

    def raw_packet(self, packet: RawPacket) -> None:
        with self.db.transaction():
            self.db.add_packet(packet)
