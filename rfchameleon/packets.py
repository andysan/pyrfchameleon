#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: Copyright 2024 Andreas Sandberg <andreas@sandberg.uk>
#
# SPDX-License-Identifier: Apache-2.0
#

from abc import (
    ABC,
    abstractmethod,
)
from datetime import datetime
from typing import Tuple

from rfchameleon.db import (
    PacketDatabase,
    RawPacket,
)


class PacketHandler(ABC):
    @abstractmethod
    def raw_packet(self, packet: RawPacket) -> None:
        pass


class PacketPrinter(PacketHandler):
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

    def raw_packet(self, packet: RawPacket) -> None:
        prefix, rx_meta = self._format_meta(packet)

        print(f"{prefix}\t{packet.payload.hex()}\t{rx_meta}")


def PacketDBDump(PacketHandler):
    def __init__(self, db: PacketDatabase):
        assert db is not None
        self.db = db

    def raw_packet(self, packet: RawPacket) -> None:
        with self.db.transaction():
            self.db.add_packet(packet)
