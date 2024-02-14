#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: Copyright 2023-2024 Andreas Sandberg <andreas@sandberg.uk>
#
# SPDX-License-Identifier: Apache-2.0
#

import enum
import logging
from contextlib import contextmanager
from typing import (
    Dict,
    Iterable,
    Iterator,
    List,
    Optional,
    Tuple,
    Union,
)
from uuid import UUID

from . import FirmwareError
from .transport import (
    BoardInfo,
    BootloaderInfo,
    BootloaderType,
    FirmwareInfo,
    ProtocolInfo,
    RadioPresetDesc,
    RadioProperty,
    RadioState,
    RadioTransport,
)

logger = logging.getLogger(__name__)

FIRMWARE_UUID = UUID("3626D5F9-8454-4519-9EEB-32DA9544D1A4")


class RadioPreset(enum.Enum):
    CHAMELEON_CHAT = UUID("0000E693-4518-4EA6-B47C-CF8B5DE743B4")

    TEST_NULL = UUID("00009CCB-0444-4534-8920-C8F2F17CC822")
    TEST_LOOPBACK = UUID("00019CCB-0444-4534-8920-C8F2F17CC822")

    @property
    def long_name(self) -> str:
        try:
            return radio_preset_names[self]
        except KeyError:
            return self.name


radio_preset_names = {
    RadioPreset.CHAMELEON_CHAT: "RF Chameleon Chat",
}


class Radio:
    _transport: RadioTransport

    protocol_info: ProtocolInfo
    firmware_info: FirmwareInfo
    bootloader_info: List[BootloaderInfo]
    board_info: BoardInfo

    radio_preset_descs: List[RadioPresetDesc]

    _radio_preset_map: Dict[UUID, int]

    _bootloader_map: Dict[int, int]

    def __init__(self, transport: RadioTransport):
        self._transport = transport

        self.protocol_info = self._get_protocol_info()
        if self.protocol_info.uuid != FIRMWARE_UUID:
            raise FirmwareError(f"Invalid firmware UUID: {self.protocol_info.uuid}")

        self.firmware_info = self._get_firmware_info()
        self.bootloader_info = self._get_bootloader_info()
        self.board_info = self._get_board_info()

        self._bootloader_map = {
            inf.type: idx for idx, inf in enumerate(self.bootloader_info)
        }

        self.radio_preset_descs = self._get_radio_presets()
        self._radio_preset_map = {
            desc.uuid: idx for idx, desc in enumerate(self.radio_preset_descs)
        }

    def _get_protocol_info(self) -> ProtocolInfo:
        return self._transport.get_obj(RadioProperty.GET_PROTOCOL_INFO, ProtocolInfo)

    def _get_firmware_info(self) -> FirmwareInfo:
        return self._transport.get_obj(RadioProperty.GET_FIRMWARE_INFO, FirmwareInfo)

    def _get_bootloader_info(self) -> List[BootloaderInfo]:
        return list(
            self._transport.get_obj_iterator(
                RadioProperty.GET_BOOTLOADER_INFO, BootloaderInfo
            )
        )

    def _get_board_info(self) -> BoardInfo:
        return self._transport.get_obj(RadioProperty.GET_BOARD_INFO, BoardInfo)

    def _get_radio_presets(self) -> List[RadioPresetDesc]:
        return list(
            self._transport.get_obj_iterator(
                RadioProperty.GET_RADIO_PRESET, RadioPresetDesc
            )
        )

    def reboot(self, bootloader: BootloaderType) -> None:
        try:
            idx = self._bootloader_map[bootloader]
        except KeyError:
            raise ValueError("Unsupported or invalid bootloader specified")

        self._transport.set(RadioProperty.SET_REBOOT, bootloader)

    def ping(self, data: bytes = b"ping", *, timeout: Optional[float] = None) -> None:
        self._transport.ping(data, timeout=timeout)

    def set_active_preset(self, preset: Union[UUID, RadioPreset]) -> None:
        idx = self._radio_preset_map[
            preset if isinstance(preset, UUID) else preset.value
        ]
        self._transport.set(RadioProperty.SET_ACTIVE_PRESET, idx)

    def set_state(self, state: RadioState) -> None:
        self._transport.set(RadioProperty.SET_RADIO_STATE, state)

    def set_rx(self, enable: bool) -> None:
        self.set_state(RadioState.RX if enable else RadioState.IDLE)

    @contextmanager
    def rx_enabled(self) -> Iterator[None]:
        self.set_rx(True)
        try:
            yield
        finally:
            self.set_rx(False)

    def recv(self, timeout: Optional[float] = None) -> bytes:
        return self._transport.recv(timeout=timeout)

    def send(self, packet: bytes) -> None:
        self._transport.send(packet)
