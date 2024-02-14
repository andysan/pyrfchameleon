#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: Copyright 2023-2024 Andreas Sandberg <andreas@sandberg.uk>
#
# SPDX-License-Identifier: Apache-2.0
#

import enum
import errno
import logging
from abc import (
    ABC,
    abstractmethod,
)
from dataclasses import (
    astuple,
    dataclass,
)
from struct import Struct
from typing import (
    Iterable,
    Optional,
    Tuple,
    Type,
    TypeVar,
    Union,
)
from uuid import UUID

from typing_extensions import Self

from . import (
    CommandError,
    RadioErrno,
    RadioErrnoOrInt,
    RequestUnsupportedError,
    ReturnValue,
    TransportException,
)

logger = logging.getLogger(__name__)


class RadioProperty(enum.IntEnum):
    GET_PROTOCOL_INFO = 0x00
    GET_FIRMWARE_INFO = 0x02
    GET_BOOTLOADER_INFO = 0x04
    SET_REBOOT = 0x05
    GET_BOARD_INFO = 0x06

    GET_RADIO_INFO = 0x10
    GET_RADIO_PRESET = 0x12
    GET_RADIO_STATE = 0x14
    SET_RADIO_STATE = 0x15
    GET_ACTIVE_PRESET = 0x16
    SET_ACTIVE_PRESET = 0x17

    def is_descriptor(self) -> bool:
        return self < 0x10


class BootloaderType(enum.IntEnum):
    REBOOT = 0x00
    ROM = 0x01
    MCUBOOT = 0x02


class RadioState(enum.IntEnum):
    IDLE = 0x00
    RX = 0x01
    TX = 0x02

    ERROR = 0xFF


class TransportObject(ABC):
    _STRUCT: Struct

    @classmethod
    def struct_size(cls) -> int:
        return cls._STRUCT.size

    @classmethod
    def unpack(cls, data: bytes) -> Self:
        return cls(*cls._STRUCT.unpack(data))


TO = TypeVar("TO", bound=TransportObject)


@dataclass
class Version:
    major: int
    minor: int
    rev: int

    def __str__(self) -> str:
        return f"{self.major}.{self.minor}.{self.rev}"


@dataclass
class ProtocolInfo(TransportObject):
    uuid: UUID
    version: Version
    max_payload: int

    _STRUCT = Struct("<16sHHHH")

    @classmethod
    def unpack(cls, data: bytes) -> Self:
        uuid, major, minor, rev, max_payload = cls._STRUCT.unpack(data)
        return cls(UUID(bytes=uuid), Version(major, minor, rev), max_payload)


@dataclass
class FirmwareInfo(TransportObject):
    version: Version

    _STRUCT = Struct("<HHH")

    @classmethod
    def unpack(cls, data: bytes) -> Self:
        major, minor, rev = cls._STRUCT.unpack(data)
        return cls(Version(major, minor, rev))


@dataclass
class BootloaderInfo(TransportObject):
    type: int
    flags: int
    version: Version

    _STRUCT = Struct("<BHHHH")

    @classmethod
    def unpack(cls, data: bytes) -> Self:
        type, flags, major, minor, rev = cls._STRUCT.unpack(data)
        return cls(type, flags, Version(major, minor, rev))


@dataclass
class BoardInfo(TransportObject):
    variant: int
    revision: int
    compatible: str

    _STRUCT = Struct("<IH40s")

    @classmethod
    def unpack(cls, data: bytes) -> Self:
        variant, revision, _compatible = cls._STRUCT.unpack(data)
        compatible = _compatible.split(b"\x00", 1)[0].decode("ASCII")
        return cls(variant, revision, compatible)


@dataclass
class RadioPresetDesc(TransportObject):
    uuid: UUID
    packet_size: int
    rx_meta_size: int

    _STRUCT = Struct("<16sHB")

    @classmethod
    def unpack(cls, data: bytes) -> Self:
        uuid, packet_size, rx_meta_size = cls._STRUCT.unpack(data)
        return cls(UUID(bytes=uuid), packet_size, rx_meta_size)


class BulkType(enum.IntEnum):
    PING = 0x00
    PONG = 0x01
    GET = 0x02
    GET_RESP = 0x03
    SET = 0x04
    SET_RESP = 0x05

    TX = 0x10
    TX_DONE = 0x11

    RX = 0x91

    @staticmethod
    def create(type: "BulkTypeOrInt") -> "BulkTypeOrInt":
        try:
            return BulkType(type)
        except ValueError:
            return type

    @property
    def is_async(self) -> bool:
        return _bulk_type_is_async(self)

    @property
    def response_type(self) -> "BulkType":
        return BulkType(self | 0x01)


def _bulk_type_is_async(type: int) -> bool:
    return type & 0x80 != 0


BulkTypeOrInt = Union[int, BulkType]


@dataclass
class BulkInHeader(TransportObject):
    MAGIC = b"RFCI"

    magic: bytes
    type: BulkTypeOrInt
    flags: int
    ret: ReturnValue
    payload_length: int

    _STRUCT = Struct("<4sHHiH")

    @classmethod
    def unpack(cls, data: bytes) -> Self:
        magic, type, flags, ret, payload_length = cls._STRUCT.unpack(data)

        return cls(
            magic,
            BulkType.create(type),
            flags,
            ReturnValue(ret),
            payload_length,
        )


@dataclass
class BulkOutHeader(TransportObject):
    MAGIC = b"RFCO"

    magic: bytes
    type: BulkTypeOrInt
    flags: int
    value: int
    payload_length: int

    _STRUCT = Struct("<4sHHIH")

    @classmethod
    def unpack(cls, data: bytes) -> Self:
        hdr = super().unpack(data)
        hdr.type = BulkType.create(hdr.type)
        return hdr

    def pack(self) -> bytes:
        return self._STRUCT.pack(*astuple(self))


class RadioTransport(ABC):
    def get(self, property: RadioProperty, length: int, *, index: int = 0) -> bytes:
        if property & 0xFFFF != property:
            raise ValueError("Invalid property")
        if index & 0xFFFF != index:
            raise ValueError("Invalid value/index")

        _, data = self._command(BulkType.GET, value=(property << 16) | index)

        return data[0:length]

    def get_obj(
        self,
        property: RadioProperty,
        cls: Type[TO],
        *,
        index: int = 0,
    ) -> TO:
        return cls.unpack(self.get(property, cls.struct_size(), index=index))

    def get_obj_iterator(self, property: RadioProperty, cls: Type[TO]) -> Iterable[TO]:
        for i in range(0x10000):
            try:
                yield self.get_obj(property, cls, index=i)
            except CommandError as e:
                if e.error == RadioErrno.ENOENT:
                    return
                raise e
            except RequestUnsupportedError:
                return

    def set(
        self,
        property: RadioProperty,
        value: int,
        *,
        data: bytes = b"",
    ) -> None:
        if property & 0xFFFF != property:
            raise ValueError("Invalid property")
        if value & 0xFFFF != value:
            raise ValueError("Invalid value/index")

        self._command(
            BulkType.SET,
            value=(property << 16) | value,
            data=data,
        )

    @abstractmethod
    def bulk_read(self, timeout: Optional[float] = None) -> Tuple[BulkInHeader, bytes]:
        pass

    @abstractmethod
    def bulk_write(self, header: BulkOutHeader, data: bytes = b"") -> None:
        pass

    def bulk_wait_for(
        self, type: BulkType, timeout: Optional[float] = None
    ) -> Tuple[BulkInHeader, bytes]:
        while True:
            header, data = self.bulk_read(timeout=timeout)
            if header.type == type:
                header.ret.raise_error()
                return header, data
            elif _bulk_type_is_async(header.type):
                logging.warning(f"Ignoring async USB packet: {header.type}")
            else:
                raise TransportException(
                    "Unexpected response type. " f"Got {header.type} expected {type}."
                )

    def _command(
        self,
        type: BulkType,
        data: bytes = b"",
        *,
        flags: int = 0,
        value: int = 0,
        timeout: Optional[float] = None,
    ) -> Tuple[BulkInHeader, bytes]:
        cmd_header = BulkOutHeader(
            magic=BulkOutHeader.MAGIC,
            type=type,
            flags=flags,
            value=value,
            payload_length=len(data),
        )

        self.bulk_write(cmd_header, data=data)
        return self.bulk_wait_for(type.response_type, timeout=timeout)

    def ping(self, data: bytes = b"ping", *, timeout: Optional[float] = None) -> None:
        header, reply = self._command(BulkType.PING, data=data, timeout=timeout)
        if reply != data:
            raise TransportException("Ping data corruption")

    def recv(self, *, timeout: Optional[float] = None) -> bytes:
        _, data = self.bulk_wait_for(BulkType.RX, timeout=timeout)
        return data

    def send(self, data: bytes, *, timeout: Optional[float] = None) -> None:
        self._command(BulkType.TX, data=data, timeout=timeout)
