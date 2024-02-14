#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: Copyright 2024 Andreas Sandberg <andreas@sandberg.uk>
#
# SPDX-License-Identifier: Apache-2.0
#

import enum
import logging
from typing import Union

logger = logging.getLogger(__name__)


class RadioErrno(enum.IntEnum):
    # No error
    EOK = (0,)
    # Unknown error occurred
    EUNKNOWN = 1
    # Invalid call type
    ENOSYS = 2
    # Invalid argument
    EINVAL = 3
    # Memory allocation failure
    ENOMEM = 4
    # Entry does not exist (e.g., valid call but invalid index).
    ENOENT = 5

    def __str__(self) -> str:
        return self.name

    @staticmethod
    def create(error: "RadioErrnoOrInt") -> "RadioErrnoOrInt":
        try:
            return RadioErrno(error)
        except ValueError:
            return error


RadioErrnoOrInt = Union[RadioErrno, int]


class ReturnValue:
    raw: int

    def __init__(self, value: int):
        self.raw = value

    @property
    def value(self) -> int:
        if self.is_error:
            raise ValueError("Return value indicates error")

        return self.raw

    @property
    def is_error(self) -> bool:
        return self.raw < 0

    @property
    def error(self) -> RadioErrnoOrInt:
        if self.is_error:
            return RadioErrno.create(-self.raw)
        else:
            return RadioErrno.EOK

    def raise_error(self, msg: str = "") -> None:
        if not self.is_error:
            return

        raise CommandError(self.error, f"Command failed: {self.error}")

    def __str__(self) -> str:
        if self.is_error:
            return f"-{self.error}"
        else:
            return f"{self.value}"

    def __repr__(self) -> str:
        if self.is_error:
            return f"ReturnValue(-{self.error})"
        else:
            return f"ReturnValue({self.value})"


class ChameleonException(Exception):
    pass


class FirmwareError(ChameleonException):
    pass


class TransportException(ChameleonException):
    pass


class NoDeviceError(ChameleonException):
    pass


class TransportTimeoutError(TransportException):
    pass


class TransportDisconnectedError(TransportException):
    pass


class CommandError(ChameleonException):
    def __init__(self, error: RadioErrnoOrInt, msg: str = ""):
        super().__init__(msg)
        self.error = error


class RequestUnsupportedError(TransportException):
    pass
