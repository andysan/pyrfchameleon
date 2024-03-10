#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: Copyright 2023-2024 Andreas Sandberg <andreas@sandberg.uk>
#
# SPDX-License-Identifier: Apache-2.0
#

import errno
import logging
from contextlib import contextmanager
from typing import (
    Iterator,
    Optional,
    Tuple,
)

import usb.core  # type: ignore
import usb.util  # type: ignore
from typing_extensions import Self

from . import (
    NoDeviceError,
    RequestUnsupportedError,
    TransportDisconnectedError,
    TransportException,
    TransportTimeoutError,
)
from .transport import (
    BulkInHeader,
    BulkOutHeader,
    BulkType,
    RadioProperty,
    RadioTransport,
)

logger = logging.getLogger(__name__)

USB_BCC_VENDOR = 0xFF

RFCH_VID = 0x1209
RFCH_PID = 0x5F00


class UsbTransport(RadioTransport):
    usb_dev: usb.core.Device
    _usb_iface: usb.core.Interface
    _usb_ep_in: usb.core.Endpoint
    _usb_ep_out: usb.core.Endpoint

    def __init__(self, dev: usb.core.Device, iface: usb.core.Interface):
        logger.debug(
            "Configuring device %04x:%04x with address %s:%s.",
            dev.idVendor,
            dev.idProduct,
            dev.bus,
            dev.address,
        )
        logger.debug("Manufacturer: %s", dev.manufacturer)
        logger.debug("Product: %s", dev.product)
        logger.debug("Serial number: %s", dev.serial_number)

        self.usb_dev = dev
        self._usb_iface = iface

        self._usb_ep_in = self._get_ep(usb.util.ENDPOINT_IN)
        self._usb_ep_out = self._get_ep(usb.util.ENDPOINT_OUT)

        assert self._usb_ep_in is not None
        assert self._usb_ep_out is not None

    @classmethod
    @contextmanager
    def open(cls, dev: Optional[usb.core.Device] = None) -> Iterator[Self]:
        if dev is None:
            dev = usb.core.find(idVendor=RFCH_VID, idProduct=RFCH_PID)

        if dev is None:
            raise NoDeviceError("Failed to find RF Chameleon.")

        dev.set_configuration()
        cfg = dev.get_active_configuration()
        iface = usb.util.find_descriptor(cfg, bInterfaceClass=USB_BCC_VENDOR)

        detached = False

        try:
            logger.debug("Detaching kernel driver...")
            dev.detach_kernel_driver(iface.bInterfaceNumber)
            logger.debug("OK")
            detached = True
        except usb.core.USBError as e:
            logger.debug("USB Error: %s", e)
        except NotImplementedError:
            logger.debug("Detach not implemented")

        logger.debug("Resetting device.")
        dev.reset()

        try:
            yield cls(dev, iface)
        finally:
            if detached:
                logger.debug("Attaching kernel driver")
                dev.attach_kernel_driver(iface.bInterfaceNumber)

    def _get_ep(self, direction):
        def matcher(desc):
            return usb.util.endpoint_direction(desc.bEndpointAddress) == direction

        return usb.util.find_descriptor(
            self._usb_iface,
            custom_match=matcher,
        )

    def _ctrl_transfer(self, *args, **kwargs) -> bytes:
        try:
            return bytes(self.usb_dev.ctrl_transfer(*args, **kwargs))
        except usb.core.USBTimeoutError as e:
            raise TransportTimeoutError() from e
        except usb.core.USBError as e:
            if e.errno == errno.EPIPE:
                raise RequestUnsupportedError() from e
            elif e.errno == errno.ENODEV:
                raise TransportDisconnectedError() from e
            else:
                raise TransportException() from e

    def _ctrl_to_dev(
        self, req: int, *, value: int = 0, data: Optional[bytes] = None
    ) -> None:
        logger.debug("_ctrl_to_dev: %s, %s, %s", req, value, data)
        self._ctrl_transfer(
            bmRequestType=usb.util.build_request_type(
                usb.util.CTRL_OUT,
                usb.util.CTRL_TYPE_VENDOR,
                usb.util.CTRL_RECIPIENT_INTERFACE,
            ),
            wIndex=self._usb_iface.bInterfaceNumber,
            bRequest=req,
            wValue=value,
            data_or_wLength=data,
        )

    def _ctrl_from_dev(self, req: int, length: int, *, value: int = 0) -> bytes:
        logger.debug("_ctrl_from_dev: %s, %s, %s", req, length, value)
        return self._ctrl_transfer(
            bmRequestType=usb.util.build_request_type(
                usb.util.CTRL_IN,
                usb.util.CTRL_TYPE_VENDOR,
                usb.util.CTRL_RECIPIENT_INTERFACE,
            ),
            wIndex=self._usb_iface.bInterfaceNumber,
            bRequest=req,
            wValue=value,
            data_or_wLength=length,
        )

    def get(self, property: RadioProperty, length: int, *, index: int = 0) -> bytes:
        if property.is_descriptor():
            return self._ctrl_from_dev(property, length, value=index)
        else:
            return super().get(property, length, index=index)

    def bulk_read(self, timeout: Optional[float] = None) -> Tuple[BulkInHeader, bytes]:
        try:
            _header = bytes(
                self._usb_ep_in.read(self._usb_ep_in.wMaxPacketSize, timeout=timeout)
            )
            header = BulkInHeader.unpack(_header)
            logger.debug("bulk_read: %s", header)
            if header.magic != BulkInHeader.MAGIC:
                raise TransportException("Invalid header")

            data = b""
            while len(data) < header.payload_length:
                data += bytes(
                    self._usb_ep_in.read(header.payload_length, timeout=timeout)
                )
        except usb.core.USBTimeoutError as e:
            raise TransportTimeoutError() from e

        return header, bytes(data)

    def bulk_write(self, header: BulkOutHeader, data: bytes = b""):
        logger.debug("bulk_write: %s", header)
        self._usb_ep_out.write(header.pack())
        if len(data):
            self._usb_ep_out.write(data)
