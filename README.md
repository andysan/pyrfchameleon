<!--
SPDX-FileCopyrightText: Copyright 2023-2024 Andreas Sandberg <andreas@sandberg.uk>

SPDX-License-Identifier: Apache-2.0
-->

# What is RF Chameleon

RF Chameleon is a set of tools to interface with ISM-band radios. It's
inspired by [RFQuack](https://rfquack.org/) but provides a more
abstract interface to the radio which implies that it needs to make
more assumptions about the underlying protocol. Unlike RFQuack, RF
Chameleon is not intended as an RF exploration tool. RF Chameleon is
intended to be used in the phase after basic exploration when the
underlying radio parameters are known.

This repository contains the Python library to interface with the RF
Chameleon hardware.
