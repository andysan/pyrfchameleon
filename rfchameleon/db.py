#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: Copyright 2024 Andreas Sandberg <andreas@sandberg.uk>
#
# SPDX-License-Identifier: Apache-2.0
#

import os
import sqlite3
import time
from abc import (
    ABC,
    abstractmethod,
)
from collections.abc import (
    ItemsView,
    KeysView,
    MutableMapping,
    ValuesView,
)
from contextlib import contextmanager
from typing import (
    Any,
    Iterable,
    Iterator,
    Optional,
    Union,
)
from uuid import UUID

from typing_extensions import Self

from .radio import RadioPreset
from .transport import (
    RadioPresetDesc,
    RxInfo,
)

sqlite3.register_adapter(UUID, lambda x: str(x).lower())
sqlite3.register_converter("UUID", lambda x: UUID(x.decode("ASCII")))


class SchemaVersionError(Exception):
    pass


class TableVersions(MutableMapping):
    _conn: sqlite3.Connection

    def __init__(self, connection: sqlite3.Connection):
        self._conn = connection

        with connection:
            self._conn.executescript(
                """
CREATE TABLE IF NOT EXISTS table_versions(
    key TEXT PRIMARY KEY,
    value INTEGER
);
            """
            )

    def keys(self) -> KeysView[str]:
        return KeysView(self)

    def values(self) -> ValuesView[int]:
        return ValuesView(self)

    def items(self) -> ItemsView[str, int]:
        return ItemsView(self)

    def __contains__(self, key: Any) -> bool:
        if not isinstance(key, str):
            return False

        try:
            self[key]
        except KeyError:
            return False

        return True

    def __getitem__(self, key: str) -> int:
        values = self._conn.execute(
            "SELECT value FROM table_versions WHERE key = ?;", (key,)
        ).fetchall()
        if not values:
            raise KeyError(f"'{key}' does not exist'")

        if len(values) > 1:
            raise RuntimeError(f"'{key}' has multiple values")

        if not isinstance(values[0][0], int):
            raise RuntimeError(f"Value of '{key}' has incorrect type ")

        return values[0][0]

    def __setitem__(self, key: str, value: int) -> None:
        self._conn.execute(
            """
INSERT INTO table_versions(key, value) VALUES (?, ?)
    ON CONFLICT(key) DO UPDATE SET value=excluded.value;
        """,
            (key, value),
        )

    def __delitem__(self, key: str) -> None:
        self._conn.execute("DELETE FROM dict WHERE key = ?;", (key,))

    def __len__(self) -> int:
        result = self._conn.execute("SELECT count(*) FROM table_versions;").fetchone()
        return result if result is not None else 0

    def __iter__(self) -> Iterator[str]:
        cursor = self._conn.execute("SELECT key FROM table_versions;")
        for row in cursor:
            yield row[0]


class DatabaseObject(ABC):
    _conn: sqlite3.Connection
    _table_versions: TableVersions
    _table_name: str
    _version: int

    def __init__(
        self,
        connection: sqlite3.Connection,
        table_versions: TableVersions,
        table_name: str,
        *,
        version: int = 1,
    ):
        self._conn = connection
        self._table_versions = table_versions
        self._table_name = table_name
        self._version = version

    @contextmanager
    def transaction(self) -> Iterator[Self]:
        with self._conn:
            yield self

    def create_or_upgrade_tables(self) -> None:
        try:
            version = self._table_versions[self._table_name]
        except KeyError:
            self.create_tables()
            return

        if version < self._version:
            with self.transaction():
                self._upgrade_tables(version)
                self._table_versions[self._table_name] = self._version

    def create_tables(self) -> None:
        if self._table_name in self._table_versions:
            return

        self._create_tables()
        self._table_versions[self._table_name] = self._version

    def _upgrade_tables(self, ver_from: int) -> None:
        raise RuntimeError("Can't upgrade table")

    @abstractmethod
    def _create_tables(self) -> None:
        pass


class PacketDatabase(DatabaseObject):
    def __init__(self, connection: sqlite3.Connection):
        super().__init__(
            connection,
            TableVersions(connection),
            "packet_db",
        )

    @classmethod
    @contextmanager
    def open(cls, path: Union[str, os.PathLike]) -> Iterator[Self]:
        conn = sqlite3.connect(
            path,
            detect_types=sqlite3.PARSE_DECLTYPES,
        )

        conn.autocommit = False
        conn.execute("PRAGMA foreign_keys = ON;")

        try:
            yield cls(conn)
        finally:
            conn.close()

    def _create_tables(self) -> None:
        self._conn.executescript(
            """
CREATE TABLE protocols(
    id INTEGER NOT NULL PRIMARY KEY,
    uuid UUID NOT NULL UNIQUE,
    name TEXT
);

CREATE TABLE raw_packets(
    id INTEGER NOT NULL PRIMARY KEY,
    time REAL NOT NULL,
    protocol INTEGER REFERENCES protocols(id),
    payload BLOB NOT NULL,
    meta BLOB,
    flags INTEGER,
    rssi REAL,
    channel INTEGER,
    crc_ok INTEGER
);
        """
        )

    def update_protocols(self, presets: Iterable[RadioPresetDesc]) -> None:
        def preset_name(uuid: UUID) -> Optional[str]:
            try:
                return RadioPreset(uuid).long_name
            except ValueError:
                return None

        _presets = [(p.uuid, preset_name(p.uuid)) for p in presets]
        self._conn.executemany(
            "INSERT OR IGNORE INTO protocols(uuid, name) VALUES (?, ?);", _presets
        )

    def add_packet(
        self,
        radio_preset: RadioPresetDesc,
        header: RxInfo,
        data: bytes,
        *,
        ts: Optional[float] = None,
    ) -> None:
        if ts is None:
            ts = time.time()

        meta_size = radio_preset.rx_meta_size
        if meta_size:
            payload, meta = data[:-meta_size], data[-meta_size:]
        else:
            payload, meta = data, None

        self._conn.execute(
            """
INSERT INTO raw_packets(time, protocol, payload, meta, flags, rssi, channel, crc_ok)
    SELECT ?, id, ?, ?, ?, ?, ?, ? FROM protocols WHERE uuid=?;
        """,
            (
                ts,
                payload,
                meta,
                header.flags,
                header.rssi,
                header.channel,
                header.crc_ok,
                radio_preset.uuid,
            ),
        )
