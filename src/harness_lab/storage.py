"""One-run SQLite world and append-only, atomically committed tool receipts."""

import json
import sqlite3
import uuid
from contextlib import closing
from pathlib import Path
from typing import Any


def canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def initialize_environment(db_path: str | Path, world: dict[str, Any]) -> None:
    """Prepare a fresh isolated world; called by a driver, never by the Host."""
    path = Path(db_path)
    if path.exists():
        raise FileExistsError(f"Refusing to reuse an environment: {path}")
    if not isinstance(world.get("target_ref"), str):
        raise ValueError("world requires a target_ref")
    if type(world.get("revision")) is not int or world["revision"] < 0:
        raise ValueError("world requires a nonnegative integer revision")
    if world.get("write_policy") not in {"allow", "forbid", "approval"}:
        raise ValueError("world requires an explicit write_policy")
    queues = world.get("queue_options")
    if not isinstance(queues, list) or not queues or not all(isinstance(x, str) for x in queues):
        raise ValueError("world requires nonempty queue_options")
    path.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(path)) as connection, connection:
        connection.executescript(
            """
            PRAGMA foreign_keys = ON;
            CREATE TABLE state (
                target_ref TEXT PRIMARY KEY,
                payload_json TEXT NOT NULL
            );
            CREATE TABLE tickets (
                ticket_id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                operation_id TEXT UNIQUE NOT NULL,
                target_ref TEXT NOT NULL,
                params_json TEXT NOT NULL
            );
            CREATE TABLE receipts (
                receipt_id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                operation_id TEXT UNIQUE NOT NULL,
                target_ref TEXT NOT NULL,
                ticket_id TEXT UNIQUE NOT NULL REFERENCES tickets(ticket_id),
                params_json TEXT NOT NULL,
                payload_json TEXT NOT NULL
            );
            CREATE TRIGGER tickets_no_update BEFORE UPDATE ON tickets
                BEGIN SELECT RAISE(ABORT, 'effects are immutable'); END;
            CREATE TRIGGER tickets_no_delete BEFORE DELETE ON tickets
                BEGIN SELECT RAISE(ABORT, 'effects are immutable'); END;
            CREATE TRIGGER receipts_no_update BEFORE UPDATE ON receipts
                BEGIN SELECT RAISE(ABORT, 'receipts are immutable'); END;
            CREATE TRIGGER receipts_no_delete BEFORE DELETE ON receipts
                BEGIN SELECT RAISE(ABORT, 'receipts are immutable'); END;
            """
        )
        connection.execute(
            "INSERT INTO state VALUES (?, ?)", (world["target_ref"], canonical_json(world))
        )


class ToolRejection(Exception):
    def __init__(self, code: str, message: str, *, repairable: bool = False):
        super().__init__(message)
        self.code = code
        self.repairable = repairable


class EnvironmentStore:
    """A single synchronous connection; its caller serializes all access."""

    def __init__(self, db_path: str | Path):
        # mode=rw prevents an incorrect process path from silently creating a new world.
        uri = Path(db_path).resolve().as_uri() + "?mode=rw"
        self.connection = sqlite3.connect(uri, uri=True, isolation_level=None)
        self.connection.execute("PRAGMA foreign_keys = ON")

    def close(self) -> None:
        self.connection.close()

    def read_state(self, target_ref: str) -> dict[str, Any]:
        row = self.connection.execute(
            "SELECT payload_json FROM state WHERE target_ref = ?", (target_ref,)
        ).fetchone()
        if row is None:
            raise ToolRejection("TARGET_NOT_FOUND", "Target does not exist")
        world = json.loads(row[0])
        world["tickets"] = [
            {"ticket_id": ticket_id, "params": json.loads(params_json)}
            for ticket_id, params_json in self.connection.execute(
                "SELECT ticket_id, params_json FROM tickets WHERE target_ref = ?", (target_ref,)
            )
        ]
        return world

    def change_state_if_unbound(
        self, operation_id: str, target_ref: str, patch: dict[str, Any]
    ) -> bool:
        """Persist a private external change before writing, never after slot commitment."""
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            bound = self.connection.execute(
                "SELECT 1 FROM receipts WHERE operation_id = ?", (operation_id,)
            ).fetchone()
            if bound:
                self.connection.execute("COMMIT")
                return False
            row = self.connection.execute(
                "SELECT payload_json FROM state WHERE target_ref = ?", (target_ref,)
            ).fetchone()
            if row is None:
                raise ToolRejection("TARGET_NOT_FOUND", "Target does not exist")
            world = json.loads(row[0])
            world.update(patch)
            self.connection.execute(
                "UPDATE state SET payload_json = ? WHERE target_ref = ?",
                (canonical_json(world), target_ref),
            )
            self.connection.execute("COMMIT")
            return True
        except BaseException:
            self.connection.execute("ROLLBACK")
            raise

    def create_ticket(
        self,
        *,
        run_id: str,
        operation_id: str,
        params: dict[str, Any],
        can_write: bool,
    ) -> dict[str, Any]:
        """No awaits or injected waits inside this complete transaction."""
        params_json = canonical_json(params)
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            row = self.connection.execute(
                "SELECT params_json, payload_json FROM receipts WHERE operation_id = ?",
                (operation_id,),
            ).fetchone()
            if row:
                if row[0] != params_json:
                    raise ToolRejection("IDEMPOTENCY_CONFLICT", "Bound parameters cannot change")
                receipt = json.loads(row[1])
            else:
                state = self.read_state(params["target_ref"])
                if not can_write or state["write_policy"] == "forbid":
                    raise ToolRejection("PERMISSION_DENIED", "Writing this target is forbidden")
                if state["write_policy"] == "approval":
                    raise ToolRejection("APPROVAL_REQUIRED", "Human approval is required")
                if params["expected_revision"] != state["revision"]:
                    raise ToolRejection("STALE_REVISION", "Refresh current state", repairable=True)
                if params["queue"] not in state["queue_options"]:
                    raise ToolRejection("INVALID_QUEUE", "Queue is unavailable", repairable=True)
                receipt = {
                    "receipt_id": f"receipt-{uuid.uuid4().hex}",
                    "run_id": run_id,
                    "operation_id": operation_id,
                    "target_ref": params["target_ref"],
                    "ticket_id": f"ticket-{uuid.uuid4().hex}",
                    "params": params,
                }
                self.connection.execute(
                    "INSERT INTO tickets VALUES (?, ?, ?, ?, ?)",
                    (
                        receipt["ticket_id"], run_id, operation_id,
                        params["target_ref"], params_json,
                    ),
                )
                self.connection.execute(
                    "INSERT INTO receipts VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        receipt["receipt_id"], run_id, operation_id,
                        params["target_ref"], receipt["ticket_id"],
                        params_json, canonical_json(receipt),
                    ),
                )
            self.connection.execute("COMMIT")
            return receipt
        except BaseException:
            self.connection.execute("ROLLBACK")
            raise
