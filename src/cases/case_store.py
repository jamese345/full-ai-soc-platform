import json
import sqlite3
from contextlib import closing
from copy import deepcopy
from pathlib import Path


class CaseStore:
    """SQLite-backed persistent store for SOC cases."""

    def __init__(self, db_path: str = "cases.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize_database()

    def _connect(self):
        return sqlite3.connect(self.db_path)

    def _initialize_database(self):
        with closing(self._connect()) as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS cases (
                    case_id TEXT PRIMARY KEY,
                    case_data TEXT NOT NULL
                )
                """
            )
            connection.commit()

    def create(self, case: dict) -> dict:
        case_copy = deepcopy(case)

        with closing(self._connect()) as connection:
            connection.execute(
                """
                INSERT INTO cases (case_id, case_data)
                VALUES (?, ?)
                """,
                (
                    case_copy["case_id"],
                    json.dumps(case_copy, ensure_ascii=False),
                ),
            )
            connection.commit()

        return deepcopy(case_copy)

    def get(self, case_id: str) -> dict | None:
        with closing(self._connect()) as connection:
            row = connection.execute(
                """
                SELECT case_data
                FROM cases
                WHERE case_id = ?
                """,
                (case_id,),
            ).fetchone()

        if row is None:
            return None

        return deepcopy(json.loads(row[0]))

    def update(self, case_id: str, case: dict) -> dict:
        case_copy = deepcopy(case)

        with closing(self._connect()) as connection:
            cursor = connection.execute(
                """
                UPDATE cases
                SET case_data = ?
                WHERE case_id = ?
                """,
                (
                    json.dumps(case_copy, ensure_ascii=False),
                    case_id,
                ),
            )
            connection.commit()

        if cursor.rowcount == 0:
            raise KeyError(f"Case not found: {case_id}")

        return deepcopy(case_copy)

    def delete(self, case_id: str) -> bool:
        with closing(self._connect()) as connection:
            cursor = connection.execute(
                """
                DELETE FROM cases
                WHERE case_id = ?
                """,
                (case_id,),
            )
            connection.commit()

        return cursor.rowcount > 0

    def list_cases(self) -> list[dict]:
        with closing(self._connect()) as connection:
            rows = connection.execute(
                """
                SELECT case_data
                FROM cases
                ORDER BY case_id
                """
            ).fetchall()

        return [
            deepcopy(json.loads(row[0]))
            for row in rows
        ]

    def count(self) -> int:
        with closing(self._connect()) as connection:
            row = connection.execute(
                """
                SELECT COUNT(*)
                FROM cases
                """
            ).fetchone()

        return int(row[0])

