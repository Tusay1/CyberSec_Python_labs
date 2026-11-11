"""Шар доступу до даних: параметризовані SQL-запити без ORM.

Модуль не залежить від FastAPI. Про очікувані помилки він повідомляє
власними винятками, які шар API перетворює на HTTP-відповіді.
"""

import sqlite3
from collections.abc import Iterable
from contextlib import closing
from typing import Any

from labs.lab03.database import get_connection

RECORD_COLUMNS = (
    "r.id, r.code, r.title, r.category_id, r.value, r.status, c.name AS category_name"
)
RECORD_SELECT = (
    f"SELECT {RECORD_COLUMNS} FROM records AS r "
    "JOIN categories AS c ON c.id = r.category_id"
)
RECORD_FIELDS = ("code", "title", "category_id", "value", "status")


class RepositoryError(Exception):
    """Базовий виняток шару даних."""


class NotFoundError(RepositoryError):
    """Запис або категорія не існує."""


class ConflictError(RepositoryError):
    """Порушено унікальність або видаляється непорожня категорія."""


def _connect() -> sqlite3.Connection:
    connection = get_connection()
    connection.row_factory = sqlite3.Row
    return connection


def _category_exists(connection: sqlite3.Connection, category_id: int) -> bool:
    row = connection.execute(
        "SELECT 1 FROM categories WHERE id = ?", (category_id,)
    ).fetchone()
    return row is not None


def _fetch_record(connection: sqlite3.Connection, record_id: int) -> dict | None:
    row = connection.execute(f"{RECORD_SELECT} WHERE r.id = ?", (record_id,)).fetchone()
    return dict(row) if row else None


def _raise_from_integrity(exc: sqlite3.IntegrityError) -> None:
    """Перетворити порушення обмежень SQLite на виняток шару даних."""
    message = str(exc)
    if "FOREIGN KEY" in message:
        raise NotFoundError("Категорію не знайдено") from exc
    if "UNIQUE" in message:
        raise ConflictError("Запис з таким кодом уже існує") from exc
    raise ConflictError("Дані порушують обмеження бази") from exc


# --------------------------------------------------------------- категорії


def list_categories() -> list[dict]:
    """Повернути всі категорії за зростанням id."""
    with closing(_connect()) as connection:
        rows = connection.execute(
            "SELECT id, name FROM categories ORDER BY id"
        ).fetchall()
    return [dict(row) for row in rows]


def create_category(name: str) -> dict:
    """Створити категорію; дублікат назви дає ConflictError."""
    with closing(_connect()) as connection:
        try:
            with connection:
                cursor = connection.execute(
                    "INSERT INTO categories (name) VALUES (?)", (name,)
                )
        except sqlite3.IntegrityError as exc:
            raise ConflictError("Категорія з такою назвою вже існує") from exc
        return {"id": cursor.lastrowid, "name": name}


def delete_category(category_id: int) -> None:
    """Видалити порожню категорію."""
    with closing(_connect()) as connection, connection:
        if not _category_exists(connection, category_id):
            raise NotFoundError("Категорію не знайдено")
        (count,) = connection.execute(
            "SELECT COUNT(*) FROM records WHERE category_id = ?",
            (category_id,),
        ).fetchone()
        if count:
            raise ConflictError("Категорія містить записи")
        try:
            connection.execute("DELETE FROM categories WHERE id = ?", (category_id,))
        except sqlite3.IntegrityError as exc:
            raise ConflictError("Категорія містить записи") from exc


# ------------------------------------------------------------------ записи


def get_record(record_id: int) -> dict | None:
    """Повернути запис разом з назвою категорії або None."""
    with closing(_connect()) as connection:
        return _fetch_record(connection, record_id)


def list_records(
    *,
    category_id: int | None = None,
    status: str | None = None,
    min_value: float | None = None,
    q: str | None = None,
    limit: int = 20,
    offset: int = 0,
) -> list[dict]:
    """Повернути записи з фільтрами (AND) і поділом на сторінки."""
    conditions: list[str] = []
    params: list[Any] = []
    if category_id is not None:
        conditions.append("r.category_id = ?")
        params.append(category_id)
    if status is not None:
        conditions.append("r.status = ?")
        params.append(status)
    if min_value is not None:
        conditions.append("r.value >= ?")
        params.append(min_value)
    if q is not None:
        # instr() шукає буквальний підрядок з урахуванням регістру.
        conditions.append("instr(r.title, ?) > 0")
        params.append(q)

    sql = RECORD_SELECT
    if conditions:
        sql += " WHERE " + " AND ".join(conditions)
    sql += " ORDER BY r.id LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    with closing(_connect()) as connection:
        rows = connection.execute(sql, params).fetchall()
    return [dict(row) for row in rows]


def create_record(data: dict) -> dict:
    """Створити запис; повертає його разом з category_name."""
    with closing(_connect()) as connection:
        try:
            with connection:
                if not _category_exists(connection, data["category_id"]):
                    raise NotFoundError("Категорію не знайдено")
                cursor = connection.execute(
                    "INSERT INTO records (code, title, category_id, value, status) "
                    "VALUES (?, ?, ?, ?, ?)",
                    tuple(data[field] for field in RECORD_FIELDS),
                )
        except sqlite3.IntegrityError as exc:
            _raise_from_integrity(exc)
        return _fetch_record(connection, cursor.lastrowid)


def replace_record(record_id: int, data: dict) -> dict:
    """Повністю замінити змінювані поля запису; id не змінюється."""
    with closing(_connect()) as connection:
        try:
            with connection:
                if _fetch_record(connection, record_id) is None:
                    raise NotFoundError("Запис не знайдено")
                if not _category_exists(connection, data["category_id"]):
                    raise NotFoundError("Категорію не знайдено")
                connection.execute(
                    "UPDATE records SET code = ?, title = ?, category_id = ?, "
                    "value = ?, status = ? WHERE id = ?",
                    (*(data[field] for field in RECORD_FIELDS), record_id),
                )
        except sqlite3.IntegrityError as exc:
            _raise_from_integrity(exc)
        return _fetch_record(connection, record_id)


def delete_record(record_id: int) -> None:
    """Видалити запис; відсутній id дає NotFoundError."""
    with closing(_connect()) as connection, connection:
        cursor = connection.execute("DELETE FROM records WHERE id = ?", (record_id,))
        if cursor.rowcount == 0:
            raise NotFoundError("Запис не знайдено")


def create_records_bulk(items: Iterable[dict]) -> list[dict]:
    """Додати пакет записів атомарно: усі або жодного.

    Усі INSERT виконуються в одній транзакції. Будь-яка помилка
    (дублікат коду, неіснуюча категорія, порушення CHECK) скасовує
    весь пакет через rollback контекстного менеджера з’єднання.
    """
    items = list(items)
    codes = [item["code"] for item in items]
    if len(codes) != len(set(codes)):
        raise ConflictError("Пакет містить повторювані коди")

    with closing(_connect()) as connection:
        try:
            with connection:
                for category_id in {item["category_id"] for item in items}:
                    if not _category_exists(connection, category_id):
                        raise NotFoundError(f"Категорію {category_id} не знайдено")
                new_ids = []
                for item in items:
                    cursor = connection.execute(
                        "INSERT INTO records "
                        "(code, title, category_id, value, status) "
                        "VALUES (?, ?, ?, ?, ?)",
                        tuple(item[field] for field in RECORD_FIELDS),
                    )
                    new_ids.append(cursor.lastrowid)
        except sqlite3.IntegrityError as exc:
            _raise_from_integrity(exc)
        return [_fetch_record(connection, record_id) for record_id in new_ids]


def count_rows() -> tuple[int, int]:
    """Повернути кількість категорій і записів."""
    with closing(_connect()) as connection:
        (categories,) = connection.execute("SELECT COUNT(*) FROM categories").fetchone()
        (records,) = connection.execute("SELECT COUNT(*) FROM records").fetchone()
    return categories, records


def insert_seed(categories: list[dict], records: list[dict]) -> None:
    """Початкове заповнення: категорії з заданими id та записи в одній транзакції."""
    with closing(_connect()) as connection, connection:
        connection.executemany(
            "INSERT INTO categories (id, name) VALUES (?, ?)",
            [(item["id"], item["name"]) for item in categories],
        )
        connection.executemany(
            "INSERT INTO records (code, title, category_id, value, status) "
            "VALUES (?, ?, ?, ?, ?)",
            [tuple(item[field] for field in RECORD_FIELDS) for item in records],
        )
