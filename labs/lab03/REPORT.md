---
title: "Лабораторна робота №3"
subtitle: "Прикладні бібліотеки Python для побудови веб-застосунків"
author: "Виконав: Любченко Артур Сергійович, група КБ-208"
lang: uk
---

| | |
|---|---|
| Студент | Любченко Артур Сергійович |
| Група | КБ-208 |
| Варіант | 1 (номер у списку — 16; варіантів у методичці 15, тому 16 → 1) |
| Репозиторій | <https://github.com/Tusay1/CyberSec_Python_labs> |


## Мета роботи

Навчитися створювати Web API за допомогою FastAPI, визначати маршрути та користуватися
автоматичною документацією; опанувати створення SQLite-бази та виконання SQL-операцій із
параметризованими запитами; навчитися перевіряти вхідні дані, формувати моделі відповідей,
обробляти помилки й виконувати пов'язані зміни в межах транзакції.

## 1. Предметна область (варіант 1)

**Реєстр вразливостей вебзастосунку** — сервіс обліку знахідок перевірки вебзастосунку.

| Елемент | Значення |
|---|---|
| Таблиця `categories` | компонент застосунку: `web`, `api`, `database` |
| Таблиця `records` | знахідка аудиту (`code`, `title`, `category_id`, `value`, `status`) |
| `value` | навчальна оцінка небезпеки, `float`, від 0 до 10 включно |
| Одиниця вимірювання | `score` |
| Поріг | `7.0` — знахідки з `value >= 7.0` потребують першочергового опрацювання |
| `status` | стан опрацювання: `new`, `in_progress`, `done` |
| Назва запису | `Знахідка вебаудиту NN` |

Оцінка є навчальною і не розраховується за окремою стандартизованою методикою.

## 2. Структура проєкту

Посилання на роботу: <https://github.com/Tusay1/CyberSec_Python_labs/tree/main/labs/lab03>

```text
CyberSec_Python_labs/
├── requirements.txt
├── .gitignore               # labs/lab03/data/*.sqlite3 тощо
├── shared/student.py        # ПІБ, група, номер варіанта
└── labs/
    ├── __init__.py
    ├── lab01/  lab02/
    └── lab03/
        ├── __init__.py
        ├── main.py          # FastAPI-застосунок, lifespan, /ping, /student
        ├── database.py      # get_connection(), initialize_database()
        ├── schema.sql       # готова схема для варіантів 1–3
        ├── repository.py    # параметризовані SQL-запити, транзакції
        ├── schemas.py       # Pydantic-моделі
        ├── config.py        # варіант, одиниця, поріг, межі value
        ├── seed.py          # початкове заповнення з JSON
        ├── routers/
        │   ├── __init__.py
        │   ├── categories.py
        │   └── records.py
        ├── data/
        │   ├── seed.json    # у Git
        │   └── lab3.sqlite3 # створюється програмою, у Git не додається
        ├── README.md
        └── REPORT.md / REPORT.docx
```

Розподіл відповідальності: маршрути (`routers/`) лише приймають HTTP-запит і формують
відповідь; усі SQL-запити зосереджено в `repository.py`, який не залежить від FastAPI і
повідомляє про помилки власними винятками `NotFoundError` / `ConflictError`; шар API
перетворює їх на `404` / `409`. Моделі — у `schemas.py`.

## 3. Схема бази даних

Дві таблиці, зв'язок «один до багатьох»: одна категорія містить багато записів.

| Таблиця | Поле | Тип | Обмеження |
|---|---|---|---|
| `categories` | `id` | INTEGER | PRIMARY KEY, `id > 0` |
| | `name` | TEXT | NOT NULL, UNIQUE, довжина 2–40 після `trim` |
| `records` | `id` | INTEGER | PRIMARY KEY, `id > 0` |
| | `code` | TEXT | NOT NULL, UNIQUE, довжина 3–40 |
| | `title` | TEXT | NOT NULL, довжина 3–120 |
| | `category_id` | INTEGER | NOT NULL, ціле `> 0`, FOREIGN KEY → `categories(id)` ON DELETE RESTRICT |
| | `value` | REAL | NOT NULL, число від 0 до 10 |
| | `status` | TEXT | NOT NULL, `new` / `in_progress` / `done` |

Використаний SQL-скрипт (спільний початок + блок для варіантів 1–3 + спільне завершення):

**`labs/lab03/schema.sql`**

```sql
PRAGMA foreign_keys = ON;

BEGIN TRANSACTION;

CREATE TABLE IF NOT EXISTS categories (
    id INTEGER PRIMARY KEY CHECK (id > 0),
    name TEXT NOT NULL UNIQUE
        CHECK (length(trim(name)) BETWEEN 2 AND 40)
);

CREATE TABLE IF NOT EXISTS records (
    id INTEGER PRIMARY KEY CHECK (id > 0),
    code TEXT NOT NULL UNIQUE
        CHECK (length(trim(code)) BETWEEN 3 AND 40),
    title TEXT NOT NULL
        CHECK (length(trim(title)) BETWEEN 3 AND 120),
    category_id INTEGER NOT NULL
        CHECK (typeof(category_id) = 'integer' AND category_id > 0),
    value REAL NOT NULL
        CHECK (typeof(value) IN ('integer', 'real')
               AND value BETWEEN 0 AND 10),
    status TEXT NOT NULL
        CHECK (status IN ('new', 'in_progress', 'done')),
    FOREIGN KEY (category_id) REFERENCES categories(id)
        ON DELETE RESTRICT
);

COMMIT;
```


`PRAGMA foreign_keys = ON` виконується також у `get_connection()` для **кожного** нового
з'єднання, бо в SQLite ця настройка не зберігається у файлі бази.

## 4. Лістинг основних модулів

### 4.1. Створення бази

**`labs/lab03/database.py`**

```python
"""Створення файлу SQLite-бази та підключення до неї."""

import sqlite3
from contextlib import closing
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DATABASE_PATH = BASE_DIR / "data" / "lab3.sqlite3"
SCHEMA_PATH = BASE_DIR / "schema.sql"


def get_connection() -> sqlite3.Connection:
    """Відкрити з’єднання з перевіркою зовнішніх ключів."""
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DATABASE_PATH)
    try:
        connection.execute("PRAGMA foreign_keys = ON")
        return connection
    except sqlite3.Error:
        connection.close()
        raise


def initialize_database() -> None:
    """Створити таблиці за готовим SQL-скриптом."""
    script = SCHEMA_PATH.read_text(encoding="utf-8")
    with closing(get_connection()) as connection:
        try:
            connection.executescript(script)
        except sqlite3.Error:
            connection.rollback()
            raise


if __name__ == "__main__":
    initialize_database()
```


### 4.2. Параметри варіанта

**`labs/lab03/config.py`**

```python
"""Параметри варіанта 1: реєстр вразливостей вебзастосунку."""

VARIANT = 1
APP_TITLE = "Реєстр вразливостей вебзастосунку"
APP_DESCRIPTION = (
    "Сервіс обліку знахідок перевірки вебзастосунку (варіант 1). "
    "Категорія визначає компонент застосунку (web, api, database), "
    "`value` — навчальна оцінка небезпеки знахідки за шкалою 0–10 "
    "(одиниця вимірювання — `score`), `status` — стан опрацювання знахідки "
    "(`new`, `in_progress`, `done`). Поріг уваги — 7.0."
)
UNIT = "score"
THRESHOLD = 7.0
VALUE_MIN = 0.0
VALUE_MAX = 10.0
STATUSES = ("new", "in_progress", "done")
BULK_MAX_ITEMS = 100
```


### 4.3. SQL-операції (шар доступу до даних)

Усі значення передаються через параметри `?`. Динамічний фільтр у `list_records()`
збирається лише з наперед визначених SQL-фрагментів, а значення йдуть окремим списком.
Пошук підрядка — `instr(title, ?) > 0`, тому `%` і `_` не є шаблонами.
Пакетне додавання (`create_records_bulk`) виконує всі `INSERT` в одній транзакції
(`with connection:`): будь-яка помилка скасовує весь пакет.

**`labs/lab03/repository.py`**

```python
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
```


### 4.4. Pydantic-моделі

**`labs/lab03/schemas.py`**

```python
"""Pydantic-моделі запитів і відповідей API."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from labs.lab03.config import VALUE_MAX, VALUE_MIN

Status = Literal["new", "in_progress", "done"]


class CategoryCreate(BaseModel):
    """Тіло запиту на створення категорії."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    name: str = Field(min_length=2, max_length=40, examples=["web"])


class CategoryRead(BaseModel):
    """Категорія у відповіді API."""

    id: int = Field(gt=0)
    name: str


class RecordCreate(BaseModel):
    """Тіло запиту на створення знахідки (id задає база)."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    code: str = Field(min_length=3, max_length=40, examples=["V01-TEST"])
    title: str = Field(min_length=3, max_length=120, examples=["Навчальна знахідка"])
    category_id: int = Field(gt=0, strict=True, examples=[1])
    value: float = Field(
        ge=VALUE_MIN,
        le=VALUE_MAX,
        allow_inf_nan=False,
        strict=True,
        description="Навчальна оцінка небезпеки, score 0–10",
        examples=[7.5],
    )
    status: Status


class RecordReplace(RecordCreate):
    """Повна заміна всіх змінюваних полів знахідки (PUT)."""


class RecordRead(RecordCreate):
    """Знахідка у відповіді API разом з id та назвою категорії."""

    id: int = Field(gt=0)
    category_name: str


class StudentRead(BaseModel):
    """Дані студента зі shared/student.py."""

    student_name: str
    group_name: str
    variant_number: int
```


### 4.5. Маршрути

**`labs/lab03/routers/categories.py`**

```python
"""Маршрути для категорій."""

from typing import Annotated

from fastapi import APIRouter, HTTPException, Path, status

from labs.lab03 import repository
from labs.lab03.repository import ConflictError, NotFoundError
from labs.lab03.schemas import CategoryCreate, CategoryRead

router = APIRouter(prefix="/categories", tags=["categories"])

CategoryId = Annotated[int, Path(gt=0, description="Додатний id категорії")]


@router.get("", response_model=list[CategoryRead], summary="Список категорій")
def list_categories() -> list[dict]:
    """Повернути всі категорії за зростанням id."""
    return repository.list_categories()


@router.post(
    "",
    response_model=CategoryRead,
    status_code=status.HTTP_201_CREATED,
    summary="Створити категорію",
    responses={409: {"description": "Категорія з такою назвою вже існує"}},
)
def create_category(payload: CategoryCreate) -> dict:
    """Створити нову категорію з унікальною назвою."""
    try:
        return repository.create_category(payload.name)
    except ConflictError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=str(exc)) from exc


@router.delete(
    "/{category_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Видалити порожню категорію",
    responses={
        404: {"description": "Категорію не знайдено"},
        409: {"description": "Категорія містить записи"},
    },
)
def delete_category(category_id: CategoryId) -> None:
    """Видалити категорію, якщо в ній немає записів."""
    try:
        repository.delete_category(category_id)
    except NotFoundError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ConflictError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=str(exc)) from exc
```


**`labs/lab03/routers/records.py`**

```python
"""Маршрути для записів (знахідок вебаудиту)."""

from typing import Annotated

from fastapi import APIRouter, Body, HTTPException, Path, Query, status

from labs.lab03 import repository
from labs.lab03.config import BULK_MAX_ITEMS, VALUE_MAX, VALUE_MIN
from labs.lab03.repository import ConflictError, NotFoundError
from labs.lab03.schemas import RecordCreate, RecordRead, RecordReplace, Status

router = APIRouter(prefix="/records", tags=["records"])

RecordId = Annotated[int, Path(gt=0, description="Додатний id запису")]

NOT_FOUND = {404: {"description": "Запис або категорію не знайдено"}}
CONFLICT = {409: {"description": "Запис з таким code уже існує"}}


def _to_http(exc: Exception) -> HTTPException:
    """Перетворити виняток шару даних на HTTP-помилку."""
    if isinstance(exc, NotFoundError):
        return HTTPException(status.HTTP_404_NOT_FOUND, detail=str(exc))
    return HTTPException(status.HTTP_409_CONFLICT, detail=str(exc))


@router.get("", response_model=list[RecordRead], summary="Список записів з фільтрами")
def list_records(
    category_id: Annotated[
        int | None, Query(gt=0, description="Лише записи цієї категорії")
    ] = None,
    record_status: Annotated[
        Status | None, Query(alias="status", description="Лише записи з цим статусом")
    ] = None,
    min_value: Annotated[
        float | None,
        Query(
            ge=VALUE_MIN,
            le=VALUE_MAX,
            allow_inf_nan=False,
            description="value >= min_value (score 0–10)",
        ),
    ] = None,
    q: Annotated[
        str | None,
        Query(
            min_length=1,
            max_length=120,
            description="Буквальний підрядок у title з урахуванням регістру",
        ),
    ] = None,
    limit: Annotated[int, Query(ge=1, le=100, description="Максимум записів")] = 20,
    offset: Annotated[int, Query(ge=0, description="Скільки записів пропустити")] = 0,
) -> list[dict]:
    """Повернути записи, відсортовані за id; фільтри об’єднуються через AND."""
    return repository.list_records(
        category_id=category_id,
        status=record_status,
        min_value=min_value,
        q=q,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/{record_id}",
    response_model=RecordRead,
    summary="Отримати запис",
    responses=NOT_FOUND,
)
def get_record(record_id: RecordId) -> dict:
    """Повернути один запис за id."""
    record = repository.get_record(record_id)
    if record is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Запис не знайдено")
    return record


@router.post(
    "",
    response_model=RecordRead,
    status_code=status.HTTP_201_CREATED,
    summary="Створити запис",
    responses={**NOT_FOUND, **CONFLICT},
)
def create_record(payload: RecordCreate) -> dict:
    """Створити запис; id генерує база."""
    try:
        return repository.create_record(payload.model_dump())
    except (NotFoundError, ConflictError) as exc:
        raise _to_http(exc) from exc


@router.post(
    "/bulk",
    response_model=list[RecordRead],
    status_code=status.HTTP_201_CREATED,
    summary="Пакетне створення записів (атомарно)",
    responses={**NOT_FOUND, **CONFLICT},
)
def create_records_bulk(
    payload: Annotated[
        list[RecordCreate],
        Body(min_length=1, max_length=BULK_MAX_ITEMS, description="JSON-масив записів"),
    ],
) -> list[dict]:
    """Створити 1–100 записів в одній транзакції: усі або жодного."""
    try:
        return repository.create_records_bulk(item.model_dump() for item in payload)
    except (NotFoundError, ConflictError) as exc:
        raise _to_http(exc) from exc


@router.put(
    "/{record_id}",
    response_model=RecordRead,
    summary="Повна заміна змінюваних полів запису",
    responses={**NOT_FOUND, **CONFLICT},
)
def replace_record(record_id: RecordId, payload: RecordReplace) -> dict:
    """Замінити всі п’ять змінюваних полів; id залишається незмінним."""
    try:
        return repository.replace_record(record_id, payload.model_dump())
    except (NotFoundError, ConflictError) as exc:
        raise _to_http(exc) from exc


@router.delete(
    "/{record_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Видалити запис",
    responses=NOT_FOUND,
)
def delete_record(record_id: RecordId) -> None:
    """Видалити запис за id."""
    try:
        repository.delete_record(record_id)
    except NotFoundError as exc:
        raise _to_http(exc) from exc
```


### 4.6. Застосунок

**`labs/lab03/main.py`**

```python
"""FastAPI-застосунок ЛР №3: реєстр вразливостей вебзастосунку (варіант 1)."""

import logging
import sqlite3
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse

from labs.lab03.config import APP_DESCRIPTION, APP_TITLE
from labs.lab03.database import initialize_database
from labs.lab03.routers import categories, records
from labs.lab03.schemas import StudentRead
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

logger = logging.getLogger("labs.lab03")


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    """Створити відсутні таблиці під час запуску (без заповнення даними)."""
    initialize_database()
    yield


app = FastAPI(
    title=APP_TITLE,
    description=APP_DESCRIPTION,
    version="1.0.0",
    lifespan=lifespan,
)
app.include_router(categories.router)
app.include_router(records.router)


@app.exception_handler(sqlite3.Error)
def handle_database_error(_: Request, exc: sqlite3.Error) -> JSONResponse:
    """Записати технічну помилку в журнал і повернути клієнту загальне повідомлення."""
    logger.error("Помилка SQLite: %s", exc, exc_info=exc)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Внутрішня помилка роботи з базою даних"},
    )


@app.get("/ping", tags=["service"], summary="Перевірка доступності API")
def ping() -> dict[str, str]:
    """Повернути статус ok."""
    return {"status": "ok"}


@app.get(
    "/student",
    response_model=StudentRead,
    tags=["service"],
    summary="Дані студента",
)
def student() -> dict:
    """Повернути ПІБ, групу та номер варіанта зі shared/student.py."""
    return {
        "student_name": STUDENT_NAME,
        "group_name": GROUP_NAME,
        "variant_number": VARIANT_NUMBER,
    }
```


### 4.7. Початкове заповнення

**`labs/lab03/seed.py`**

```python
"""Початкове заповнення бази з data/seed.json в одній транзакції."""

import json
import logging
import sqlite3
import sys
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from labs.lab03 import repository
from labs.lab03.database import BASE_DIR, initialize_database
from labs.lab03.schemas import RecordCreate

SEED_PATH = BASE_DIR / "data" / "seed.json"
EXPECTED_CATEGORIES = 3
EXPECTED_RECORDS = 8

logger = logging.getLogger(__name__)


class SeedCategory(BaseModel):
    """Категорія у початкових даних (id задається явно)."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    id: int = Field(gt=0, strict=True)
    name: str = Field(min_length=2, max_length=40)


class SeedData(BaseModel):
    """Структура seed.json: два масиви — categories і records."""

    model_config = ConfigDict(extra="forbid")

    categories: list[SeedCategory] = Field(
        min_length=EXPECTED_CATEGORIES, max_length=EXPECTED_CATEGORIES
    )
    records: list[RecordCreate] = Field(
        min_length=EXPECTED_RECORDS, max_length=EXPECTED_RECORDS
    )


def load_seed(path: Path = SEED_PATH) -> SeedData:
    """Прочитати JSON і перевірити його структуру та взаємні посилання."""
    raw = json.loads(path.read_text(encoding="utf-8"))
    data = SeedData.model_validate(raw)

    ids = [category.id for category in data.categories]
    names = [category.name for category in data.categories]
    codes = [record.code for record in data.records]
    if len(set(ids)) != len(ids) or len(set(names)) != len(names):
        raise ValueError("Категорії мають повторювані id або назви")
    if len(set(codes)) != len(codes):
        raise ValueError("Записи мають повторювані коди")
    unknown = {record.category_id for record in data.records} - set(ids)
    if unknown:
        raise ValueError(
            f"Записи посилаються на неіснуючі категорії: {sorted(unknown)}"
        )
    return data


def seed() -> int:
    """Заповнити порожню базу; повертає код завершення."""
    try:
        data = load_seed()
    except FileNotFoundError:
        print(f"Помилка: файл {SEED_PATH.name} не знайдено.", file=sys.stderr)
        return 1
    except json.JSONDecodeError as exc:
        print(f"Помилка: некоректний JSON у seed.json ({exc.msg}).", file=sys.stderr)
        return 1
    except (ValidationError, ValueError) as exc:
        print(f"Помилка: некоректні початкові дані.\n{exc}", file=sys.stderr)
        return 1

    try:
        initialize_database()
        categories, records = repository.count_rows()
        if categories or records:
            print(
                "База вже містить дані "
                f"(категорій: {categories}, записів: {records}). "
                "Початкове заповнення пропущено, дані не змінено."
            )
            return 0
        repository.insert_seed(
            [category.model_dump() for category in data.categories],
            [record.model_dump() for record in data.records],
        )
    except sqlite3.IntegrityError:
        logger.exception("Порушення обмежень під час заповнення")
        print(
            "Помилка: початкові дані порушують обмеження бази. "
            "Весь пакет скасовано, база не змінена.",
            file=sys.stderr,
        )
        return 1
    except sqlite3.Error:
        logger.exception("Помилка SQLite під час заповнення")
        print("Помилка роботи з базою даних. Зміни скасовано.", file=sys.stderr)
        return 1

    categories, records = repository.count_rows()
    print(f"Базу заповнено: категорій — {categories}, записів — {records}.")
    return 0


if __name__ == "__main__":
    logging.basicConfig(level=logging.WARNING)
    raise SystemExit(seed())
```


## 5. Початкові дані

Записи побудовано за правилом розділу 5.1 методички: `code = V01-NN`,
`title = "Знахідка вебаудиту NN"`, значення `[9.1, 5.4, 3.2, 7.5, 8.0, 2.4, 6.3, 7.1]`.

Категорії: `1` — `web`, `2` — `api`, `3` — `database`.

| № | code | title | category_id | value | status |
|---|---|---|---|---|---|
| 1 | V01-01 | Знахідка вебаудиту 01 | 1 (web) | 9.1 | new |
| 2 | V01-02 | Знахідка вебаудиту 02 | 2 (api) | 5.4 | in_progress |
| 3 | V01-03 | Знахідка вебаудиту 03 | 3 (database) | 3.2 | done |
| 4 | V01-04 | Знахідка вебаудиту 04 | 1 (web) | 7.5 | new |
| 5 | V01-05 | Знахідка вебаудиту 05 | 2 (api) | 8.0 | done |
| 6 | V01-06 | Знахідка вебаудиту 06 | 3 (database) | 2.4 | in_progress |
| 7 | V01-07 | Знахідка вебаудиту 07 | 1 (web) | 6.3 | done |
| 8 | V01-08 | Знахідка вебаудиту 08 | 2 (api) | 7.1 | new |

**`labs/lab03/data/seed.json`**

```json
{
  "categories": [
    {
      "id": 1,
      "name": "web"
    },
    {
      "id": 2,
      "name": "api"
    },
    {
      "id": 3,
      "name": "database"
    }
  ],
  "records": [
    {
      "code": "V01-01",
      "title": "Знахідка вебаудиту 01",
      "category_id": 1,
      "value": 9.1,
      "status": "new"
    },
    {
      "code": "V01-02",
      "title": "Знахідка вебаудиту 02",
      "category_id": 2,
      "value": 5.4,
      "status": "in_progress"
    },
    {
      "code": "V01-03",
      "title": "Знахідка вебаудиту 03",
      "category_id": 3,
      "value": 3.2,
      "status": "done"
    },
    {
      "code": "V01-04",
      "title": "Знахідка вебаудиту 04",
      "category_id": 1,
      "value": 7.5,
      "status": "new"
    },
    {
      "code": "V01-05",
      "title": "Знахідка вебаудиту 05",
      "category_id": 2,
      "value": 8.0,
      "status": "done"
    },
    {
      "code": "V01-06",
      "title": "Знахідка вебаудиту 06",
      "category_id": 3,
      "value": 2.4,
      "status": "in_progress"
    },
    {
      "code": "V01-07",
      "title": "Знахідка вебаудиту 07",
      "category_id": 1,
      "value": 6.3,
      "status": "done"
    },
    {
      "code": "V01-08",
      "title": "Знахідка вебаудиту 08",
      "category_id": 2,
      "value": 7.1,
      "status": "new"
    }
  ]
}
```


## 6. Результати перевірок (завдання 3)

Команди запуску:

```bash
python -m labs.lab03.seed
uvicorn labs.lab03.main:app --reload --host 127.0.0.1 --port 8000
```

Підсумок сценаріїв:

| № | Сценарій | Результат |
|---|---|---|
| 1 | Початкове заповнення та повторний запуск `seed.py` | 3 категорії, 8 записів; повторний запуск: «пропущено, дані не змінено» |
| 2 | `GET /ping`, `/student`, `/categories` | `200`, правильні дані |
| 3 | Створення, читання, `PUT`, видалення запису | `201` → `200` → `200` → `204` → `404` |
| 4 | Фільтри, два фільтри, `limit`/`offset` | вибірки відповідають умовам, порядок за `id` стабільний |
| 5 | Від'ємне `value`, порожній `title`, статус `closed`, `limit=0` | `422`, кількість записів не змінилась (8) |
| 6 | `value = 10.5` | `422`, база не змінилась |
| 7 | Неіснуючий `record_id`; запис з `category_id = 99` | `404` |
| 8 | Повторний `code` `V01-01`; повторна категорія `web` | `409`, запис `V01-01` не змінився |
| 9 | Видалення непорожньої / порожньої категорії | `409` / `204` |
| 10 | Коректний пакет із двох записів | `201`, записів 8 → 10 |
| 11 | Пакет: новий + дублікат `V01-01` | `409`, записів 10 → 10, `V01-ROLLBACK` відсутній |
| 12 | Пакет: новий + категорія 42 | `404`, записів 10 → 10 |
| 13 | `q=' OR 1=1 --` | `200`, `[]` — рядок оброблено як дані, записи не змінились |
| 14 | Перезапуск сервера | записи 9 і 10 доступні після перезапуску |
| + | Поле `id` у тілі; `value: true`; `record_id = 0` | `422` (`extra="forbid"`, `strict`, `gt=0`) |

Повний журнал запитів і відповідей (отримано `curl` на запущеному сервері):

#### 1. Початкове заповнення та повторний запуск seed.py

```text
$ .venv/bin/python -m labs.lab03.seed
Базу заповнено: категорій — 3, записів — 8.


$ .venv/bin/python -m labs.lab03.seed
База вже містить дані (категорій: 3, записів: 8). Початкове заповнення пропущено, дані не змінено.
```

#### 2. /ping, /student, /categories

```text
$ c http://127.0.0.1:8000/ping
{"status":"ok"}
[HTTP 200]

$ c http://127.0.0.1:8000/student
{"student_name":"Любченко Артур Сергійович","group_name":"КБ-208","variant_number":16}
[HTTP 200]

$ c http://127.0.0.1:8000/categories
[{"id":1,"name":"web"},{"id":2,"name":"api"},{"id":3,"name":"database"}]
[HTTP 200]
```

#### 3. CRUD одного запису

```text
$ c -X POST http://127.0.0.1:8000/records -H Content-Type:application/json -d {"code":"V01-TEST","title":"Навчальна знахідка","category_id":1,"value":7.5,"status":"new"}
{"code":"V01-TEST","title":"Навчальна знахідка","category_id":1,"value":7.5,"status":"new","id":9,"category_name":"web"}
[HTTP 201]

$ c http://127.0.0.1:8000/records/9
{"code":"V01-TEST","title":"Навчальна знахідка","category_id":1,"value":7.5,"status":"new","id":9,"category_name":"web"}
[HTTP 200]

$ c -X PUT http://127.0.0.1:8000/records/9 -H Content-Type:application/json -d {"code":"V01-TEST","title":"Навчальна знахідка (виправлено)","category_id":2,"value":8.2,"status":"in_progress"}
{"code":"V01-TEST","title":"Навчальна знахідка (виправлено)","category_id":2,"value":8.2,"status":"in_progress","id":9,"category_name":"api"}
[HTTP 200]

$ c -X DELETE http://127.0.0.1:8000/records/9

[HTTP 204]

$ c http://127.0.0.1:8000/records/9
{"detail":"Запис не знайдено"}
[HTTP 404]
```

#### 4. Фільтри, два фільтри, limit і offset

```text
$ c http://127.0.0.1:8000/records?category_id=1
[{"code":"V01-01","title":"Знахідка вебаудиту 01","category_id":1,"value":9.1,"status":"new","id":1,"category_name":"web"},{"code":"V01-04","title":"Знахідка вебаудиту 04","category_id":1,"value":7.5,"status":"new","id":4,"category_name":"web"},{"code":"V01-07","title":"Знахідка вебаудиту 07","category_id":1,"value":6.3,"status":"done","id":7,"category_name":"web"}]
[HTTP 200]

$ c http://127.0.0.1:8000/records?category_id=1&status=new
[{"code":"V01-01","title":"Знахідка вебаудиту 01","category_id":1,"value":9.1,"status":"new","id":1,"category_name":"web"},{"code":"V01-04","title":"Знахідка вебаудиту 04","category_id":1,"value":7.5,"status":"new","id":4,"category_name":"web"}]
[HTTP 200]

$ c http://127.0.0.1:8000/records?min_value=7.0&limit=2&offset=0
[{"code":"V01-01","title":"Знахідка вебаудиту 01","category_id":1,"value":9.1,"status":"new","id":1,"category_name":"web"},{"code":"V01-04","title":"Знахідка вебаудиту 04","category_id":1,"value":7.5,"status":"new","id":4,"category_name":"web"}]
[HTTP 200]

$ c http://127.0.0.1:8000/records?min_value=7.0&limit=2&offset=2
[{"code":"V01-05","title":"Знахідка вебаудиту 05","category_id":2,"value":8.0,"status":"done","id":5,"category_name":"api"},{"code":"V01-08","title":"Знахідка вебаудиту 08","category_id":2,"value":7.1,"status":"new","id":8,"category_name":"api"}]
[HTTP 200]

$ c http://127.0.0.1:8000/records?q=%2005
[{"code":"V01-05","title":"Знахідка вебаудиту 05","category_id":2,"value":8.0,"status":"done","id":5,"category_name":"api"}]
[HTTP 200]
```

#### 5. Від'ємне value, порожній title, недозволений статус, limit=0

```text
[кількість записів у базі: 8]

$ c -X POST http://127.0.0.1:8000/records -H Content-Type:application/json -d {"code":"V01-BAD1","title":"Тест","category_id":1,"value":-1,"status":"new"}
{"detail":[{"type":"greater_than_equal","loc":["body","value"],"msg":"Input should be greater than or equal to 0","input":-1,"ctx":{"ge":0.0}}]}
[HTTP 422]

$ c -X POST http://127.0.0.1:8000/records -H Content-Type:application/json -d {"code":"V01-BAD2","title":"   ","category_id":1,"value":5,"status":"new"}
{"detail":[{"type":"string_too_short","loc":["body","title"],"msg":"String should have at least 3 characters","input":"   ","ctx":{"min_length":3}}]}
[HTTP 422]

$ c -X POST http://127.0.0.1:8000/records -H Content-Type:application/json -d {"code":"V01-BAD3","title":"Тест статусу","category_id":1,"value":5,"status":"closed"}
{"detail":[{"type":"literal_error","loc":["body","status"],"msg":"Input should be 'new', 'in_progress' or 'done'","input":"closed","ctx":{"expected":"'new', 'in_progress' or 'done'"}}]}
[HTTP 422]

$ c http://127.0.0.1:8000/records?limit=0
{"detail":[{"type":"greater_than_equal","loc":["query","limit"],"msg":"Input should be greater than or equal to 1","input":"0","ctx":{"ge":1}}]}
[HTTP 422]
[кількість записів у базі: 8]
```

#### 6. Значення за межами верхньої межі

```text
$ c -X POST http://127.0.0.1:8000/records -H Content-Type:application/json -d {"code":"V01-BAD4","title":"Завелика оцінка","category_id":1,"value":10.5,"status":"new"}
{"detail":[{"type":"less_than_equal","loc":["body","value"],"msg":"Input should be less than or equal to 10","input":10.5,"ctx":{"le":10.0}}]}
[HTTP 422]
[кількість записів у базі: 8]
```

#### 7. Неіснуючий record_id; запис з неіснуючою категорією

```text
$ c http://127.0.0.1:8000/records/999
{"detail":"Запис не знайдено"}
[HTTP 404]

$ c -X PUT http://127.0.0.1:8000/records/999 -H Content-Type:application/json -d {"code":"V01-X","title":"Нема такого","category_id":1,"value":1,"status":"new"}
{"detail":"Запис не знайдено"}
[HTTP 404]

$ c -X DELETE http://127.0.0.1:8000/records/999
{"detail":"Запис не знайдено"}
[HTTP 404]

$ c -X POST http://127.0.0.1:8000/records -H Content-Type:application/json -d {"code":"V01-NOCAT","title":"Без категорії","category_id":99,"value":5,"status":"new"}
{"detail":"Категорію не знайдено"}
[HTTP 404]
```

#### 8. Повторний code і повторна назва категорії

```text
$ c -X POST http://127.0.0.1:8000/records -H Content-Type:application/json -d {"code":"V01-01","title":"Дублікат коду","category_id":1,"value":5,"status":"new"}
{"detail":"Запис з таким кодом уже існує"}
[HTTP 409]

$ c -X POST http://127.0.0.1:8000/categories -H Content-Type:application/json -d {"name":"web"}
{"detail":"Категорія з такою назвою вже існує"}
[HTTP 409]

$ c http://127.0.0.1:8000/records/1
{"code":"V01-01","title":"Знахідка вебаудиту 01","category_id":1,"value":9.1,"status":"new","id":1,"category_name":"web"}
[HTTP 200]
```

#### 9. Видалення непорожньої та порожньої категорій

```text
$ c -X DELETE http://127.0.0.1:8000/categories/1
{"detail":"Категорія містить записи"}
[HTTP 409]

$ c -X POST http://127.0.0.1:8000/categories -H Content-Type:application/json -d {"name":"frontend"}
{"id":4,"name":"frontend"}
[HTTP 201]

$ c -X DELETE http://127.0.0.1:8000/categories/4

[HTTP 204]

$ c http://127.0.0.1:8000/categories
[{"id":1,"name":"web"},{"id":2,"name":"api"},{"id":3,"name":"database"}]
[HTTP 200]
```

#### 10. Коректний пакет із двох записів

```text
[кількість записів у базі: 8]

$ c -X POST http://127.0.0.1:8000/records/bulk -H Content-Type:application/json -d [{"code":"V01-B1","title":"Пакетна знахідка 1","category_id":1,"value":6.5,"status":"new"},{"code":"V01-B2","title":"Пакетна знахідка 2","category_id":3,"value":8.8,"status":"done"}]
[{"code":"V01-B1","title":"Пакетна знахідка 1","category_id":1,"value":6.5,"status":"new","id":9,"category_name":"web"},{"code":"V01-B2","title":"Пакетна знахідка 2","category_id":3,"value":8.8,"status":"done","id":10,"category_name":"database"}]
[HTTP 201]
[кількість записів у базі: 10]
```

#### 11. Пакет: перший новий, другий має code з бази

```text
[кількість записів у базі: 10]

$ c -X POST http://127.0.0.1:8000/records/bulk -H Content-Type:application/json -d [{"code":"V01-ROLLBACK","title":"Перший елемент","category_id":1,"value":4.0,"status":"new"},{"code":"V01-01","title":"Дублікат коду","category_id":2,"value":5.0,"status":"new"}]
{"detail":"Запис з таким кодом уже існує"}
[HTTP 409]
[кількість записів у базі: 10]

$ c http://127.0.0.1:8000/records?q=%D0%9F%D0%B5%D1%80%D1%88%D0%B8%D0%B9
[]
[HTTP 200]
```

#### 12. Пакет: перший новий, другий з неіснуючою категорією

```text
[кількість записів у базі: 10]

$ c -X POST http://127.0.0.1:8000/records/bulk -H Content-Type:application/json -d [{"code":"V01-ROLLBACK2","title":"Перший елемент","category_id":1,"value":4.0,"status":"new"},{"code":"V01-NEWCAT","title":"Неіснуюча категорія","category_id":42,"value":5.0,"status":"new"}]
{"detail":"Категорію 42 не знайдено"}
[HTTP 404]
[кількість записів у базі: 10]
```

#### 13. Пошук q=' OR 1=1 --

```text
[кількість записів у базі: 10]

$ c http://127.0.0.1:8000/records?q=%27%20OR%201%3D1%20--
[]
[HTTP 200]
[кількість записів у базі: 10]
```

#### 14. Створення запису та перезапуск сервера

```text
$ (сервер зупинено і запущено знову: uvicorn labs.lab03.main:app)
$ curl -s http://127.0.0.1:8000/records/9
{"code":"V01-B1","title":"Пакетна знахідка 1","category_id":1,"value":6.5,"status":"new","id":9,"category_name":"web"}
[HTTP 200]
$ curl -s http://127.0.0.1:8000/records/10
{"code":"V01-B2","title":"Пакетна знахідка 2","category_id":3,"value":8.8,"status":"done","id":10,"category_name":"database"}
[HTTP 200]
```

#### Додатково: зайве поле id у тілі, value=true, record_id=0

```text
$ curl -X POST /records -d {"id":5,"code":"V01-ID",...}
{"detail":[{"type":"extra_forbidden","loc":["body","id"],"msg":"Extra inputs are not permitted","input":5}]}
[HTTP 422]
$ curl -X POST /records -d {"value":true,...}
{"detail":[{"type":"float_type","loc":["body","value"],"msg":"Input should be a valid number","input":true}]}
[HTTP 422]
$ curl /records/0
{"detail":[{"type":"greater_than","loc":["path","record_id"],"msg":"Input should be greater than 0","input":"0","ctx":{"gt":0}}]}
[HTTP 422]
```


## 7. Демонстрація скасування пакета

Сценарій 11 (другий елемент має `code`, що вже є в базі):

```text
[кількість записів у базі: 10]
POST /records/bulk  [{"code":"V01-ROLLBACK",...}, {"code":"V01-01",...}]
{"detail":"Запис з таким кодом уже існує"}   [HTTP 409]
[кількість записів у базі: 10]
GET /records?q=Перший  →  []                    [HTTP 200]
```

Перший елемент `V01-ROLLBACK` встиг виконати `INSERT`, але другий порушив `UNIQUE`,
`sqlite3.IntegrityError` перервав блок `with connection:`, і контекстний менеджер виконав
`rollback()` — у базі не збережено жодного елемента пакета. Сценарій 12 (неіснуюча
категорія) так само дав `404` без змін: 10 записів до та після запиту.

## 8. Перевірка стилю (Ruff)

```text
$ ruff check labs/lab03
All checks passed!
$ ruff format --check labs/lab03
11 files already formatted
```

Перед виправленням Ruff знайшов 3 зауваження `SIM117` (вкладені `with`) у `repository.py`
та 2 файли з неправильним форматуванням; їх виправлено через `ruff check --fix` і
`ruff format`, після чого перевірки проходять.

Перевірка всього репозиторію:

```text
$ ruff check .
labs/lab01/task3.py:41:30: DTZ005 `datetime.datetime.now()` called without a `tz` argument
labs/lab02/task2.py:58:12: DTZ007 Naive datetime constructed using `datetime.datetime.strptime()` without %z
Found 2 errors.
$ ruff format --check .
unformatted: File would be reformatted
1 file would be reformatted, 33 files already formatted
```

Залишкові зауваження стосуються файлів ЛР №1 і ЛР №2 (`labs/lab01/task3.py`,
`labs/lab02/task2.py`, `labs/lab02/task1.py`), а не коду ЛР №3.

## 9. Скріншоти

_[Скріншот 1: Swagger UI — <http://127.0.0.1:8000/docs>, список маршрутів]_

_[Скріншот 2: виконання `POST /records` у Swagger UI, відповідь 201]_

_[Скріншот 3: виконання `POST /records/bulk` з дублікатом, відповідь 409]_

_[Скріншот 4: термінал — `python -m labs.lab03.seed` (перший і повторний запуск)]_

## 10. Висновки

У роботі реалізовано Web API «Реєстр вразливостей вебзастосунку» на FastAPI з базою
SQLite без ORM. Схему створює готовий SQL-скрипт; початкові дані (3 категорії, 8 записів)
завантажуються з JSON в одній транзакції, повторне заповнення не створює дублікатів.

**Перевірка даних** відбувається на двох рівнях: Pydantic-моделі (`extra="forbid"`,
обрізання пробілів, довжини рядків, `value` 0–10 без `inf`/`NaN`/`bool`, статус з
`Literal`, додатні `id`, розмір пакета 1–100) повертають `422` ще до звернення до бази;
обмеження `NOT NULL`, `UNIQUE`, `CHECK` і `FOREIGN KEY` у самій базі гарантують
узгодженість незалежно від того, звідки виконується запит.

**Захист від SQL-ін'єкцій** забезпечують параметризовані запити: значення передаються
окремо від SQL-тексту, тому рядок `' OR 1=1 --` шукається як звичайний текст.
Динамічні фільтри складаються лише з фіксованих фрагментів коду.

**Цілісність бази** забезпечують транзакції (`with connection:` — `commit` за успіху,
`rollback` за винятку), `PRAGMA foreign_keys = ON` для кожного з'єднання та
`ON DELETE RESTRICT`. Пакетне додавання атомарне: помилка в будь-якому елементі
скасовує весь пакет. Технічні помилки SQLite записуються в журнал, а клієнт отримує
загальне повідомлення без SQL і шляхів до файлів.

## Відповіді на контрольні питання

1. **Таблиця** — набір однотипних об'єктів, **запис** — рядок (один об'єкт), **поле** — стовпець
   (властивість). `categories` — компоненти вебзастосунку, `records` — знахідки аудиту; зв'язок «один до багатьох».
2. **Первинний ключ** однозначно ідентифікує запис; **зовнішній** посилається на первинний ключ
   іншої таблиці. Запис із неіснуючою категорією відхиляється: API повертає `404`, а база
   (за ввімкненого `foreign_keys`) — `IntegrityError: FOREIGN KEY constraint failed`.
3. CSV/JSON — просто файли з даними; SQLite додає типи, обмеження, індекси й унікальність,
   SQL-пошук і фільтрацію, транзакції та зовнішні ключі.
4. Параметр `?` передає значення окремо від тексту SQL — воно не може змінити структуру
   запиту. Назви таблиць і полів — частина структури запиту, тому їх не можна параметризувати.
5. Щоб пакет зберігався повністю або не зберігався зовсім. З `commit()` після кожного запису
   частина пакета залишилася б у базі після помилки.
6. `with connection:` підтверджує транзакцію за успіху або скасовує за винятку, але не закриває
   з'єднання — тому використовується `closing(...)`.
7. `GET` → `SELECT`, `POST` → `INSERT`, `PUT` → `UPDATE`, `DELETE` → `DELETE`. `PUT` — повна
   заміна ресурсу, тому вимагає всіх змінюваних полів.
8. Шляху: `record_id` у `/records/{record_id}`; запиту: `category_id`, `status`, `limit` у
   `GET /records?...`; тіло: JSON у `POST /records`, `PUT /records/{id}`, `POST /records/bulk`.
9. Типи, довжини, діапазони, допустимі статуси, відсутність зайвих полів.
10. `response_model` задає і документує структуру відповіді та фільтрує зайві поля.
11. `id` генерує база; клієнт не повинен впливати на ідентифікатори.
12. `201` — створення запису, `204` — видалення, `404` — немає запису/категорії, `409` —
    дублікат `code` або непорожня категорія, `422` — `value=-1`. `204 No Content` за
    визначенням не має тіла.
13. JSON і SQL-скрипт дозволяють відтворити базу; робочий `.sqlite3` — змінний бінарний
    результат роботи програми, який може містити тимчасові дані.
