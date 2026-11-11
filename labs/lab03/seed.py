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
