"""CLI ЛР №4: перегляд запису NVD про вразливість і правило варіанта.

Приклади:
    python -m labs.lab04.main --cve CVE-2099-10001 --input labs/lab04/data/nvd_sample.json
    python -m labs.lab04.main --cve CVE-2021-44228
"""

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

from labs.lab04.analysis import VARIANT_COUNT, build_report, extract_record
from labs.lab04.api_client import FetchError, fetch_response
from shared.student import VARIANT_NUMBER

CVE_PATTERN = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}")


def cve_id_type(value: str) -> str:
    """Тип аргументу argparse: повний збіг з CVE-YYYY-NNNN+ (регістр важливий)."""
    if not CVE_PATTERN.fullmatch(value):
        raise argparse.ArgumentTypeError(
            f"некоректний ідентифікатор {value!r}, очікується CVE-РРРР-NNNN"
        )
    return value


def resolve_variant(number: Any) -> int:
    """Перевірити номер варіанта зі shared/student.py і звести до 1–15.

    У shared/student.py записано наскрізний номер у списку групи (16),
    а методичка має 15 варіантів, тому номер береться по колу: 16 → 1.
    Не int, bool або число < 1 — помилка.
    """
    if isinstance(number, bool) or not isinstance(number, int) or number < 1:
        raise ValueError("VARIANT_NUMBER має бути цілим додатним числом")
    return (number - 1) % VARIANT_COUNT + 1


def load_response(path: Path) -> Any:
    """Прочитати локальну відповідь NVD з UTF-8 JSON-файла."""
    return json.loads(Path(path).read_text(encoding="utf-8"))


def build_parser() -> argparse.ArgumentParser:
    """Створити парсер аргументів командного рядка."""
    parser = argparse.ArgumentParser(
        prog="python -m labs.lab04.main",
        description="Перегляд запису NVD про вразливість за правилом варіанта.",
    )
    parser.add_argument(
        "--cve", required=True, type=cve_id_type, help="ідентифікатор CVE"
    )
    parser.add_argument(
        "--input",
        type=Path,
        help="локальний JSON-файл з відповіддю NVD (без мережевих запитів)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Запустити утиліту; повертає код завершення 0, 1 або 2."""
    args = build_parser().parse_args(argv)

    try:
        variant = resolve_variant(VARIANT_NUMBER)
    except ValueError as exc:
        print(f"Помилка варіанта: {exc}", file=sys.stderr)
        return 2

    try:
        if args.input is not None:
            payload = load_response(args.input)
        else:
            payload = fetch_response(args.cve)
    except FileNotFoundError:
        print(f"Помилка: файл {args.input} не знайдено.", file=sys.stderr)
        return 1
    except json.JSONDecodeError as exc:
        print(
            f"Помилка: файл {args.input} містить некоректний JSON "
            f"(рядок {exc.lineno}, позиція {exc.colno}).",
            file=sys.stderr,
        )
        return 1
    except UnicodeDecodeError:
        print(f"Помилка: файл {args.input} не в кодуванні UTF-8.", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"Помилка читання файла {args.input}: {exc.strerror}.", file=sys.stderr)
        return 1
    except FetchError as exc:
        print(f"Помилка отримання даних з NVD: {exc}.", file=sys.stderr)
        return 1

    try:
        record = extract_record(payload, args.cve)
        report = build_report(record, args.cve, variant)
    except ValueError as exc:
        print(f"Помилка даних: {exc}.", file=sys.stderr)
        return 1

    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
