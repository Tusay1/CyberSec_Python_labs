---
title: "Лабораторна робота №4"
subtitle: "Інтеграція із зовнішніми Web API та автоматизоване тестування Python-коду"
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

Навчитися отримувати відомості про вразливості через Web API, перевіряти відповіді та
обробляти мережеві помилки; відокремлювати отримання даних від їх аналізу; писати
відтворювані тести за допомогою pytest для звичайних, граничних і помилкових випадків.

## 1. Варіант, правило відбору та метрика CVSS

| Варіант | Напрям відбору | Поріг `T` | Поле `field` | Значення `expected` |
|---|---|---|---|---|
| 1 | Мережевий вектор атаки | 7.0 | `attackVector` | `NETWORK` |

Умова: `score >= 7.0` **і** `cvssData.attackVector == "NETWORK"` у **тій самій** вибраній оцінці.

**CVSS (Common Vulnerability Scoring System) v3.1** описує технічну серйозність вразливості
базовою оцінкою від 0 до 10. Метрика **Attack Vector (AV)** показує, звідки можна провести
атаку: `NETWORK` — віддалено через мережу (найширша поверхня атаки), `ADJACENT_NETWORK` —
із суміжного сегмента, `LOCAL` — потрібен локальний доступ, `PHYSICAL` — фізичний доступ до
пристрою. Правило варіанта відбирає для ручного огляду серйозні (≥ 7.0) вразливості, які
можна експлуатувати віддалено. Стан `review` означає відповідність навчальному правилу, а не
готовий пріоритет усунення.

Аналізується лише `metrics.cvssMetricV31`: вибирається перший елемент з `type = "Primary"`,
а якщо його немає — перший елемент списку.

**Номер варіанта.** Програма імпортує `shared.student.VARIANT_NUMBER`. Там записано 16
(номер у списку групи), а методичка містить 15 варіантів, тому номер береться по колу:
`(16 − 1) mod 15 + 1 = 1`. Значення, що не є `int`, `bool` або число < 1 дають код завершення 2.

## 2. Репозиторій, локальний запуск і JSON-звіт

Посилання на роботу: <https://github.com/Tusay1/CyberSec_Python_labs/tree/main/labs/lab04>

```text
labs/lab04/
├── __init__.py
├── main.py              # аргументи, load_response(), main()
├── api_client.py        # build_headers(), fetch_response()
├── analysis.py          # extract_record(), build_report(), правила варіантів
├── data/nvd_sample.json # синтетична відповідь CVE-2099-10001
├── tests/
│   ├── conftest.py      # заборона мережі, фікстури з глибокою копією відповіді
│   ├── test_analysis.py
│   ├── test_api_client.py
│   └── test_main.py
├── README.md
└── REPORT.md / REPORT.docx
```

Локальний запуск і приклади помилок:

```text
$ python -m labs.lab04.main --cve CVE-2099-10001 --input labs/lab04/data/nvd_sample.json
{
  "cve_id": "CVE-2099-10001",
  "variant": 1,
  "description": "Synthetic vulnerability for offline API testing.",
  "vuln_status": "Analyzed",
  "cvss_version": "3.1",
  "score": 9.8,
  "score_source": "nvd@nist.gov",
  "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  "rule": {
    "threshold": 7.0,
    "field": "attackVector",
    "expected": "NETWORK"
  },
  "observed": "NETWORK",
  "decision": "review"
}
[код завершення: 0]

$ python -m labs.lab04.main --cve cve-2021-44228
usage: python -m labs.lab04.main [-h] --cve CVE [--input INPUT]
python -m labs.lab04.main: error: argument --cve: некоректний ідентифікатор 'cve-2021-44228', очікується CVE-РРРР-NNNN
[код завершення: 2]

$ python -m labs.lab04.main --cve CVE-2099-10001 --input labs/lab04/data/missing.json
Помилка: файл labs/lab04/data/missing.json не знайдено.
[код завершення: 1]
```

Отриманий звіт збігається з очікуваним у методичці для варіанта 1 (`decision: "review"`).
Синтетичний файл містить дві оцінки v3.1: спочатку `Secondary` (4.2, `LOCAL`), потім
`Primary` (9.8, `NETWORK`) — так у локальному режимі видно, що `Primary` має пріоритет.

## 3. Результати pytest і Ruff

```text
$ python -m pytest labs/lab04/tests -q
........................................................................ [ 61%]
..............................................                           [100%]
118 passed in 0.18s
```

```text
$ ruff check labs/lab04
All checks passed!
$ ruff format --check labs/lab04
10 files already formatted
```

Ruff (правило `TRY004`) рекомендує `TypeError` при перевірках типу, тоді як методичка
вимагає `ValueError` для порушень контракту. Правило не вимикалося: введено виняток
`DataFormatError(ValueError)`, тож код задовольняє обидві вимоги.

**Тест на межі порогу.** `test_threshold_boundary` змінює лише `baseScore` у копії
синтетичної відповіді (це тест порівняння, а не перерахунок CVSS) і явно задає очікування:

```text
labs/lab04/tests/test_analysis.py::test_threshold_boundary[6.9-other] PASSED [  0%]
labs/lab04/tests/test_analysis.py::test_threshold_boundary[7.0-review] PASSED [  1%]
labs/lab04/tests/test_analysis.py::test_threshold_boundary[7.1-review] PASSED [  2%]
labs/lab04/tests/test_analysis.py::test_threshold_boundary[0-other] PASSED [  3%]
labs/lab04/tests/test_analysis.py::test_threshold_boundary[10-review] PASSED [  4%]
```

Значення 7.0 рівно на порозі має давати `review`, бо умова — «не менше». Експеримент:
тимчасова заміна `>=` на `>` в `analysis.py` — тест рівності порогу виявив помилку,
після чого умову відновлено:

```text
E         + other

labs/lab04/tests/test_analysis.py:27: AssertionError
=========================== short test summary info ============================
FAILED labs/lab04/tests/test_analysis.py::test_threshold_boundary[7.0-review]
1 failed, 117 passed in 0.20s
```

### Покриття обов'язкових сценаріїв

| Сценарій | Тести |
|---|---|
| Оцінка нижче / на / вище порогу; `LOCAL` за оцінки 9.8 | `test_threshold_boundary`, `test_wrong_field_value_with_high_score` |
| Не знайдено; `Rejected`; відсутній статус | `test_not_found`, `test_rejected_ignores_high_score`, `test_missing_status_gives_insufficient_data` |
| Відсутні оцінка або потрібне поле | `test_missing_score_gives_insufficient_data`, `test_missing_variant_field_gives_insufficient_data` |
| Некоректний тип / значення поля, `baseScore` | `test_invalid_variant_field_raises`, `test_invalid_base_score_raises` (`"9.8"`, `true`, `inf`, `NaN`, …) |
| `Primary` пріоритетніший за попередній `Secondary`; без `Primary` — перший | `test_primary_has_priority_over_earlier_secondary`, `test_without_primary_first_entry_is_selected` |
| Запит: `cveId`, таймаут, заголовки з ключем і без | `test_fetch_uses_expected_request`, `test_fetch_sends_api_key_in_header_not_url`, `test_build_headers_*` |
| Мережеві та HTTP-помилки, некоректний JSON | `test_network_errors_raise_fetch_error`, `test_http_error_raises_fetch_error`, `test_invalid_json_raises_fetch_error` |
| Локальний JSON без мережі; некоректний / відсутній файл | `test_local_mode_builds_report_without_network`, `test_invalid_json_file`, `test_missing_file` |
| Аргументи та номер варіанта (код 2) | `test_invalid_cve_argument_exits_with_two`, `test_invalid_variant_number_returns_two` |

## 4. Запит до NVD

```text
Дата: 2026-11-11 12:21 UTC
Команда: python -m labs.lab04.main --cve CVE-2021-44228   (без ключа API)
```

```json
  "cve_id": "CVE-2021-44228",
  "variant": 1,
  "description": "Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled. From log4j 2.15.0, this behavior has been disabled by default. From version 2.16.0 (along with 2.12.2, 2.12.3, and 2.3.1), this functionality has been completely removed. Note that this vulnerability is specific to log4j-core and does not affect log4net, log4cxx, or other Apache Logging Services projects.",
  "vuln_status": "Analyzed",
  "cvss_version": "3.1",
  "score": 10.0,
  "score_source": "nvd@nist.gov",
  "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
  "rule": {
    "threshold": 7.0,
    "field": "attackVector",
    "expected": "NETWORK"
  },
  "observed": "NETWORK",
  "decision": "review"
}
```

Код завершення: 0. CVE-2021-44228 (Log4Shell) має оцінку 10.0 від `nvd@nist.gov` і
мережевий вектор атаки, тому для варіанта 1 отримано `review`. Дані NVD можуть змінюватися,
тому цей результат не закріплено в автоматичних тестах.

## 5. Лістинги

**`labs/lab04/api_client.py`**

```python
"""Мінімальний клієнт NVD CVE API 2.0: заголовки та один GET-запит."""

import os
from typing import Any

import requests

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
TIMEOUT = (3.05, 10)
API_KEY_ENV = "NVD_API_KEY"


class FetchError(Exception):
    """Помилка отримання відповіді: мережа, HTTP-статус або некоректний JSON.

    Повідомлення не містить ключа, заголовків чи тіла відповіді.
    """


def build_headers() -> dict[str, str]:
    """Повернути заголовки запиту.

    Ключ зчитується з NVD_API_KEY під час виклику (не під час імпорту).
    Порожній або пробільний ключ означає запит без ключа.
    """
    headers = {"Accept": "application/json"}
    api_key = (os.getenv(API_KEY_ENV) or "").strip()
    if api_key:
        headers["apiKey"] = api_key
    return headers


def fetch_response(cve_id: str) -> Any:
    """Виконати один GET-запит до NVD і повернути декодований JSON.

    Перенаправлення вимкнено, TLS перевіряється, таймаут (з'єднання, читання).
    Семантичну перевірку даних виконує analysis.extract_record().
    """
    try:
        response = requests.get(
            NVD_API_URL,
            params={"cveId": cve_id},
            headers=build_headers(),
            timeout=TIMEOUT,
            allow_redirects=False,
        )
    except requests.exceptions.Timeout as exc:
        raise FetchError("перевищено час очікування відповіді NVD") from exc
    except requests.exceptions.ConnectionError as exc:
        raise FetchError("не вдалося з'єднатися з NVD") from exc
    except requests.exceptions.RequestException as exc:
        raise FetchError("помилка виконання HTTP-запиту") from exc

    try:
        response.raise_for_status()
    except requests.exceptions.HTTPError as exc:
        raise FetchError(f"NVD повернув HTTP-помилку {response.status_code}") from exc

    if response.status_code != 200:
        raise FetchError(f"неочікуваний HTTP-статус {response.status_code}")

    try:
        return response.json()
    except requests.exceptions.JSONDecodeError as exc:
        raise FetchError("відповідь NVD не є коректним JSON") from exc
```


**`labs/lab04/analysis.py`**

```python
"""Перевірка відповіді NVD і застосування правила варіанта.

Функції працюють лише з переданими аргументами: не читають файлів,
змінних середовища, не виконують HTTP-запитів і нічого не друкують.
Порушення контракту даних → ValueError.
"""

import math
from typing import Any

VARIANT_COUNT = 15

# Варіант → (поріг T, поле cvssData, очікуване значення)
RULES: dict[int, tuple[float, str, str]] = {
    1: (7.0, "attackVector", "NETWORK"),
    2: (8.0, "attackComplexity", "LOW"),
    3: (7.0, "privilegesRequired", "NONE"),
    4: (8.0, "userInteraction", "NONE"),
    5: (7.0, "confidentialityImpact", "HIGH"),
    6: (7.0, "integrityImpact", "HIGH"),
    7: (7.0, "availabilityImpact", "HIGH"),
    8: (9.0, "scope", "CHANGED"),
    9: (5.0, "attackVector", "LOCAL"),
    10: (6.0, "privilegesRequired", "LOW"),
    11: (6.0, "userInteraction", "REQUIRED"),
    12: (6.0, "confidentialityImpact", "LOW"),
    13: (6.0, "integrityImpact", "LOW"),
    14: (6.0, "availabilityImpact", "LOW"),
    15: (8.0, "attackComplexity", "HIGH"),
}


class DataFormatError(ValueError):
    """Відповідь NVD або аргументи порушують очікуваний контракт."""


_IMPACT = frozenset({"NONE", "LOW", "HIGH"})
ALLOWED_VALUES: dict[str, frozenset[str]] = {
    "attackVector": frozenset({"NETWORK", "ADJACENT_NETWORK", "LOCAL", "PHYSICAL"}),
    "attackComplexity": frozenset({"LOW", "HIGH"}),
    "privilegesRequired": _IMPACT,
    "userInteraction": frozenset({"NONE", "REQUIRED"}),
    "scope": frozenset({"UNCHANGED", "CHANGED"}),
    "confidentialityImpact": _IMPACT,
    "integrityImpact": _IMPACT,
    "availabilityImpact": _IMPACT,
}

REPORT_KEYS = (
    "cve_id",
    "variant",
    "description",
    "vuln_status",
    "cvss_version",
    "score",
    "score_source",
    "vector",
    "rule",
    "observed",
    "decision",
)


def _optional_text(container: dict, key: str, where: str) -> str | None:
    """Відсутнє поле → None; наявне має бути непорожнім рядком."""
    if key not in container:
        return None
    value = container[key]
    if not isinstance(value, str) or not value.strip():
        raise DataFormatError(f"{where}.{key} має бути непорожнім рядком")
    return value


def _english_description(cve: dict) -> str | None:
    """Перший непорожній опис англійською або None."""
    if "descriptions" not in cve:
        return None
    descriptions = cve["descriptions"]
    if not isinstance(descriptions, list):
        raise DataFormatError("cve.descriptions має бути списком")
    for item in descriptions:
        if not isinstance(item, dict):
            raise DataFormatError("елементи descriptions мають бути об'єктами")
        lang, value = item.get("lang"), item.get("value")
        if not isinstance(lang, str) or not isinstance(value, str):
            raise DataFormatError("descriptions: lang і value мають бути рядками")
    for item in descriptions:
        if item["lang"] == "en" and item["value"].strip():
            return item["value"]
    return None


def _select_metric(cve: dict) -> dict | None:
    """Вибрати оцінку CVSS v3.1: перший Primary, інакше перший елемент."""
    if "metrics" not in cve:
        return None
    metrics = cve["metrics"]
    if not isinstance(metrics, dict):
        raise DataFormatError("cve.metrics має бути об'єктом")
    if "cvssMetricV31" not in metrics:
        return None
    entries = metrics["cvssMetricV31"]
    if not isinstance(entries, list):
        raise DataFormatError("metrics.cvssMetricV31 має бути списком")
    if not entries:
        return None
    if not all(isinstance(entry, dict) for entry in entries):
        raise DataFormatError("елементи cvssMetricV31 мають бути об'єктами")
    return next(
        (entry for entry in entries if entry.get("type") == "Primary"), entries[0]
    )


def _parse_metric(entry: dict) -> dict:
    """Перевірити вибрану оцінку і повернути її внутрішнє подання."""
    cvss = entry.get("cvssData")
    if not isinstance(cvss, dict):
        raise DataFormatError("cvssData має бути об'єктом")

    score = cvss.get("baseScore")
    if (
        isinstance(score, bool)
        or not isinstance(score, (int, float))
        or not math.isfinite(score)
        or not 0 <= score <= 10
    ):
        raise DataFormatError("baseScore має бути скінченним числом від 0 до 10")

    version = _optional_text(cvss, "version", "cvssData")
    if version is not None and version != "3.1":
        raise DataFormatError("cvssData.version має дорівнювати '3.1'")

    return {
        "score": float(score),
        "version": version,
        "vector": _optional_text(cvss, "vectorString", "cvssData"),
        "source": _optional_text(entry, "source", "cvssMetricV31[]"),
        # Копія лише рядкових полів метрики: payload не змінюється.
        "fields": {key: cvss[key] for key in ALLOWED_VALUES if key in cvss},
    }


def extract_record(payload: Any, cve_id: str) -> dict | None:
    """Перевірити відповідь NVD і повернути внутрішній запис або None.

    Формат запису::

        {
            "cve_id": str,
            "vuln_status": str | None,     # None — статус відсутній
            "description": str | None,     # перший непорожній англійський опис
            "metric": None | {             # None — оцінки v3.1 немає / не аналізувалась
                "score": float,            # baseScore 0–10
                "version": str | None,     # "3.1" або None
                "vector": str | None,
                "source": str | None,
                "fields": {назва_поля_cvssData: значення, ...},
            },
        }

    None повертається, якщо vulnerabilities — порожній список (не знайдено).
    Для статусу Rejected або відсутнього статусу оцінки не аналізуються.
    """
    if not isinstance(payload, dict):
        raise DataFormatError("відповідь має бути JSON-об'єктом")
    vulnerabilities = payload.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        raise DataFormatError("поле vulnerabilities має бути списком")
    if not vulnerabilities:
        return None
    if len(vulnerabilities) > 1:
        raise DataFormatError(
            "для точного ідентифікатора очікується не більше одного запису"
        )

    item = vulnerabilities[0]
    if not isinstance(item, dict) or not isinstance(item.get("cve"), dict):
        raise DataFormatError("елемент vulnerabilities має містити об'єкт cve")
    cve = item["cve"]
    if cve.get("id") != cve_id:
        raise DataFormatError("cve.id не збігається із запитаним ідентифікатором")

    status = _optional_text(cve, "vulnStatus", "cve")
    record = {
        "cve_id": cve_id,
        "vuln_status": status,
        "description": _english_description(cve),
        "metric": None,
    }
    if status is None or status == "Rejected":
        return record

    entry = _select_metric(cve)
    if entry is not None:
        record["metric"] = _parse_metric(entry)
    return record


def validate_variant(variant: Any) -> int:
    """Перевірити, що номер варіанта — int (не bool) від 1 до 15."""
    if isinstance(variant, bool) or not isinstance(variant, int):
        raise DataFormatError("номер варіанта має бути цілим числом")
    if not 1 <= variant <= VARIANT_COUNT:
        raise DataFormatError(f"номер варіанта має бути від 1 до {VARIANT_COUNT}")
    return variant


def build_report(record: dict | None, cve_id: str, variant: int) -> dict:
    """Застосувати правило варіанта і повернути словник звіту.

    Стани перевіряються в порядку: not_found → rejected →
    insufficient_data → review → other.
    """
    variant = validate_variant(variant)
    threshold, field, expected = RULES[variant]
    report: dict[str, Any] = dict.fromkeys(REPORT_KEYS)
    report.update(
        cve_id=cve_id,
        variant=variant,
        rule={"threshold": threshold, "field": field, "expected": expected},
    )

    if record is None:
        report["decision"] = "not_found"
        return report

    report["vuln_status"] = record["vuln_status"]
    report["description"] = record["description"]
    if record["vuln_status"] == "Rejected":
        report["decision"] = "rejected"
        return report

    metric = record["metric"]
    if record["vuln_status"] is None or metric is None:
        report["decision"] = "insufficient_data"
        return report

    report.update(
        cvss_version=metric["version"],
        score=metric["score"],
        score_source=metric["source"],
        vector=metric["vector"],
    )
    if field not in metric["fields"]:
        report["decision"] = "insufficient_data"
        return report

    observed = metric["fields"][field]
    if not isinstance(observed, str) or observed not in ALLOWED_VALUES[field]:
        raise DataFormatError(f"cvssData.{field} має недопустиме значення")
    report["observed"] = observed

    matches = metric["score"] >= threshold and observed == expected
    report["decision"] = "review" if matches else "other"
    return report
```


**`labs/lab04/main.py`**

```python
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
```


**`labs/lab04/tests/conftest.py`**

```python
"""Спільні фікстури: заборона мережі та синтетична відповідь NVD."""

import copy
import json
from pathlib import Path

import pytest

SAMPLE_PATH = Path(__file__).resolve().parent.parent / "data" / "nvd_sample.json"
SAMPLE_CVE = "CVE-2099-10001"


@pytest.fixture(autouse=True)
def isolated_environment(monkeypatch):
    """Заборонити справжні запити Requests і прибрати успадкований ключ."""
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    monkeypatch.delattr("requests.sessions.Session.request")


@pytest.fixture(scope="session")
def _sample_original() -> dict:
    return json.loads(SAMPLE_PATH.read_text(encoding="utf-8"))


@pytest.fixture
def sample(_sample_original) -> dict:
    """Нова глибока копія синтетичної відповіді для кожного тесту."""
    return copy.deepcopy(_sample_original)


@pytest.fixture
def cve(sample) -> dict:
    """Об'єкт cve з копії відповіді (зміни не впливають на інші тести)."""
    return sample["vulnerabilities"][0]["cve"]


@pytest.fixture
def primary(cve) -> dict:
    """cvssData вибраної (Primary) оцінки в копії відповіді."""
    for entry in cve["metrics"]["cvssMetricV31"]:
        if entry["type"] == "Primary":
            return entry["cvssData"]
    raise AssertionError("у синтетичній відповіді немає Primary")
```


**`labs/lab04/tests/test_analysis.py`**

```python
"""Модульні тести analysis.py: правило варіанта 1 і перевірка даних."""

import copy

import pytest

from labs.lab04.analysis import build_report, extract_record

from .conftest import SAMPLE_CVE

VARIANT = 1  # attackVector == NETWORK і score >= 7.0


def report_for(payload, variant=VARIANT, cve_id=SAMPLE_CVE):
    return build_report(extract_record(payload, cve_id), cve_id, variant)


# ----------------------------------------------------------- межа порогу


@pytest.mark.parametrize(
    ("score", "expected"),
    [(6.9, "other"), (7.0, "review"), (7.1, "review"), (0, "other"), (10, "review")],
)
def test_threshold_boundary(sample, primary, score, expected):
    primary["baseScore"] = score
    assert report_for(sample)["decision"] == expected


def test_wrong_field_value_with_high_score(sample, primary):
    primary["attackVector"] = "LOCAL"
    report = report_for(sample)
    assert report["score"] == 9.8
    assert report["observed"] == "LOCAL"
    assert report["decision"] == "other"


def test_sample_full_report(sample):
    assert report_for(sample) == {
        "cve_id": "CVE-2099-10001",
        "variant": 1,
        "description": "Synthetic vulnerability for offline API testing.",
        "vuln_status": "Analyzed",
        "cvss_version": "3.1",
        "score": 9.8,
        "score_source": "nvd@nist.gov",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "rule": {"threshold": 7.0, "field": "attackVector", "expected": "NETWORK"},
        "observed": "NETWORK",
        "decision": "review",
    }


@pytest.mark.parametrize(
    ("variant", "expected"),
    [(v, "review") for v in range(1, 8)] + [(v, "other") for v in range(8, 16)],
)
def test_sample_decision_for_all_variants(sample, variant, expected):
    assert report_for(sample, variant=variant)["decision"] == expected


def test_payload_is_not_modified(sample):
    before = copy.deepcopy(sample)
    report_for(sample)
    assert sample == before


# ------------------------------------------------------ стани без оцінки


def test_not_found():
    report = report_for({"vulnerabilities": []})
    assert report["decision"] == "not_found"
    assert report["cve_id"] == SAMPLE_CVE
    assert report["variant"] == VARIANT
    assert report["rule"] == {
        "threshold": 7.0,
        "field": "attackVector",
        "expected": "NETWORK",
    }
    for key in (
        "description",
        "vuln_status",
        "cvss_version",
        "score",
        "score_source",
        "vector",
        "observed",
    ):
        assert report[key] is None


def test_rejected_ignores_high_score(sample, cve):
    cve["vulnStatus"] = "Rejected"
    report = report_for(sample)
    assert report["decision"] == "rejected"
    assert report["vuln_status"] == "Rejected"
    assert report["description"] == "Synthetic vulnerability for offline API testing."
    assert report["score"] is None
    assert report["observed"] is None


def test_missing_status_gives_insufficient_data(sample, cve):
    del cve["vulnStatus"]
    report = report_for(sample)
    assert report["decision"] == "insufficient_data"
    assert report["vuln_status"] is None
    assert report["score"] is None


@pytest.mark.parametrize("mutation", ["no_metrics", "no_v31", "empty_v31"])
def test_missing_score_gives_insufficient_data(sample, cve, mutation):
    if mutation == "no_metrics":
        del cve["metrics"]
    elif mutation == "no_v31":
        del cve["metrics"]["cvssMetricV31"]
    else:
        cve["metrics"]["cvssMetricV31"] = []
    report = report_for(sample)
    assert report["decision"] == "insufficient_data"
    assert report["vuln_status"] == "Analyzed"
    assert report["score"] is None


def test_missing_variant_field_gives_insufficient_data(sample, primary):
    del primary["attackVector"]
    report = report_for(sample)
    assert report["decision"] == "insufficient_data"
    assert report["score"] == 9.8
    assert report["observed"] is None


# --------------------------------------------------- вибір Primary/Secondary


def test_primary_has_priority_over_earlier_secondary(sample, cve):
    entries = cve["metrics"]["cvssMetricV31"]
    assert entries[0]["type"] == "Secondary"
    report = report_for(sample)
    assert report["score_source"] == "nvd@nist.gov"
    assert report["score"] == 9.8


def test_without_primary_first_entry_is_selected(sample, cve):
    for entry in cve["metrics"]["cvssMetricV31"]:
        entry["type"] = "Secondary"
    report = report_for(sample)
    assert report["score_source"] == "cna@example.org"
    assert report["score"] == 4.2
    assert report["observed"] == "LOCAL"
    assert report["decision"] == "other"


def test_optional_report_fields_absent_become_null(sample, cve, primary):
    del primary["version"], primary["vectorString"]
    for entry in cve["metrics"]["cvssMetricV31"]:
        entry.pop("source")
    report = report_for(sample)
    assert report["cvss_version"] is None
    assert report["vector"] is None
    assert report["score_source"] is None
    assert report["decision"] == "review"


def test_description_without_english_is_null(sample, cve):
    cve["descriptions"] = [{"lang": "uk", "value": "Лише українською"}]
    assert report_for(sample)["description"] is None


# ----------------------------------------------------------- помилки даних


@pytest.mark.parametrize("value", [None, "network", "", 1, ["NETWORK"]])
def test_invalid_variant_field_raises(sample, primary, value):
    primary["attackVector"] = value
    with pytest.raises(ValueError):
        report_for(sample)


@pytest.mark.parametrize(
    "score", ["9.8", True, None, -0.1, 10.1, float("inf"), float("nan")]
)
def test_invalid_base_score_raises(sample, primary, score):
    primary["baseScore"] = score
    with pytest.raises(ValueError):
        report_for(sample)


def test_missing_base_score_raises(sample, primary):
    del primary["baseScore"]
    with pytest.raises(ValueError):
        report_for(sample)


@pytest.mark.parametrize(
    "payload",
    [
        [],
        "text",
        {},
        {"vulnerabilities": None},
        {"vulnerabilities": [{}]},
        {"vulnerabilities": [{"cve": []}]},
    ],
)
def test_invalid_payload_structure_raises(payload):
    with pytest.raises(ValueError):
        extract_record(payload, SAMPLE_CVE)


def test_two_vulnerabilities_raise(sample):
    sample["vulnerabilities"].append(copy.deepcopy(sample["vulnerabilities"][0]))
    with pytest.raises(ValueError):
        extract_record(sample, SAMPLE_CVE)


def test_other_cve_id_raises(sample):
    with pytest.raises(ValueError):
        extract_record(sample, "CVE-2099-99999")


@pytest.mark.parametrize(
    ("path", "value"),
    [
        ("metrics", None),
        ("metrics", []),
        ("cvssMetricV31", None),
        ("cvssMetricV31", {}),
        ("cvssMetricV31", ["not a dict"]),
        ("vulnStatus", ""),
        ("vulnStatus", 5),
        ("descriptions", "text"),
    ],
)
def test_invalid_present_fields_raise(sample, cve, path, value):
    if path == "cvssMetricV31":
        cve["metrics"]["cvssMetricV31"] = value
    else:
        cve[path] = value
    with pytest.raises(ValueError):
        report_for(sample)


@pytest.mark.parametrize(
    ("key", "value"),
    [("version", "3.0"), ("version", ""), ("vectorString", 5), ("vectorString", " ")],
)
def test_invalid_optional_cvss_fields_raise(sample, primary, key, value):
    primary[key] = value
    with pytest.raises(ValueError):
        report_for(sample)


def test_cvss_data_must_be_object(sample, cve):
    cve["metrics"]["cvssMetricV31"][1]["cvssData"] = None
    with pytest.raises(ValueError):
        report_for(sample)


@pytest.mark.parametrize("variant", [0, 16, -1, True, "1", 1.0])
def test_build_report_rejects_bad_variant(variant):
    with pytest.raises(ValueError):
        build_report(None, SAMPLE_CVE, variant)
```


**`labs/lab04/tests/test_api_client.py`**

```python
"""Тести HTTP-клієнта з підміною requests.get."""

from unittest.mock import Mock

import pytest
import requests

from labs.lab04 import api_client
from labs.lab04.api_client import FetchError

URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVE = "CVE-2099-10001"


def make_response(status_code=200, payload=None, json_error=None):
    response = Mock(spec=requests.Response)
    response.status_code = status_code
    response.headers = {"Content-Type": "application/json; charset=utf-8"}
    if json_error is not None:
        response.json.side_effect = json_error
    else:
        response.json.return_value = payload
    return response


def test_fetch_uses_expected_request(monkeypatch):
    payload = {"startIndex": 0, "totalResults": 0, "vulnerabilities": []}
    response = make_response(payload=payload)
    fake_get = Mock(return_value=response)
    monkeypatch.setattr(api_client.requests, "get", fake_get)

    assert api_client.fetch_response(CVE) == payload
    fake_get.assert_called_once_with(
        URL,
        params={"cveId": CVE},
        headers={"Accept": "application/json"},
        timeout=(3.05, 10),
        allow_redirects=False,
    )
    response.raise_for_status.assert_called_once_with()


def test_fetch_sends_api_key_in_header_not_url(monkeypatch):
    monkeypatch.setenv("NVD_API_KEY", "  fake-test-key  ")
    fake_get = Mock(return_value=make_response(payload={"vulnerabilities": []}))
    monkeypatch.setattr(api_client.requests, "get", fake_get)

    api_client.fetch_response(CVE)
    kwargs = fake_get.call_args.kwargs
    assert kwargs["headers"] == {
        "Accept": "application/json",
        "apiKey": "fake-test-key",
    }
    assert kwargs["params"] == {"cveId": CVE}
    assert "fake-test-key" not in fake_get.call_args.args[0]


@pytest.mark.parametrize("value", [None, "", "   "])
def test_build_headers_without_key(monkeypatch, value):
    if value is not None:
        monkeypatch.setenv("NVD_API_KEY", value)
    assert api_client.build_headers() == {"Accept": "application/json"}


def test_build_headers_reads_key_at_call_time(monkeypatch):
    assert "apiKey" not in api_client.build_headers()
    monkeypatch.setenv("NVD_API_KEY", "fake-key")
    assert api_client.build_headers()["apiKey"] == "fake-key"


@pytest.mark.parametrize(
    "error",
    [
        requests.exceptions.ConnectTimeout("timeout"),
        requests.exceptions.ReadTimeout("timeout"),
        requests.exceptions.ConnectionError("down"),
        requests.exceptions.TooManyRedirects("loop"),
    ],
)
def test_network_errors_raise_fetch_error(monkeypatch, error):
    monkeypatch.setattr(api_client.requests, "get", Mock(side_effect=error))
    with pytest.raises(FetchError):
        api_client.fetch_response(CVE)


@pytest.mark.parametrize("status_code", [403, 404, 500, 503])
def test_http_error_raises_fetch_error(monkeypatch, status_code):
    response = make_response(status_code=status_code)
    response.raise_for_status.side_effect = requests.exceptions.HTTPError(
        f"{status_code} error", response=response
    )
    monkeypatch.setattr(api_client.requests, "get", Mock(return_value=response))

    with pytest.raises(FetchError, match=str(status_code)):
        api_client.fetch_response(CVE)
    response.json.assert_not_called()


@pytest.mark.parametrize("status_code", [204, 301, 302])
def test_unexpected_status_raises_fetch_error(monkeypatch, status_code):
    response = make_response(status_code=status_code)
    monkeypatch.setattr(api_client.requests, "get", Mock(return_value=response))
    with pytest.raises(FetchError, match="неочікуваний"):
        api_client.fetch_response(CVE)


def test_invalid_json_raises_fetch_error(monkeypatch):
    response = make_response(
        json_error=requests.exceptions.JSONDecodeError("Invalid JSON", "{", 1)
    )
    monkeypatch.setattr(api_client.requests, "get", Mock(return_value=response))
    with pytest.raises(FetchError, match="JSON"):
        api_client.fetch_response(CVE)


def test_real_network_is_blocked():
    """Автоматична фікстура не дає дійти до справжньої мережі."""
    with pytest.raises(AttributeError):
        requests.get(URL, timeout=1)
```


**`labs/lab04/tests/test_main.py`**

```python
"""Інтеграційні тести CLI: локальний режим, помилки, коди завершення."""

import json
from unittest.mock import Mock

import pytest

from labs.lab04 import api_client, main
from labs.lab04.api_client import FetchError

from .conftest import SAMPLE_CVE, SAMPLE_PATH


def run(capsys, *argv):
    code = main.main(list(argv))
    out, err = capsys.readouterr()
    return code, out, err


def test_local_mode_builds_report_without_network(monkeypatch, capsys):
    fake_fetch = Mock(side_effect=AssertionError("мережа не повинна викликатися"))
    monkeypatch.setattr(main, "fetch_response", fake_fetch)

    code, out, err = run(capsys, "--cve", SAMPLE_CVE, "--input", str(SAMPLE_PATH))
    assert code == 0
    assert err == ""
    report = json.loads(out)
    assert report["decision"] == "review"
    assert report["variant"] == 1
    assert report["observed"] == "NETWORK"
    fake_fetch.assert_not_called()


def test_output_is_single_json_object_with_unicode(tmp_path, sample, cve, capsys):
    cve["descriptions"] = [{"lang": "en", "value": "Опис із кирилицею"}]
    path = tmp_path / "nvd.json"
    path.write_text(json.dumps(sample), encoding="utf-8")

    code, out, _ = run(capsys, "--cve", SAMPLE_CVE, "--input", str(path))
    assert code == 0
    assert "Опис із кирилицею" in out  # ensure_ascii=False
    assert json.loads(out)["description"] == "Опис із кирилицею"


def test_not_found_from_file_returns_zero(tmp_path, capsys):
    path = tmp_path / "empty.json"
    path.write_text('{"vulnerabilities": []}', encoding="utf-8")
    code, out, _ = run(capsys, "--cve", SAMPLE_CVE, "--input", str(path))
    assert code == 0
    assert json.loads(out)["decision"] == "not_found"


def test_invalid_json_file(tmp_path, capsys):
    path = tmp_path / "broken.json"
    path.write_text("{", encoding="utf-8")
    code, out, err = run(capsys, "--cve", SAMPLE_CVE, "--input", str(path))
    assert code == 1
    assert out == ""
    assert "некоректний JSON" in err
    assert "Traceback" not in err


def test_missing_file(tmp_path, capsys):
    code, out, err = run(
        capsys, "--cve", SAMPLE_CVE, "--input", str(tmp_path / "missing.json")
    )
    assert code == 1
    assert out == ""
    assert "не знайдено" in err


def test_invalid_structure_in_file(tmp_path, sample, primary, capsys):
    primary["baseScore"] = "9.8"
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(sample), encoding="utf-8")
    code, out, err = run(capsys, "--cve", SAMPLE_CVE, "--input", str(path))
    assert code == 1
    assert out == ""
    assert "Помилка даних" in err


def test_network_mode_uses_fetch(monkeypatch, sample, capsys):
    fake_fetch = Mock(return_value=sample)
    monkeypatch.setattr(main, "fetch_response", fake_fetch)
    code, out, _ = run(capsys, "--cve", SAMPLE_CVE)
    assert code == 0
    fake_fetch.assert_called_once_with(SAMPLE_CVE)
    assert json.loads(out)["decision"] == "review"


def test_network_error_returns_one(monkeypatch, capsys):
    monkeypatch.setattr(
        main, "fetch_response", Mock(side_effect=FetchError("NVD повернув 503"))
    )
    code, out, err = run(capsys, "--cve", SAMPLE_CVE)
    assert code == 1
    assert out == ""
    assert "503" in err


def test_real_client_with_mocked_requests(monkeypatch, sample, capsys):
    """Справжній fetch_response + підмінений requests.get з ключем."""
    monkeypatch.setenv("NVD_API_KEY", "fake-key")
    response = Mock(status_code=200)
    response.json.return_value = sample
    fake_get = Mock(return_value=response)
    monkeypatch.setattr(api_client.requests, "get", fake_get)

    code, out, err = run(capsys, "--cve", SAMPLE_CVE)
    assert code == 0
    assert "fake-key" not in out + err
    assert fake_get.call_args.kwargs["headers"]["apiKey"] == "fake-key"


@pytest.mark.parametrize(
    "cve_id", ["cve-2099-10001", "CVE-99-1", "CVE-2099-123", "CVE-2099-10001x", ""]
)
def test_invalid_cve_argument_exits_with_two(cve_id, capsys):
    with pytest.raises(SystemExit) as exc_info:
        main.main(["--cve", cve_id])
    assert exc_info.value.code == 2
    assert "некоректний ідентифікатор" in capsys.readouterr().err


def test_missing_cve_argument_exits_with_two():
    with pytest.raises(SystemExit) as exc_info:
        main.main([])
    assert exc_info.value.code == 2


@pytest.mark.parametrize("number", [0, -3, True, "1", 1.5, None])
def test_invalid_variant_number_returns_two(monkeypatch, capsys, number):
    monkeypatch.setattr(main, "VARIANT_NUMBER", number)
    code, out, err = run(capsys, "--cve", SAMPLE_CVE, "--input", str(SAMPLE_PATH))
    assert code == 2
    assert out == ""
    assert "варіанта" in err


@pytest.mark.parametrize(("number", "expected"), [(1, 1), (9, 9), (15, 15), (16, 1)])
def test_variant_number_from_student(monkeypatch, capsys, number, expected):
    monkeypatch.setattr(main, "VARIANT_NUMBER", number)
    code, out, _ = run(capsys, "--cve", SAMPLE_CVE, "--input", str(SAMPLE_PATH))
    assert code == 0
    assert json.loads(out)["variant"] == expected
```


## 6. Висновки

Створено консольну утиліту, яка отримує запис про вразливість із NVD CVE API 2.0 або з
локального JSON-файла, перевіряє структуру відповіді, вибирає оцінку CVSS v3.1 і застосовує
правило варіанта 1. Отримання даних (`api_client.py`), аналіз (`analysis.py`) та інтерфейс
командного рядка (`main.py`) розділено, тому аналіз тестується як чисті функції без мережі.

**Що перевіряють локальні тести.** 118 тестів покривають логіку правила (зокрема межу
порогу), вибір оцінки, усі стани `decision`, відхилення некоректних даних, параметри
HTTP-запиту (URL, `cveId`, заголовки, таймаут, заборона перенаправлень), обробку мережевих і
HTTP-помилок та роботу CLI з кодами завершення. Справжня мережа заблокована автоматичною
фікстурою, `requests.get` підміняється двійником.

**Що потребує перевірки з реальним сервісом.** Тести не підтверджують, що справжній NVD
повертає дані саме в такому форматі, що адреса й заголовок `apiKey` приймаються сервером,
як поводяться обмеження частоти запитів і реальні таймаути. Тому виконано один ручний запит.

**Чому брак даних не означає відсутності небезпеки.** `insufficient_data` лише показує, що
NVD ще не надав оцінку v3.1 (наприклад, запис очікує аналізу) або бракує потрібного поля.
Вразливість від цього не стає безпечною: її серйозність просто невідома. Аналогічно, `other`
означає лише невідповідність навчальному правилу, а не відсутність ризику.

## Відповіді на контрольні питання

1. HTTP-помилка (`4xx`/`5xx`) означає, що запит не виконано; порожній результат — успішна
   відповідь `200` з `vulnerabilities: []`, тобто запис не знайдено (`not_found`, код 0).
2. `200` і успішне декодування означають лише валідний JSON; поля можуть бути відсутні,
   мати неправильний тип (`"9.8"`, `true`) або значення поза діапазоном.
3. `timeout=(3.05, 10)` — межа встановлення з'єднання і межа очікування між отриманням
   даних під час читання. Це не загальний час: повільна, але безперервна відповідь може
   тривати довше.
4. `cveId` — через `params`, ключ — через заголовок `apiKey`. URL може потрапити в журнали
   серверів і проксі, історію та повідомлення про помилки.
5. Там, де код шукає ім'я: `api_client.requests.get` (модуль імпортує `requests`) — тоді
   виконується справжня `fetch_response()`.
6. Бо підмінена функція не виконує код клієнта: аргументи `timeout` і `headers` формуються
   саме в ньому і не потрапляють до двійника.
7. `tmp_path` дає окремий тимчасовий каталог для файлів тесту, `capsys` перехоплює
   `stdout`/`stderr`, `isolated_environment` прибирає `NVD_API_KEY` і забороняє мережу.
8. `Mock` лише зберігає атрибут; `raise_for_status()` у двійника нічого не перевіряє, тому
   потрібно задати `side_effect=HTTPError(...)`.
