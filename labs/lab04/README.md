# Лабораторна робота №4 — NVD API + pytest

Консольна утиліта для перегляду запису про вразливість у NVD (CVE API 2.0),
застосування правила варіанта і формування JSON-звіту. Тести не звертаються до мережі.

## Варіант 1

| Поріг `T` | Поле `cvssData` | Очікуване значення | Напрям відбору |
|---|---|---|---|
| 7.0 | `attackVector` | `NETWORK` | Мережевий вектор атаки |

Умова: `baseScore >= 7.0` **і** `attackVector == "NETWORK"` у тій самій вибраній оцінці CVSS v3.1.

> Номер варіанта береться з `shared.student.VARIANT_NUMBER`. Там записано 16
> (номер у списку групи), а методичка має 15 варіантів, тому програма бере номер
> по колу: `(16 - 1) % 15 + 1 = 1`. Не `int`, `bool` або число < 1 → код завершення 2.

## Встановлення

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Запуск (з кореня репозиторію)

Локальний режим (без мережі, синтетична відповідь `CVE-2099-10001`):

```bash
python -m labs.lab04.main --cve CVE-2099-10001 --input labs/lab04/data/nvd_sample.json
```

Мережевий режим (один ручний запит до NVD):

```bash
python -m labs.lab04.main --cve CVE-2021-44228
# необов'язково: export NVD_API_KEY="..."  — ключ передається лише в заголовку apiKey
```

Коди завершення: `0` — звіт сформовано (зокрема `not_found`, `insufficient_data`),
`1` — помилка отримання/читання/перевірки даних, `2` — неправильні аргументи або номер варіанта.

## Формат звіту

```json
{
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
  "decision": "review"
}
```

`decision`: `not_found` → `rejected` → `insufficient_data` → `review` → `other` (у такому порядку).

## Структура

```
labs/lab04/
├── main.py            # argparse, load_response(), main()
├── api_client.py      # build_headers(), fetch_response()
├── analysis.py        # extract_record(), build_report(), правила 15 варіантів
├── data/nvd_sample.json
├── tests/             # conftest.py, test_analysis.py, test_api_client.py, test_main.py
└── REPORT.md / REPORT.docx
```

## Тести та стиль

```bash
python -m pytest labs/lab04/tests -q
ruff check labs/lab04
ruff format --check labs/lab04
```
