# Лабораторна робота №3 — FastAPI + SQLite

**Варіант 1: Реєстр вразливостей вебзастосунку.**

Сервіс обліку знахідок перевірки вебзастосунку.

| Поле | Значення |
|---|---|
| Категорії | `web`, `api`, `database` — компонент застосунку |
| `value` | навчальна оцінка небезпеки, `float`, 0–10 включно, одиниця — `score` |
| `status` | стан опрацювання: `new`, `in_progress`, `done` |
| Поріг | `7.0` (знахідки з `value >= 7.0` потребують першочергової уваги) |

## Структура

```
labs/lab03/
├── main.py            # FastAPI-застосунок, lifespan, /ping, /student
├── database.py        # Підключення (PRAGMA foreign_keys = ON) і виконання schema.sql
├── schema.sql         # Готова схема: categories + records (варіанти 1–3)
├── repository.py      # Параметризовані SQL-запити, транзакції
├── schemas.py         # Pydantic-моделі
├── config.py          # Варіант, одиниця, поріг, межі value
├── seed.py            # Початкове заповнення з data/seed.json
├── routers/
│   ├── categories.py
│   └── records.py
├── data/seed.json     # 3 категорії, 8 записів (файл .sqlite3 у Git не потрапляє)
└── REPORT.md / REPORT.docx  # Звіт
```

## Встановлення

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Запуск (з кореня репозиторію)

```bash
python -m labs.lab03.database      # створити таблиці (необов'язково — це робить і seed, і API)
python -m labs.lab03.seed          # початкове заповнення (повторний запуск нічого не змінює)
uvicorn labs.lab03.main:app --reload --host 127.0.0.1 --port 8000
```

Документація: <http://127.0.0.1:8000/docs> (Swagger UI), <http://127.0.0.1:8000/openapi.json>.

## Маршрути

| Метод і маршрут | Відповідь |
|---|---|
| `GET /ping` | 200 `{"status": "ok"}` |
| `GET /student` | 200 ПІБ, група, варіант |
| `GET /categories` | 200 список |
| `POST /categories` | 201 / 409 / 422 |
| `DELETE /categories/{id}` | 204 / 404 / 409 (категорія містить записи) |
| `GET /records` | 200; фільтри `category_id`, `status`, `min_value`, `q`, `limit` (1–100, 20), `offset` (≥0, 0) |
| `GET /records/{id}` | 200 / 404 |
| `POST /records` | 201 / 404 (категорія) / 409 (code) / 422 |
| `PUT /records/{id}` | 200 / 404 / 409 / 422 |
| `DELETE /records/{id}` | 204 / 404 |
| `POST /records/bulk` | 201 / 404 / 409 / 422 — один пакет = одна транзакція |

## Приклади запитів

```bash
curl -i "http://127.0.0.1:8000/ping"
curl -i "http://127.0.0.1:8000/records?category_id=1&status=new&limit=5&offset=0"

curl -i -X POST "http://127.0.0.1:8000/records" \
  -H "Content-Type: application/json" \
  -d '{"code":"V01-TEST","title":"Навчальна знахідка","category_id":1,"value":7.5,"status":"new"}'

# Скасування пакета: другий елемент дублює code V01-01 → 409, V01-ROLLBACK не зберігається
curl -i -X POST "http://127.0.0.1:8000/records/bulk" \
  -H "Content-Type: application/json" \
  -d '[{"code":"V01-ROLLBACK","title":"Перший елемент","category_id":1,"value":4.0,"status":"new"},{"code":"V01-01","title":"Дублікат коду","category_id":2,"value":5.0,"status":"new"}]'
```

## Перевірка стилю

```bash
ruff check labs/lab03
ruff format --check labs/lab03
```
