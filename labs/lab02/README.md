# Лабораторна робота №2: Розробка консольних утиліт для задач кібербезпеки
**Варіант 1**: Аналізатор журналів веб-сервера (Nginx/Apache Access Log)

## Опис завдань

### Завдання 1: Моделювання облікового запису та безпечних сесій (`task1.py`)
- **Безпека паролів:** Хешування через PBKDF2-HMAC-SHA256 ($100\,000$ ітерацій + випадкова сіль `os.urandom(16)`), безпечне порівняння через `hmac.compare_digest`.
- **Валідація:** Перевірка email через `@property` та регулярні вирази (`ValueError`).
- **ООП:** Наслідування (`Admin` від `User`), композиція (`UserAccount` об'єднує `User`, `Session`, `AuditLog`).
- **Спеціальні методи:** `__getitem__` та `__setitem__` для безпечного доступу до атрибутів акаунту (`KeyError`/`TypeError`).

---

### Завдання 2: CLI-аналізатор журналів веб-сервера (`task2.py`)
- **Розбір логів:** Парсинг формату Nginx за допомогою регулярного виразу `LOG_LINE_REGEX`.
- **Аналіз помилок:** Агрегація IP-адрес із кодами відповідей `>= min_status` за допомогою `collections.Counter`.
- **Детекція атак:** Пошук сигнатур SQL-ін'єкцій, Directory Traversal та XSS у запитах.
- **Експорт:** Формування підсумкових звітів у JSON або CSV з обробкою помилок файлової системи (`FileNotFoundError`, `PermissionError`, `OSError`).

---

## Інструкція із запуску

### 1. Встановлення залежностей
```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt

ООП 1 завдання

python -m labs.lab02.main demo

. Варіанти запуску Завдання 2 (CLI-утиліта):
Стандартний аналіз (звіт у JSON, Топ-5 помилок >= 400):

python -m labs.lab02.main analyze --log-file labs/lab02/data/access.log --output labs/lab02/data/web_report.json

Експорт у формат CSV:
python -m labs.lab02.main analyze --log-file labs/lab02/data/access.log --output labs/lab02/data/web_report.csv --format csv


Фільтрація лише серверних помилок (5xx) та Топ-3 IP:
python -m labs.lab02.main analyze --log-file labs/lab02/data/access.log --output labs/lab02/data/errors_500.json --min-status 500 --top 3

Тест обробки помилок (передача неіснуючого файлу):
python -m labs.lab02.main analyze --log-file labs/lab02/data/not_found.log