"""Завдання 3: Безпечне хешування, CSV-база та JSON-логування з винятками."""

import csv
import functools
import hashlib
import json
import os
import sys
from datetime import datetime

sys.path.append(
    os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))
)
from shared.student import VARIANT_NUMBER

DATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "data"))
CSV_FILE = os.path.join(DATA_DIR, "users.csv")
LOG_FILE = os.path.join(DATA_DIR, "log.json")

MIN_PASSWORD_LENGTH = 12
PERSONAL_SALT = f"{VARIANT_NUMBER:05d}"


class ValidationError(Exception):

    pass


def log_event(func):

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        username = (
            args[0]
            if len(args) > 0
            else kwargs.get("username", "unknown_user")
        )
        result_flag = False

        try:
            result_flag = func(*args, **kwargs)
            return result_flag
        finally:
            log_record = {
                "event": "login",
                "user": str(username),
                "result": "success" if result_flag else "failure",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "args": [str(a) for a in args],
                "kwargs": {k: str(v) for k, v in kwargs.items()},
            }
            try:
                logs = []
                if os.path.exists(LOG_FILE):
                    with open(LOG_FILE, "r", encoding="utf-8") as f:
                        logs = json.load(f)
                logs.append(log_record)
                with open(LOG_FILE, "w", encoding="utf-8") as f:
                    json.dump(logs, f, indent=4, ensure_ascii=False)
            except (PermissionError, IOError) as io_err:
                print(f"[!] Помилка запису лог-файлу: {io_err}")
            except json.JSONDecodeError:
                # Якщо файл пошкоджено, створюємо лог заново
                with open(LOG_FILE, "w", encoding="utf-8") as f:
                    json.dump([log_record], f, indent=4, ensure_ascii=False)

    return wrapper


def generate_hash(password: str, salt: str = "00000") -> str:
    if not password or not salt:
        raise ValueError("Пароль та сіль не можуть бути порожніми.")
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValidationError(
            f"Пароль '{password}' занадто короткий (мінімум {MIN_PASSWORD_LENGTH} символів)."
        )

    payload = (password + salt).encode("utf-8")
    return hashlib.sha3_512(payload).hexdigest()


def create_user(username: str, password: str) -> tuple[str, str]:
    """Створює пару (логін, хеш)."""
    return username, generate_hash(password, PERSONAL_SALT)


def create_users(users_list: tuple[tuple[str, str], ...]) -> bool:
    """Записує базу даних користувачів у CSV-файл з локальною обробкою I/O помилок."""
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        with open(CSV_FILE, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            for user, pwd in users_list:
                u_name, pwd_hash = create_user(user, pwd)
                writer.writerow([u_name, pwd_hash])
        return True
    except (FileNotFoundError, PermissionError, IOError) as e:
        print(f"[ERROR] Не вдалося створити/записати CSV-базу: {e}")
        return False


def read_users_db() -> list[dict[str, str]]:
    users_db = []
    try:
        with open(CSV_FILE, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            for row in reader:
                if row:
                    users_db.append({"username": row[0], "hash": row[1]})
    except FileNotFoundError:
        print(f"[ERROR] Файл бази {CSV_FILE} не знайдено.")
    except (PermissionError, IOError) as e:
        print(f"[ERROR] Помилка доступу під час читання CSV: {e}")
    return users_db


@log_event
def login(username: str, password: str, users_db: list[dict[str, str]]) -> bool:
    try:
        if not username or not password:
            raise ValueError("Логін і пароль є обов'язковими для заповнення.")

        pwd_hash = generate_hash(password, PERSONAL_SALT)

        for record in users_db:
            if record["username"] == username and record["hash"] == pwd_hash:
                return True
        return False

    except ValueError as val_err:
        print(f" [!] Помилка даних під час спроби входу: {val_err}")
        return False
    except ValidationError as val_err:
        print(f" [!] Помилка валідації пароля під час входу: {val_err}")
        return False


users_to_register = (
    ("soc_lead", "SuperSecretPass2026!"),
    ("analyst_one", "AnalystSecureP@ss1"),
    ("threat_hunter", "HuntingThreats#2026"),
    ("incident_resp", "IncidentHandler$99"),
    ("crypto_analyst", "QuantumSafe#Pass2026"),
    ("forensic_tech", "EvidenceChain@1234"),
    ("cloud_sec", "CloudDefenseKey#2026"),
    ("pentester", "ExploitPayload@999"),
    ("audit_agent", "CompliancePass#2026"),
    ("root_admin", "RootAdminP@ssw0rd!"),
)


def run_task3() -> None:
    print(f"--- Завдання 3 | Алгоритм: sha3_512, Сіль: {PERSONAL_SALT} ---")

    # 1. Запис бази даних
    if create_users(users_to_register):
        print("[+] Базу користувачів успішно створено та записано в CSV.")

    # 2. Зчитування бази даних
    db = read_users_db()
    print("\nВміст бази даних (CSV):")
    print(f"{'Користувач':<18} | {'Хеш пароля (SHA3-512)':<30}")
    print("-" * 52)
    for row in db:
        print(f"{row['username']:<18} | {row['hash'][:27]}...")

    # 3. Штатні та нештатні виклики login
    print("\n--- Тестування сценаріїв автентифікації ---")

    # Успішний вхід
    ok = login("soc_lead", "SuperSecretPass2026!", db)
    print(f"1. Вхід з правильним паролем: {ok}")

    # Невірний пароль (відповідає вимогам довжини, але хеш не той)
    wrong = login("soc_lead", "IncorrectPass2026!", db)
    print(f"2. Вхід з хибним паролем: {wrong}")

    # Порожній логін (викликає ValueError всередині login)
    print("3. Вхід із порожнім значенням:")
    login("", "SomeValidPassword123!", db)

    # Занадто короткий пароль (викликає ValidationError всередині login)
    print("4. Вхід із занадто коротким паролем:")
    login("soc_lead", "123", db)

    # 4. Пряма демонстрація перехоплення винятків через try-except
    print("\n--- Демонстрація перехоплення конкретних винятків ---")

    # Демонстрація FileNotFoundError
    print("1. Тест FileNotFoundError:")
    try:
        with open("labs/lab01/data/non_existing_file.txt", "r") as f:
            f.read()
    except FileNotFoundError as err:
        print(f"   [Перехоплено FileNotFoundError]: {err}")

    # Демонстрація ValidationError
    print("2. Тест ValidationError:")
    try:
        generate_hash("short_pwd", PERSONAL_SALT)
    except ValidationError as err:
        print(f"   [Перехоплено ValidationError]: {err}")

    # Демонстрація ValueError
    print("3. Тест ValueError:")
    try:
        generate_hash("", PERSONAL_SALT)
    except ValueError as err:
        print(f"   [Перехоплено ValueError]: {err}")

    print("\n[+] Усі сценарії помилок успішно відпрацьовані без падіння програми.")


if __name__ == "__main__":
    run_task3()