"""Головна точка входу для запуску демонстрації або аналізатора."""

import argparse
import sys
import time
from labs.lab02.task1 import Admin, AuditLog, User, UserAccount
from labs.lab02.task2 import run_analyzer


def run_demo() -> None:
    print("=== [DEMO] Завдання 1: Моделювання облікового запису та ООП ===\n")

    user = User(username="alice", email="alice@company.com")
    user.set_password("SecurePassword2026!")
    print(f"1. Створено користувача: {user}")

    print("\n2. Валідація email через @property (демонстрація обробки ValueError):")
    try:
        user.email = "bad-email@"
    except ValueError as exc:
        print(f"   [Очікуване виключення ValueError перехоплено]: {exc}")
    user.email = "alice_work@corp.ua"
    print(f"   [Успішно оновлено]: {user.email}")

    print("\n3. Наслідування: клас Admin:")
    admin = Admin(username="root_admin", email="admin@corp.ua", permissions={"manage_users"})
    admin.grant_permission("firewall_write")
    print(f"   {admin}")
    print(f"   Чи є дозвіл 'firewall_write': {admin.has_permission('firewall_write')}")

    print("\n4. Композиція UserAccount та автентифікація:")
    audit = AuditLog()
    account = UserAccount(user=user, audit_log=audit)

    fail_auth = account.login("alice", "WrongPassword", ip="192.168.1.100")
    print(f"   Вхід із невірним паролем: {fail_auth}")

    success_auth = account.login("alice", "SecurePassword2026!", ip="192.168.1.100")
    print(f"   Вхід із вірним паролем:   {success_auth}")
    print(f"   Сесія активна:            {account.is_authenticated()}")

    print("\n5. Тест таймауту сесії:")
    time.sleep(1.1)
    timeout_test = account.session.is_active(timeout_sec=1)
    print(f"   Чи активна сесія з таймаутом 1 сек: {timeout_test}")

    print("\n6. Завершення сесії (Logout):")
    account.logout()
    print(f"   Сесія після logout: {account.session}")

    print("\n7. Спеціальні методи __getitem__ та __setitem__ (демонстрація KeyError):")
    account["user"] = User(username="bob", email="bob@company.com")
    print(f"   Отримано ім'я користувача через account['user'].username: {account['user'].username}")
    try:
        _ = account["password_hash"]
    except KeyError as exc:
        print(f"   [Спроба доступу до приватного поля перехоплена KeyError]: {exc}")

    print("\n8. Журнал аудиту (AuditLog):")
    for log_record in audit.show_all():
        print(f"   {log_record}")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="python -m labs.lab02.main",
        description="ЛР №2: Розробка консольних утиліт кібербезпеки",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("demo", help="Запустити демонстрацію Завдання 1 (ООП)")

    analyze_parser = subparsers.add_parser("analyze", help="Запустити CLI-утиліти (Завдання 2)")
    analyze_parser.add_argument("--log-file", required=True, help="Шлях до файлу access.log")
    analyze_parser.add_argument("--output", help="Шлях для збереження звіту")
    analyze_parser.add_argument("--min-status", type=int, default=400, help="Мінімальний HTTP-код помилки")
    analyze_parser.add_argument("--top", type=int, default=5, help="Кількість топ-IP для виводу")
    analyze_parser.add_argument("--format", choices=["json", "csv"], default="json", help="Формат звіту")

    args = parser.parse_args()

    if args.command == "demo":
        run_demo()
    elif args.command == "analyze":
        run_analyzer(
            log_file=args.log_file,
            output=args.output,
            min_status=args.min_status,
            top=args.top,
            out_format=args.format,
        )
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()