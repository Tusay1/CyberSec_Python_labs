import os
import random
import string
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

passwords = [
    "password123",
    "Qwerty!2023",
    "admin",
    "MyP@ssword",
    "123456",
    "SecurePass!",
    "test",
    "P@ssword123",
    "welcome",
    "StrongP@ss1",
]

criteria = {
    "min_length": 8,
    "require_digits": True,
    "require_upper": True,
    "require_special": True,
}

forbidden_passwords = {
    "password",
    "123456",
    "admin",
    "test",
    "welcome",
    "qwerty",
}


def evaluate_password(pwd: str, all_passwords: list[str]) -> str:
    min_len = criteria["min_length"]

    if pwd in forbidden_passwords or len(pwd) < min_len:
        return "Заборонений"

    has_digit = any(c.isdigit() for c in pwd)
    has_upper = any(c.isupper() for c in pwd)
    has_lower = any(c.islower() for c in pwd)
    has_special = any(c in string.punctuation for c in pwd)

    meets_all = len(pwd) >= min_len and has_digit and has_upper and has_special

    if meets_all:
        if len(pwd) >= min_len + 4 and all_passwords.count(pwd) == 1:
            return "Дуже сильний"
        return "Сильний"

    if len(pwd) >= min_len and (has_digit or has_upper or has_lower or has_special):
        return "Середній"

    if has_digit or has_upper or has_lower or has_special:
        return "Слабкий"

    return "Заборонений"


def run_task1() -> None:
    print(f"--- Завдання 1 | {STUDENT_NAME} ({GROUP_NAME}), Вар. {VARIANT_NUMBER} ---")

    test_passwords = passwords.copy()
    random_indices = random.sample(range(len(passwords)), 3)
    for idx in random_indices:
        test_passwords.append(passwords[idx])

    print(f"{'№':<3} | {'Пароль':<20} | {'Статус надійності'}")
    print("-" * 48)
    for i, pwd in enumerate(test_passwords, start=1):
        status = evaluate_password(pwd, test_passwords)
        print(f"{i:<3} | {pwd:<20} | {status}")
    print()


if __name__ == "__main__":
    run_task1()
