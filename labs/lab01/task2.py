"""Завдання 2: Багаторівнева система контролю доступу."""

import os
import sys

sys.path.append(
    os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))
)
from shared.student import VARIANT_NUMBER

users = {
    "admin001": {
        "role": "administrator",
        "clearance": 4,
        "department": "IT",
        "active": True,
    },
    "user123": {
        "role": "analyst",
        "clearance": 2,
        "department": "Security",
        "active": True,
    },
    "guest789": {
        "role": "guest",
        "clearance": 1,
        "department": "External",
        "active": True,
    },
    "manager456": {
        "role": "manager",
        "clearance": 3,
        "department": "Operations",
        "active": True,
    },
    "contractor99": {
        "role": "contractor",
        "clearance": 1,
        "department": "External",
        "active": False,
    },
}

resources = [
    ("database_backup", 4),
    ("user_logs", 2),
    ("public_docs", 1),
    ("financial_reports", 3),
    ("system_config", 4),
    ("training_materials", 1),
    ("security_policies", 3),
    ("audit_logs", 4),
    ("employee_data", 3),
    ("temp_files", 1),
]

security_levels = ("Public", "Internal", "Confidential", "Secret")
blocked_users = {"contractor99", "temp_user", "suspended_acc"}


def check_access(user_id: str, resource_name: str, res_level: int) -> str:
    if user_id not in users:
        return "DENY (User not found)"
    if user_id in blocked_users:
        return "DENY (User is blocked)"
    if not users[user_id]["active"]:
        return "DENY (Account inactive)"
    if users[user_id]["clearance"] >= res_level:
        return "ALLOW"
    return "DENY (Insufficient clearance)"


def run_task2() -> None:
    print(f"--- Завдання 2 | Варіант {VARIANT_NUMBER} ---")

    print("Список ресурсів системи:")
    for res_name, level_idx in resources:
        level_str = security_levels[level_idx - 1]
        print(f" - {res_name:<20}: Рівень {level_idx} ({level_str})")

    print("\nРезультати перевірки доступу:")
    for user_id in users:
        for res_name, res_level in resources:
            status = check_access(user_id, res_name, res_level)
            print(f"user={user_id:<14} resource={res_name:<20} -> {status}")
    print()


if __name__ == "__main__":
    run_task2()