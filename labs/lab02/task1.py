import hashlib
import hmac
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone

PBKDF2_ITERATIONS = 100_000
SESSION_TIMEOUT_SEC = 900
EMAIL_REGEX = re.compile(r"^[a-zA-Z][a-zA-Z0-9_]{2,63}@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")


class User:
    """Клас облікового запису користувача."""

    def __init__(
        self, username: str, email: str, role: str = "user", active: bool = True
    ) -> None:
        self.username = username
        self._email = ""
        self.email = email
        self.role = role
        self.active = active
        self.__password_salt: bytes = os.urandom(16)
        self.__password_hash: bytes = b""

    @property
    def email(self) -> str:
        return self._email

    @email.setter
    def email(self, value: str) -> None:
        if not EMAIL_REGEX.match(value):
            raise ValueError(
                f"Некоректний email: '{value}'. Локальна частина має починатися "
                "з латинської літери (3-64 символи: літери, цифри, _)."
            )
        self._email = value

    def set_password(self, password: str) -> None:
        """Хешує та записує пароль з використанням PBKDF2-HMAC-SHA256."""
        if not password:
            raise ValueError("Пароль не може бути порожнім.")
        self.__password_salt = os.urandom(16)
        self.__password_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            self.__password_salt,
            PBKDF2_ITERATIONS,
        )

    def check_password(self, password: str) -> bool:
        """Безпечно перевіряє пароль за хешем без уразливості до timing-атак."""
        if not self.__password_hash or not password:
            return False
        computed_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            self.__password_salt,
            PBKDF2_ITERATIONS,
        )
        return hmac.compare_digest(self.__password_hash, computed_hash)

    def deactivate(self) -> None:
        self.active = False

    def __str__(self) -> str:
        status = "Active" if self.active else "Inactive"
        return f"User(username='{self.username}', role='{self.role}', email='{self.email}', status='{status}')"


class Admin(User):
    """Клас адміністратора з керуванням дозволами (наслідування від User)."""

    def __init__(
        self,
        username: str,
        email: str,
        permissions: set[str] | None = None,
        active: bool = True,
    ) -> None:
        super().__init__(username=username, email=email, role="admin", active=active)
        self.permissions: set[str] = (
            set(permissions) if permissions is not None else set()
        )

    def grant_permission(self, permission: str) -> None:
        self.permissions.add(permission)

    def revoke_permission(self, permission: str) -> None:
        self.permissions.discard(permission)

    def has_permission(self, permission: str) -> bool:
        return permission in self.permissions

    def __str__(self) -> str:
        perms = ", ".join(sorted(self.permissions)) or "None"
        return f"Admin(username='{self.username}', permissions=[{perms}], active={self.active})"


class Session:
    """Клас керування поточною сесією користувача."""

    def __init__(self, ip: str) -> None:
        self.ip = ip
        now = datetime.now(timezone.utc)
        self.login_time = now
        self.last_activity = now

    def touch(self) -> None:
        """Оновлює час останньої активності."""
        self.last_activity = datetime.now(timezone.utc)

    def is_active(self, timeout_sec: int) -> bool:
        """Перевіряє, чи не минув таймаут активності сесії."""
        if timeout_sec <= 0:
            raise ValueError("timeout_sec повинен бути додатним числом.")
        elapsed = (datetime.now(timezone.utc) - self.last_activity).total_seconds()
        return elapsed < timeout_sec


@dataclass(frozen=True)
class AuditEntry:
    """Запис журналу подій безпеки."""

    timestamp: datetime
    username: str
    action: str


class AuditLog:
    """Журнал аудиту подій безпеки."""

    def __init__(self) -> None:
        self._entries: list[AuditEntry] = []

    def add_log(self, username: str, action: str) -> None:
        entry = AuditEntry(
            timestamp=datetime.now(timezone.utc),
            username=username,
            action=action,
        )
        self._entries.append(entry)

    def show_all(self) -> list[str]:
        return [
            f"[{entry.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}] {entry.username} -> {entry.action}"
            for entry in self._entries
        ]


class UserAccount:
    """Клас облікового запису (композиція: User, Session, AuditLog)."""

    def __init__(
        self,
        user: User,
        session: Session | None = None,
        audit_log: AuditLog | None = None,
    ) -> None:
        self.user = user
        self.session = session
        self.audit_log = audit_log if audit_log is not None else AuditLog()

    def login(self, username: str, password: str, ip: str) -> bool:
        """Автентифікація: перевірка активності, пароля та реєстрація сесії."""
        if self.user.username != username or not self.user.active:
            self.audit_log.add_log(username, "login_failure")
            return False

        if not self.user.check_password(password):
            self.audit_log.add_log(username, "login_failure")
            return False

        self.session = Session(ip=ip)
        self.session.touch()
        self.audit_log.add_log(username, "login_success")
        return True

    def is_authenticated(self) -> bool:
        """Перевіряє, чи сесія відкрита та активна без її подовження."""
        if self.session is None:
            return False
        return self.session.is_active(SESSION_TIMEOUT_SEC)

    def logout(self) -> None:
        """Завершує активну сесію та реєструє подію."""
        user_name = self.user.username
        self.session = None
        self.audit_log.add_log(user_name, "logout")

    def __getitem__(self, key: str):
        allowed_attrs = {"user", "session", "audit_log"}
        if key in allowed_attrs:
            return getattr(self, key)
        raise KeyError(f"Доступ до поля '{key}' заборонено або поле відсутнє.")

    def __setitem__(self, key: str, value) -> None:
        if key == "user":
            if not isinstance(value, User):
                raise TypeError("Значення для 'user' повинно бути екземпляром User.")
            self.user = value
        elif key == "session":
            if value is not None and not isinstance(value, Session):
                raise TypeError(
                    "Значення для 'session' повинно бути екземпляром Session або None."
                )
            self.session = value
        elif key == "audit_log":
            if not isinstance(value, AuditLog):
                raise TypeError(
                    "Значення для 'audit_log' повинно бути екземпляром AuditLog."
                )
            self.audit_log = value
        else:
            raise KeyError(f"Зміна поля '{key}' заборонена.")
