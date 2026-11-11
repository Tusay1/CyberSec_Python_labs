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
