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
