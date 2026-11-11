"""Перевірка відповіді NVD і застосування правила варіанта.

Функції працюють лише з переданими аргументами: не читають файлів,
змінних середовища, не виконують HTTP-запитів і нічого не друкують.
Порушення контракту даних → ValueError.
"""

import math
from typing import Any

VARIANT_COUNT = 15

# Варіант → (поріг T, поле cvssData, очікуване значення)
RULES: dict[int, tuple[float, str, str]] = {
    1: (7.0, "attackVector", "NETWORK"),
    2: (8.0, "attackComplexity", "LOW"),
    3: (7.0, "privilegesRequired", "NONE"),
    4: (8.0, "userInteraction", "NONE"),
    5: (7.0, "confidentialityImpact", "HIGH"),
    6: (7.0, "integrityImpact", "HIGH"),
    7: (7.0, "availabilityImpact", "HIGH"),
    8: (9.0, "scope", "CHANGED"),
    9: (5.0, "attackVector", "LOCAL"),
    10: (6.0, "privilegesRequired", "LOW"),
    11: (6.0, "userInteraction", "REQUIRED"),
    12: (6.0, "confidentialityImpact", "LOW"),
    13: (6.0, "integrityImpact", "LOW"),
    14: (6.0, "availabilityImpact", "LOW"),
    15: (8.0, "attackComplexity", "HIGH"),
}


class DataFormatError(ValueError):
    """Відповідь NVD або аргументи порушують очікуваний контракт."""


_IMPACT = frozenset({"NONE", "LOW", "HIGH"})
ALLOWED_VALUES: dict[str, frozenset[str]] = {
    "attackVector": frozenset({"NETWORK", "ADJACENT_NETWORK", "LOCAL", "PHYSICAL"}),
    "attackComplexity": frozenset({"LOW", "HIGH"}),
    "privilegesRequired": _IMPACT,
    "userInteraction": frozenset({"NONE", "REQUIRED"}),
    "scope": frozenset({"UNCHANGED", "CHANGED"}),
    "confidentialityImpact": _IMPACT,
    "integrityImpact": _IMPACT,
    "availabilityImpact": _IMPACT,
}

REPORT_KEYS = (
    "cve_id",
    "variant",
    "description",
    "vuln_status",
    "cvss_version",
    "score",
    "score_source",
    "vector",
    "rule",
    "observed",
    "decision",
)


def _optional_text(container: dict, key: str, where: str) -> str | None:
    """Відсутнє поле → None; наявне має бути непорожнім рядком."""
    if key not in container:
        return None
    value = container[key]
    if not isinstance(value, str) or not value.strip():
        raise DataFormatError(f"{where}.{key} має бути непорожнім рядком")
    return value


def _english_description(cve: dict) -> str | None:
    """Перший непорожній опис англійською або None."""
    if "descriptions" not in cve:
        return None
    descriptions = cve["descriptions"]
    if not isinstance(descriptions, list):
        raise DataFormatError("cve.descriptions має бути списком")
    for item in descriptions:
        if not isinstance(item, dict):
            raise DataFormatError("елементи descriptions мають бути об'єктами")
        lang, value = item.get("lang"), item.get("value")
        if not isinstance(lang, str) or not isinstance(value, str):
            raise DataFormatError("descriptions: lang і value мають бути рядками")
    for item in descriptions:
        if item["lang"] == "en" and item["value"].strip():
            return item["value"]
    return None


def _select_metric(cve: dict) -> dict | None:
    """Вибрати оцінку CVSS v3.1: перший Primary, інакше перший елемент."""
    if "metrics" not in cve:
        return None
    metrics = cve["metrics"]
    if not isinstance(metrics, dict):
        raise DataFormatError("cve.metrics має бути об'єктом")
    if "cvssMetricV31" not in metrics:
        return None
    entries = metrics["cvssMetricV31"]
    if not isinstance(entries, list):
        raise DataFormatError("metrics.cvssMetricV31 має бути списком")
    if not entries:
        return None
    if not all(isinstance(entry, dict) for entry in entries):
        raise DataFormatError("елементи cvssMetricV31 мають бути об'єктами")
    return next(
        (entry for entry in entries if entry.get("type") == "Primary"), entries[0]
    )


def _parse_metric(entry: dict) -> dict:
    """Перевірити вибрану оцінку і повернути її внутрішнє подання."""
    cvss = entry.get("cvssData")
    if not isinstance(cvss, dict):
        raise DataFormatError("cvssData має бути об'єктом")

    score = cvss.get("baseScore")
    if (
        isinstance(score, bool)
        or not isinstance(score, (int, float))
        or not math.isfinite(score)
        or not 0 <= score <= 10
    ):
        raise DataFormatError("baseScore має бути скінченним числом від 0 до 10")

    version = _optional_text(cvss, "version", "cvssData")
    if version is not None and version != "3.1":
        raise DataFormatError("cvssData.version має дорівнювати '3.1'")

    return {
        "score": float(score),
        "version": version,
        "vector": _optional_text(cvss, "vectorString", "cvssData"),
        "source": _optional_text(entry, "source", "cvssMetricV31[]"),
        # Копія лише рядкових полів метрики: payload не змінюється.
        "fields": {key: cvss[key] for key in ALLOWED_VALUES if key in cvss},
    }


def extract_record(payload: Any, cve_id: str) -> dict | None:
    """Перевірити відповідь NVD і повернути внутрішній запис або None.

    Формат запису::

        {
            "cve_id": str,
            "vuln_status": str | None,     # None — статус відсутній
            "description": str | None,     # перший непорожній англійський опис
            "metric": None | {             # None — оцінки v3.1 немає / не аналізувалась
                "score": float,            # baseScore 0–10
                "version": str | None,     # "3.1" або None
                "vector": str | None,
                "source": str | None,
                "fields": {назва_поля_cvssData: значення, ...},
            },
        }

    None повертається, якщо vulnerabilities — порожній список (не знайдено).
    Для статусу Rejected або відсутнього статусу оцінки не аналізуються.
    """
    if not isinstance(payload, dict):
        raise DataFormatError("відповідь має бути JSON-об'єктом")
    vulnerabilities = payload.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        raise DataFormatError("поле vulnerabilities має бути списком")
    if not vulnerabilities:
        return None
    if len(vulnerabilities) > 1:
        raise DataFormatError(
            "для точного ідентифікатора очікується не більше одного запису"
        )

    item = vulnerabilities[0]
    if not isinstance(item, dict) or not isinstance(item.get("cve"), dict):
        raise DataFormatError("елемент vulnerabilities має містити об'єкт cve")
    cve = item["cve"]
    if cve.get("id") != cve_id:
        raise DataFormatError("cve.id не збігається із запитаним ідентифікатором")

    status = _optional_text(cve, "vulnStatus", "cve")
    record = {
        "cve_id": cve_id,
        "vuln_status": status,
        "description": _english_description(cve),
        "metric": None,
    }
    if status is None or status == "Rejected":
        return record

    entry = _select_metric(cve)
    if entry is not None:
        record["metric"] = _parse_metric(entry)
    return record


def validate_variant(variant: Any) -> int:
    """Перевірити, що номер варіанта — int (не bool) від 1 до 15."""
    if isinstance(variant, bool) or not isinstance(variant, int):
        raise DataFormatError("номер варіанта має бути цілим числом")
    if not 1 <= variant <= VARIANT_COUNT:
        raise DataFormatError(f"номер варіанта має бути від 1 до {VARIANT_COUNT}")
    return variant


def build_report(record: dict | None, cve_id: str, variant: int) -> dict:
    """Застосувати правило варіанта і повернути словник звіту.

    Стани перевіряються в порядку: not_found → rejected →
    insufficient_data → review → other.
    """
    variant = validate_variant(variant)
    threshold, field, expected = RULES[variant]
    report: dict[str, Any] = dict.fromkeys(REPORT_KEYS)
    report.update(
        cve_id=cve_id,
        variant=variant,
        rule={"threshold": threshold, "field": field, "expected": expected},
    )

    if record is None:
        report["decision"] = "not_found"
        return report

    report["vuln_status"] = record["vuln_status"]
    report["description"] = record["description"]
    if record["vuln_status"] == "Rejected":
        report["decision"] = "rejected"
        return report

    metric = record["metric"]
    if record["vuln_status"] is None or metric is None:
        report["decision"] = "insufficient_data"
        return report

    report.update(
        cvss_version=metric["version"],
        score=metric["score"],
        score_source=metric["source"],
        vector=metric["vector"],
    )
    if field not in metric["fields"]:
        report["decision"] = "insufficient_data"
        return report

    observed = metric["fields"][field]
    if not isinstance(observed, str) or observed not in ALLOWED_VALUES[field]:
        raise DataFormatError(f"cvssData.{field} має недопустиме значення")
    report["observed"] = observed

    matches = metric["score"] >= threshold and observed == expected
    report["decision"] = "review" if matches else "other"
    return report
