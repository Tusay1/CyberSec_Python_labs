"""Модульні тести analysis.py: правило варіанта 1 і перевірка даних."""

import copy

import pytest

from labs.lab04.analysis import build_report, extract_record

from .conftest import SAMPLE_CVE

VARIANT = 1  # attackVector == NETWORK і score >= 7.0


def report_for(payload, variant=VARIANT, cve_id=SAMPLE_CVE):
    return build_report(extract_record(payload, cve_id), cve_id, variant)


# ----------------------------------------------------------- межа порогу


@pytest.mark.parametrize(
    ("score", "expected"),
    [(6.9, "other"), (7.0, "review"), (7.1, "review"), (0, "other"), (10, "review")],
)
def test_threshold_boundary(sample, primary, score, expected):
    primary["baseScore"] = score
    assert report_for(sample)["decision"] == expected


def test_wrong_field_value_with_high_score(sample, primary):
    primary["attackVector"] = "LOCAL"
    report = report_for(sample)
    assert report["score"] == 9.8
    assert report["observed"] == "LOCAL"
    assert report["decision"] == "other"


def test_sample_full_report(sample):
    assert report_for(sample) == {
        "cve_id": "CVE-2099-10001",
        "variant": 1,
        "description": "Synthetic vulnerability for offline API testing.",
        "vuln_status": "Analyzed",
        "cvss_version": "3.1",
        "score": 9.8,
        "score_source": "nvd@nist.gov",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "rule": {"threshold": 7.0, "field": "attackVector", "expected": "NETWORK"},
        "observed": "NETWORK",
        "decision": "review",
    }


@pytest.mark.parametrize(
    ("variant", "expected"),
    [(v, "review") for v in range(1, 8)] + [(v, "other") for v in range(8, 16)],
)
def test_sample_decision_for_all_variants(sample, variant, expected):
    assert report_for(sample, variant=variant)["decision"] == expected


def test_payload_is_not_modified(sample):
    before = copy.deepcopy(sample)
    report_for(sample)
    assert sample == before


# ------------------------------------------------------ стани без оцінки


def test_not_found():
    report = report_for({"vulnerabilities": []})
    assert report["decision"] == "not_found"
    assert report["cve_id"] == SAMPLE_CVE
    assert report["variant"] == VARIANT
    assert report["rule"] == {
        "threshold": 7.0,
        "field": "attackVector",
        "expected": "NETWORK",
    }
    for key in (
        "description",
        "vuln_status",
        "cvss_version",
        "score",
        "score_source",
        "vector",
        "observed",
    ):
        assert report[key] is None


def test_rejected_ignores_high_score(sample, cve):
    cve["vulnStatus"] = "Rejected"
    report = report_for(sample)
    assert report["decision"] == "rejected"
    assert report["vuln_status"] == "Rejected"
    assert report["description"] == "Synthetic vulnerability for offline API testing."
    assert report["score"] is None
    assert report["observed"] is None


def test_missing_status_gives_insufficient_data(sample, cve):
    del cve["vulnStatus"]
    report = report_for(sample)
    assert report["decision"] == "insufficient_data"
    assert report["vuln_status"] is None
    assert report["score"] is None


@pytest.mark.parametrize("mutation", ["no_metrics", "no_v31", "empty_v31"])
def test_missing_score_gives_insufficient_data(sample, cve, mutation):
    if mutation == "no_metrics":
        del cve["metrics"]
    elif mutation == "no_v31":
        del cve["metrics"]["cvssMetricV31"]
    else:
        cve["metrics"]["cvssMetricV31"] = []
    report = report_for(sample)
    assert report["decision"] == "insufficient_data"
    assert report["vuln_status"] == "Analyzed"
    assert report["score"] is None


def test_missing_variant_field_gives_insufficient_data(sample, primary):
    del primary["attackVector"]
    report = report_for(sample)
    assert report["decision"] == "insufficient_data"
    assert report["score"] == 9.8
    assert report["observed"] is None


# --------------------------------------------------- вибір Primary/Secondary


def test_primary_has_priority_over_earlier_secondary(sample, cve):
    entries = cve["metrics"]["cvssMetricV31"]
    assert entries[0]["type"] == "Secondary"
    report = report_for(sample)
    assert report["score_source"] == "nvd@nist.gov"
    assert report["score"] == 9.8


def test_without_primary_first_entry_is_selected(sample, cve):
    for entry in cve["metrics"]["cvssMetricV31"]:
        entry["type"] = "Secondary"
    report = report_for(sample)
    assert report["score_source"] == "cna@example.org"
    assert report["score"] == 4.2
    assert report["observed"] == "LOCAL"
    assert report["decision"] == "other"


def test_optional_report_fields_absent_become_null(sample, cve, primary):
    del primary["version"], primary["vectorString"]
    for entry in cve["metrics"]["cvssMetricV31"]:
        entry.pop("source")
    report = report_for(sample)
    assert report["cvss_version"] is None
    assert report["vector"] is None
    assert report["score_source"] is None
    assert report["decision"] == "review"


def test_description_without_english_is_null(sample, cve):
    cve["descriptions"] = [{"lang": "uk", "value": "Лише українською"}]
    assert report_for(sample)["description"] is None


# ----------------------------------------------------------- помилки даних


@pytest.mark.parametrize("value", [None, "network", "", 1, ["NETWORK"]])
def test_invalid_variant_field_raises(sample, primary, value):
    primary["attackVector"] = value
    with pytest.raises(ValueError):
        report_for(sample)


@pytest.mark.parametrize(
    "score", ["9.8", True, None, -0.1, 10.1, float("inf"), float("nan")]
)
def test_invalid_base_score_raises(sample, primary, score):
    primary["baseScore"] = score
    with pytest.raises(ValueError):
        report_for(sample)


def test_missing_base_score_raises(sample, primary):
    del primary["baseScore"]
    with pytest.raises(ValueError):
        report_for(sample)


@pytest.mark.parametrize(
    "payload",
    [
        [],
        "text",
        {},
        {"vulnerabilities": None},
        {"vulnerabilities": [{}]},
        {"vulnerabilities": [{"cve": []}]},
    ],
)
def test_invalid_payload_structure_raises(payload):
    with pytest.raises(ValueError):
        extract_record(payload, SAMPLE_CVE)


def test_two_vulnerabilities_raise(sample):
    sample["vulnerabilities"].append(copy.deepcopy(sample["vulnerabilities"][0]))
    with pytest.raises(ValueError):
        extract_record(sample, SAMPLE_CVE)


def test_other_cve_id_raises(sample):
    with pytest.raises(ValueError):
        extract_record(sample, "CVE-2099-99999")


@pytest.mark.parametrize(
    ("path", "value"),
    [
        ("metrics", None),
        ("metrics", []),
        ("cvssMetricV31", None),
        ("cvssMetricV31", {}),
        ("cvssMetricV31", ["not a dict"]),
        ("vulnStatus", ""),
        ("vulnStatus", 5),
        ("descriptions", "text"),
    ],
)
def test_invalid_present_fields_raise(sample, cve, path, value):
    if path == "cvssMetricV31":
        cve["metrics"]["cvssMetricV31"] = value
    else:
        cve[path] = value
    with pytest.raises(ValueError):
        report_for(sample)


@pytest.mark.parametrize(
    ("key", "value"),
    [("version", "3.0"), ("version", ""), ("vectorString", 5), ("vectorString", " ")],
)
def test_invalid_optional_cvss_fields_raise(sample, primary, key, value):
    primary[key] = value
    with pytest.raises(ValueError):
        report_for(sample)


def test_cvss_data_must_be_object(sample, cve):
    cve["metrics"]["cvssMetricV31"][1]["cvssData"] = None
    with pytest.raises(ValueError):
        report_for(sample)


@pytest.mark.parametrize("variant", [0, 16, -1, True, "1", 1.0])
def test_build_report_rejects_bad_variant(variant):
    with pytest.raises(ValueError):
        build_report(None, SAMPLE_CVE, variant)
