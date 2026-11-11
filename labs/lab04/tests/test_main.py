"""Інтеграційні тести CLI: локальний режим, помилки, коди завершення."""

import json
from unittest.mock import Mock

import pytest

from labs.lab04 import api_client, main
from labs.lab04.api_client import FetchError

from .conftest import SAMPLE_CVE, SAMPLE_PATH


def run(capsys, *argv):
    code = main.main(list(argv))
    out, err = capsys.readouterr()
    return code, out, err


def test_local_mode_builds_report_without_network(monkeypatch, capsys):
    fake_fetch = Mock(side_effect=AssertionError("мережа не повинна викликатися"))
    monkeypatch.setattr(main, "fetch_response", fake_fetch)

    code, out, err = run(capsys, "--cve", SAMPLE_CVE, "--input", str(SAMPLE_PATH))
    assert code == 0
    assert err == ""
    report = json.loads(out)
    assert report["decision"] == "review"
    assert report["variant"] == 1
    assert report["observed"] == "NETWORK"
    fake_fetch.assert_not_called()


def test_output_is_single_json_object_with_unicode(tmp_path, sample, cve, capsys):
    cve["descriptions"] = [{"lang": "en", "value": "Опис із кирилицею"}]
    path = tmp_path / "nvd.json"
    path.write_text(json.dumps(sample), encoding="utf-8")

    code, out, _ = run(capsys, "--cve", SAMPLE_CVE, "--input", str(path))
    assert code == 0
    assert "Опис із кирилицею" in out  # ensure_ascii=False
    assert json.loads(out)["description"] == "Опис із кирилицею"


def test_not_found_from_file_returns_zero(tmp_path, capsys):
    path = tmp_path / "empty.json"
    path.write_text('{"vulnerabilities": []}', encoding="utf-8")
    code, out, _ = run(capsys, "--cve", SAMPLE_CVE, "--input", str(path))
    assert code == 0
    assert json.loads(out)["decision"] == "not_found"


def test_invalid_json_file(tmp_path, capsys):
    path = tmp_path / "broken.json"
    path.write_text("{", encoding="utf-8")
    code, out, err = run(capsys, "--cve", SAMPLE_CVE, "--input", str(path))
    assert code == 1
    assert out == ""
    assert "некоректний JSON" in err
    assert "Traceback" not in err


def test_missing_file(tmp_path, capsys):
    code, out, err = run(
        capsys, "--cve", SAMPLE_CVE, "--input", str(tmp_path / "missing.json")
    )
    assert code == 1
    assert out == ""
    assert "не знайдено" in err


def test_invalid_structure_in_file(tmp_path, sample, primary, capsys):
    primary["baseScore"] = "9.8"
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(sample), encoding="utf-8")
    code, out, err = run(capsys, "--cve", SAMPLE_CVE, "--input", str(path))
    assert code == 1
    assert out == ""
    assert "Помилка даних" in err


def test_network_mode_uses_fetch(monkeypatch, sample, capsys):
    fake_fetch = Mock(return_value=sample)
    monkeypatch.setattr(main, "fetch_response", fake_fetch)
    code, out, _ = run(capsys, "--cve", SAMPLE_CVE)
    assert code == 0
    fake_fetch.assert_called_once_with(SAMPLE_CVE)
    assert json.loads(out)["decision"] == "review"


def test_network_error_returns_one(monkeypatch, capsys):
    monkeypatch.setattr(
        main, "fetch_response", Mock(side_effect=FetchError("NVD повернув 503"))
    )
    code, out, err = run(capsys, "--cve", SAMPLE_CVE)
    assert code == 1
    assert out == ""
    assert "503" in err


def test_real_client_with_mocked_requests(monkeypatch, sample, capsys):
    """Справжній fetch_response + підмінений requests.get з ключем."""
    monkeypatch.setenv("NVD_API_KEY", "fake-key")
    response = Mock(status_code=200)
    response.json.return_value = sample
    fake_get = Mock(return_value=response)
    monkeypatch.setattr(api_client.requests, "get", fake_get)

    code, out, err = run(capsys, "--cve", SAMPLE_CVE)
    assert code == 0
    assert "fake-key" not in out + err
    assert fake_get.call_args.kwargs["headers"]["apiKey"] == "fake-key"


@pytest.mark.parametrize(
    "cve_id", ["cve-2099-10001", "CVE-99-1", "CVE-2099-123", "CVE-2099-10001x", ""]
)
def test_invalid_cve_argument_exits_with_two(cve_id, capsys):
    with pytest.raises(SystemExit) as exc_info:
        main.main(["--cve", cve_id])
    assert exc_info.value.code == 2
    assert "некоректний ідентифікатор" in capsys.readouterr().err


def test_missing_cve_argument_exits_with_two():
    with pytest.raises(SystemExit) as exc_info:
        main.main([])
    assert exc_info.value.code == 2


@pytest.mark.parametrize("number", [0, -3, True, "1", 1.5, None])
def test_invalid_variant_number_returns_two(monkeypatch, capsys, number):
    monkeypatch.setattr(main, "VARIANT_NUMBER", number)
    code, out, err = run(capsys, "--cve", SAMPLE_CVE, "--input", str(SAMPLE_PATH))
    assert code == 2
    assert out == ""
    assert "варіанта" in err


@pytest.mark.parametrize(("number", "expected"), [(1, 1), (9, 9), (15, 15), (16, 1)])
def test_variant_number_from_student(monkeypatch, capsys, number, expected):
    monkeypatch.setattr(main, "VARIANT_NUMBER", number)
    code, out, _ = run(capsys, "--cve", SAMPLE_CVE, "--input", str(SAMPLE_PATH))
    assert code == 0
    assert json.loads(out)["variant"] == expected
