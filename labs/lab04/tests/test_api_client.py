"""Тести HTTP-клієнта з підміною requests.get."""

from unittest.mock import Mock

import pytest
import requests

from labs.lab04 import api_client
from labs.lab04.api_client import FetchError

URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVE = "CVE-2099-10001"


def make_response(status_code=200, payload=None, json_error=None):
    response = Mock(spec=requests.Response)
    response.status_code = status_code
    response.headers = {"Content-Type": "application/json; charset=utf-8"}
    if json_error is not None:
        response.json.side_effect = json_error
    else:
        response.json.return_value = payload
    return response


def test_fetch_uses_expected_request(monkeypatch):
    payload = {"startIndex": 0, "totalResults": 0, "vulnerabilities": []}
    response = make_response(payload=payload)
    fake_get = Mock(return_value=response)
    monkeypatch.setattr(api_client.requests, "get", fake_get)

    assert api_client.fetch_response(CVE) == payload
    fake_get.assert_called_once_with(
        URL,
        params={"cveId": CVE},
        headers={"Accept": "application/json"},
        timeout=(3.05, 10),
        allow_redirects=False,
    )
    response.raise_for_status.assert_called_once_with()


def test_fetch_sends_api_key_in_header_not_url(monkeypatch):
    monkeypatch.setenv("NVD_API_KEY", "  fake-test-key  ")
    fake_get = Mock(return_value=make_response(payload={"vulnerabilities": []}))
    monkeypatch.setattr(api_client.requests, "get", fake_get)

    api_client.fetch_response(CVE)
    kwargs = fake_get.call_args.kwargs
    assert kwargs["headers"] == {
        "Accept": "application/json",
        "apiKey": "fake-test-key",
    }
    assert kwargs["params"] == {"cveId": CVE}
    assert "fake-test-key" not in fake_get.call_args.args[0]


@pytest.mark.parametrize("value", [None, "", "   "])
def test_build_headers_without_key(monkeypatch, value):
    if value is not None:
        monkeypatch.setenv("NVD_API_KEY", value)
    assert api_client.build_headers() == {"Accept": "application/json"}


def test_build_headers_reads_key_at_call_time(monkeypatch):
    assert "apiKey" not in api_client.build_headers()
    monkeypatch.setenv("NVD_API_KEY", "fake-key")
    assert api_client.build_headers()["apiKey"] == "fake-key"


@pytest.mark.parametrize(
    "error",
    [
        requests.exceptions.ConnectTimeout("timeout"),
        requests.exceptions.ReadTimeout("timeout"),
        requests.exceptions.ConnectionError("down"),
        requests.exceptions.TooManyRedirects("loop"),
    ],
)
def test_network_errors_raise_fetch_error(monkeypatch, error):
    monkeypatch.setattr(api_client.requests, "get", Mock(side_effect=error))
    with pytest.raises(FetchError):
        api_client.fetch_response(CVE)


@pytest.mark.parametrize("status_code", [403, 404, 500, 503])
def test_http_error_raises_fetch_error(monkeypatch, status_code):
    response = make_response(status_code=status_code)
    response.raise_for_status.side_effect = requests.exceptions.HTTPError(
        f"{status_code} error", response=response
    )
    monkeypatch.setattr(api_client.requests, "get", Mock(return_value=response))

    with pytest.raises(FetchError, match=str(status_code)):
        api_client.fetch_response(CVE)
    response.json.assert_not_called()


@pytest.mark.parametrize("status_code", [204, 301, 302])
def test_unexpected_status_raises_fetch_error(monkeypatch, status_code):
    response = make_response(status_code=status_code)
    monkeypatch.setattr(api_client.requests, "get", Mock(return_value=response))
    with pytest.raises(FetchError, match="неочікуваний"):
        api_client.fetch_response(CVE)


def test_invalid_json_raises_fetch_error(monkeypatch):
    response = make_response(
        json_error=requests.exceptions.JSONDecodeError("Invalid JSON", "{", 1)
    )
    monkeypatch.setattr(api_client.requests, "get", Mock(return_value=response))
    with pytest.raises(FetchError, match="JSON"):
        api_client.fetch_response(CVE)


def test_real_network_is_blocked():
    """Автоматична фікстура не дає дійти до справжньої мережі."""
    with pytest.raises(AttributeError):
        requests.get(URL, timeout=1)
