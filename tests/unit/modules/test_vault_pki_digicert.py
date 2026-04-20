from unittest.mock import patch

import pytest

import saltext.vault.utils.vault as vaultutil
from saltext.vault.modules import vault_pki_digicert


@pytest.fixture
def configure_loader_modules():
    return {
        vault_pki_digicert: {
            "__grains__": {"id": "test-minion"},
            "__opts__": {},
            "__context__": {},
        }
    }


@pytest.fixture
def query():
    with patch("saltext.vault.utils.vault.query", autospec=True) as _query:
        yield _query


def test_issue_certificate(query):
    query.return_value = {"data": {"certificate": "cert", "common_name": "test"}}

    res = vault_pki_digicert.issue_certificate(
        "myrole", "example.com", dns_names="test1,test2", profile_id="123"
    )

    assert res == {"certificate": "cert", "common_name": "test"}
    endpoint = query.call_args[0][1]
    payload = query.call_args[1]["payload"]
    assert endpoint == "digicert-pki/issue/myrole"
    assert payload["common_name"] == "example.com"
    assert payload["dns_names"] == "test1,test2"
    assert payload["profile_id"] == "123"


def test_pickup_certificate(query):
    query.return_value = {"data": {"certificate": "cert"}}

    res = vault_pki_digicert.pickup_certificate("req_id")

    assert res == {"certificate": "cert"}
    endpoint = query.call_args[0][1]
    assert endpoint == "digicert-pki/pickup/req_id"


def test_revoke_certificate(query):
    query.return_value = {"data": {}}

    res = vault_pki_digicert.revoke_certificate("myrole", "12345")

    assert res is True
    endpoint = query.call_args[0][1]
    payload = query.call_args[1]["payload"]
    assert endpoint == "digicert-pki/revoke/myrole"
    assert payload["serial_number"] == "12345"


def test_revoke_certificate_failed(query):
    query.side_effect = vaultutil.VaultInvocationError("Failed")

    res = vault_pki_digicert.revoke_certificate("myrole", "12345")

    assert res is False


def test_list_certificates(query):
    query.return_value = {"data": {"keys": ["cert1", "cert2"]}}

    res = vault_pki_digicert.list_certificates()

    assert res == ["cert1", "cert2"]
    endpoint = query.call_args[0][1]
    assert endpoint == "digicert-pki/certs"
    assert query.call_args[0][0] == "LIST"


def test_read_certificate(query):
    query.return_value = {"data": {"certificate": "cert", "private_key": "key"}}

    res = vault_pki_digicert.read_certificate("12345")

    assert res == {"certificate": "cert", "private_key": "key"}
    endpoint = query.call_args[0][1]
    assert endpoint == "digicert-pki/certs/12345"
