"""
Manage the Vault (or OpenBao) DigiCert PKI secret engine, request X.509 certificates.

.. versionadded:: 1.5.0

.. important::
    This module requires the general :ref:`Vault setup <vault-setup>`.
"""

import logging

from salt.exceptions import CommandExecutionError

from saltext.vault.utils import vault

log = logging.getLogger(__name__)

__virtualname__ = "vault_pki_digicert"


def __virtual__():
    return __virtualname__


def issue_certificate(
    role_name,
    common_name,
    mount="digicert-pki",
    dns_names=None,
    profile_id=None,
    tags=None,
    csr=None,
    **kwargs,
):
    """
    Request a new certificate.

    `API method docs <https://docs.digicert.com/de/trust-lifecycle-manager/integration-guides/hashicorp-vault/configuration-and-certificate-operations/certificate-apis.html>`__.

    CLI Example:

    .. code-block:: bash

            salt '*' vault_pki_digicert.issue_certificate myrole name.example.com

    role_name
        Name of the role to be used for issuing the certificate.

    common_name
        Common name to be set for the certificate.

    mount
        Mount path the PKI backend is mounted to. Defaults to ``digicert-pki``.

    dns_names
        (Optional) Specify additional names.

    profile_id
        (Optional) Specify certificate profile ID.

    tags
        Specify tags.

    csr
        (Optional) Include and sign CSR for the request.

    kwargs
        Any additional parameter accepted by Vault API.
    """
    endpoint = f"{mount}/issue/{role_name}"

    payload = {k: v for k, v in kwargs.items() if not k.startswith("_")}
    payload["common_name"] = common_name

    if dns_names is not None:
        payload["dns_names"] = dns_names
    if profile_id is not None:
        payload["profile_id"] = profile_id
    if tags is not None:
        payload["tags"] = tags
    if csr is not None:
        payload["csr"] = csr

    try:
        res = vault.query("POST", endpoint, __opts__, __context__, payload=payload)
        return res.get("data", res)
    except vault.VaultException as err:
        raise CommandExecutionError(f"{err.__class__}: {err}") from err


def pickup_certificate(request_id, mount="digicert-pki"):
    """
    Pick up a pending certificate with the request_id in the issuing response.

    CLI Example:

    .. code-block:: bash

            salt '*' vault_pki_digicert.pickup_certificate 95e4032f-bd7b-4b71-9b39-6e9fb0966484

    request_id
        The ID of the request to pick up.

    mount
        Mount path the PKI backend is mounted to. Defaults to ``digicert-pki``.
    """
    endpoint = f"{mount}/pickup/{request_id}"

    try:
        res = vault.query("GET", endpoint, __opts__, __context__)
        return res.get("data", res)
    except vault.VaultException as err:
        raise CommandExecutionError(f"{err.__class__}: {err}") from err


def revoke_certificate(role_name, serial_number, mount="digicert-pki"):
    """
    Revoke issued certificate.

    CLI Example:

    .. code-block:: bash

            salt '*' vault_pki_digicert.revoke_certificate myrole 748B6C3B014C48A1F3FF0C17C4764428360F68F5

    role_name
        Name of the role.

    serial_number
        Specifies the serial of the certificate to revoke.

    mount
        Mount path the PKI backend is mounted to. Defaults to ``digicert-pki``.
    """
    endpoint = f"{mount}/revoke/{role_name}"
    payload = {"serial_number": serial_number}

    try:
        vault.query("POST", endpoint, __opts__, __context__, payload=payload, safe_to_retry=True)
        return True
    except vault.VaultInvocationError:
        return False
    except vault.VaultException as err:
        raise CommandExecutionError(f"{err.__class__}: {err}") from err


def list_certificates(mount="digicert-pki"):
    """
    List issued certificates serial numbers.

    CLI Example:

    .. code-block:: bash

            salt '*' vault_pki_digicert.list_certificates

    mount
        Mount path the PKI backend is mounted to. Defaults to ``digicert-pki``.
    """
    endpoint = f"{mount}/certs"

    try:
        return vault.query("LIST", endpoint, __opts__, __context__)["data"]["keys"]
    except vault.VaultException as err:
        raise CommandExecutionError(f"{err.__class__}: {err}") from err


def read_certificate(serial_number, mount="digicert-pki"):
    """
    Read issued certificate.

    CLI Example:

    .. code-block:: bash

            salt '*' vault_pki_digicert.read_certificate 7e85c5d185949a4608b51b9c22cb35e5eaf3563f

    serial_number
        Specifies the serial of the key to read.

    mount
        Mount path the PKI backend is mounted to. Defaults to ``digicert-pki``.
    """
    endpoint = f"{mount}/certs/{serial_number}"

    try:
        return vault.query("GET", endpoint, __opts__, __context__)["data"]
    except vault.VaultException as err:
        raise CommandExecutionError(f"{err.__class__}: {err}") from err
