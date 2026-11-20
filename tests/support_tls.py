"""A throwaway certificate authority and TLS servers for the remote-transport tests.

Everything here is generated at run time (nothing is committed, so the secret scan stays empty) with
`cryptography`, which is already in the development environment through the lab. The servers listen on
127.0.0.1 only. A name such as `api.test.example` is mapped to 127.0.0.1 by the injected resolver of the
transport under test, never by the operating system.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import ssl
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from tests.support import FakeServer

HOST = "api.test.example"


@dataclass(frozen=True)
class Authority:
    key: ec.EllipticCurvePrivateKey
    cert: x509.Certificate
    pem_path: Path  # the CA certificate, to hand to `ca_bundle`


def _name(common: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common)])


def _utc(delta_days: float) -> dt.datetime:
    return dt.datetime.now(dt.UTC) + dt.timedelta(days=delta_days)


def make_authority(directory: Path, common: str = "boundarycheck test CA") -> Authority:
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name(common))
        .issuer_name(_name(common))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_utc(-2))
        .not_valid_after(_utc(2))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False, key_agreement=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )  # fmt: skip
    path = directory / f"{common.replace(' ', '-')}.pem"
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return Authority(key, cert, path)


def issue(
    authority: Authority,
    directory: Path,
    names: Iterable[str] = (HOST,),
    *,
    not_before_days: float = -1,
    not_after_days: float = 1,
) -> tuple[Path, Path]:
    """A server certificate for `names` signed by `authority`. Returns (certificate, key) paths."""
    key = ec.generate_private_key(ec.SECP256R1())
    sans: list[x509.GeneralName] = [x509.DNSName(n) for n in names]
    sans.append(x509.IPAddress(ipaddress.ip_address("127.0.0.1")))
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name(next(iter(names), HOST)))
        .issuer_name(authority.cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_utc(not_before_days))
        .not_valid_after(_utc(not_after_days))
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(authority.key, hashes.SHA256())
    )
    stem = f"leaf-{x509.random_serial_number() % 10**8}"
    cert_path, key_path = directory / f"{stem}.pem", directory / f"{stem}.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    )
    return cert_path, key_path


class TlsServer(FakeServer):
    """A FakeServer that speaks TLS. `requests` still records every HTTP request that arrived, so a
    handshake the client refuses leaves `requests == []`: the token was never sent. `sni` records the
    server name the client asked for."""

    def __init__(self, certificate: Path, key: Path, *, minimum: ssl.TLSVersion = ssl.TLSVersion.TLSv1_2) -> None:
        super().__init__()
        self.sni: list[str | None] = []
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = minimum
        context.load_cert_chain(certfile=str(certificate), keyfile=str(key))

        def remember(_sock: object, name: str | None, _ctx: object) -> None:
            self.sni.append(name)

        context.sni_callback = remember  # type: ignore[assignment]
        # the handshake happens in the request thread, so a refused handshake cannot stall `accept`
        self.httpd.socket = context.wrap_socket(self.httpd.socket, server_side=True, do_handshake_on_connect=False)
        self.httpd.handle_error = lambda *_a: None  # type: ignore[method-assign]  # a refused handshake is expected
        self.base_url = f"https://{HOST}:{self.port}"
