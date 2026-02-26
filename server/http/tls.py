"""TLS support for Seep HTTP server."""

from __future__ import annotations

import secrets
import re
import ssl
import subprocess
from http.server import HTTPServer
from pathlib import Path

from server.config import ServerConfig

_GREEN = "\033[32m"
_YELLOW = "\033[33m"
_RED = "\033[31m"
_DIM = "\033[2m"
_RESET = "\033[0m"

# Plausible hostnames for self-signed certs (blend with common internal services)
_DEFAULT_CN_POOL = [
    "localhost",
    "mail.local",
    "intranet.local",
    "srv01.corp.local",
    "web01.internal",
    "app-server",
    "exchange.local",
    "fileserver.internal",
]


def _random_cn() -> str:
    """Pick a plausible random CN from the pool."""
    return secrets.choice(_DEFAULT_CN_POOL)


def generate_self_signed_cert(
    cert_path: Path,
    key_path: Path,
    hostname: str = "",
) -> None:
    """Generate a self-signed TLS certificate using openssl.

    Args:
        cert_path: Destination path for the PEM certificate.
        key_path:  Destination path for the private key.
        hostname:  CN value embedded in the certificate.
    """
    if not hostname:
        hostname = _random_cn()

    if not re.match(r"^[a-zA-Z0-9._-]+$", hostname):
        raise ValueError(f"Invalid hostname: {hostname!r}")

    cert_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.parent.mkdir(parents=True, exist_ok=True)

    cmd = [
        "openssl",
        "req",
        "-x509",
        "-newkey",
        "rsa:4096",
        "-keyout",
        str(key_path),
        "-out",
        str(cert_path),
        "-days",
        "365",
        "-nodes",
        "-subj",
        f"/CN={hostname}",
    ]

    try:
        subprocess.run(
            cmd,
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        print(
            f"{_GREEN}[+]{_RESET} Self-signed certificate generated\n"
            f"    cert: {_DIM}{cert_path}{_RESET}\n"
            f"    key:  {_DIM}{key_path}{_RESET}"
        )
    except FileNotFoundError:
        raise RuntimeError(
            "openssl not found — install it (apt install openssl) or supply a certificate manually."
        )
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(
            f"openssl failed (exit {exc.returncode}) — check openssl is working."
        ) from exc


def wrap_server_tls(server: HTTPServer, config: ServerConfig) -> HTTPServer:
    """Wrap an HTTPServer's socket with TLS using the configured certificate.

    If the certificate or key file does not exist it is generated automatically
    via :func:`generate_self_signed_cert`.

    Args:
        server: A bound (but not yet serving) HTTPServer instance.
        config: Seep server configuration carrying TLS paths.

    Returns:
        The same server instance with its socket replaced by a TLS-wrapped one.
    """
    workdir = config.workdir
    cert_path = (workdir / config.tls.cert_path).resolve()
    key_path = (workdir / config.tls.key_path).resolve()

    # Ensure paths stay within workdir
    workdir_resolved = workdir.resolve()
    for label, p in [("cert_path", cert_path), ("key_path", key_path)]:
        try:
            p.relative_to(workdir_resolved)
        except ValueError:
            raise RuntimeError(
                f"TLS {label} resolves outside workdir: {p}\n"
                f"  workdir: {workdir_resolved}"
            )

    if not cert_path.exists() or not key_path.exists():
        print(
            f"{_YELLOW}[*]{_RESET} TLS cert/key not found — generating self-signed certificate…"
        )
        generate_self_signed_cert(cert_path, key_path)

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    try:
        ctx.load_cert_chain(str(cert_path), str(key_path))
    except ssl.SSLError as exc:
        raise RuntimeError(
            f"Failed to load TLS cert/key: {exc}\n"
            f"  cert: {cert_path}\n"
            f"  key:  {key_path}"
        ) from exc

    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    print(f"{_GREEN}[+]{_RESET} TLS enabled (cert: {_DIM}{cert_path.name}{_RESET})")
    return server
