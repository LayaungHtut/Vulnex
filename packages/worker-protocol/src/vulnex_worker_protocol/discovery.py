"""Result bodies of the `network.discover` task (M5).

The scanner reports raw observations only: which ports accepted a TCP connection, the bytes a
service sent first, what a TLS handshake showed, and what one `GET /` returned. It does not
name products or decide anything about vulnerabilities; the control plane does that with
versioned rules (probe/evaluate split, INITIAL_ARCHITECTURE §5.4). Every field is bounded, and
the control plane validates submissions against these models before storing them.
"""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

PROFILE = "discovery"
TASK_KIND = "network.discover"
BATCH_OPEN_PORTS = 100  # open-port observations per submission (the gateway caps bodies at 1 MB)


class _Model(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class TlsCertificate(_Model):
    subject: str = Field(max_length=2000)
    issuer: str = Field(max_length=2000)
    serial: str = Field(max_length=100)
    not_before: str = Field(max_length=40)
    not_after: str = Field(max_length=40)
    dns_names: list[str] = Field(default_factory=list, max_length=200)
    ip_addresses: list[str] = Field(default_factory=list, max_length=50)
    signature_algorithm: str | None = Field(default=None, max_length=100)
    key_type: str | None = Field(default=None, max_length=20)
    key_bits: int | None = Field(default=None, ge=0, le=65536)
    self_signed: bool
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class TlsObservation(_Model):
    version: str | None = Field(default=None, max_length=20)
    cipher: str | None = Field(default=None, max_length=100)
    cipher_bits: int | None = Field(default=None, ge=0, le=1024)
    server_name: str | None = Field(default=None, max_length=253)
    certificate: TlsCertificate | None = None
    # Per protocol version: True accepted, False refused, absent not tested.
    protocols: dict[Literal["TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"], bool] = Field(
        default_factory=dict
    )


class HttpObservation(_Model):
    scheme: Literal["http", "https"]
    host_header: str = Field(max_length=260)
    status: int = Field(ge=100, le=999)
    reason: str = Field(default="", max_length=200)
    headers: list[tuple[str, str]] = Field(default_factory=list, max_length=60)
    title: str | None = Field(default=None, max_length=300)
    body_bytes: int = Field(ge=0)
    body_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")


class OpenPort(_Model):
    address: str = Field(max_length=15)
    port: int = Field(ge=1, le=65535)
    observed_at: str = Field(max_length=40)
    connect_ms: int = Field(ge=0)
    banner: str | None = Field(default=None, max_length=4096)
    banner_b64: str | None = Field(default=None, max_length=5500)
    tls: TlsObservation | None = None
    http: HttpObservation | None = None
    probe: str | None = Field(default=None, max_length=50)  # name of a safe protocol probe
    probe_reply: str | None = Field(default=None, max_length=4096)
    errors: list[str] = Field(default_factory=list, max_length=10)


class RefusedProbe(_Model):
    address: str | None = Field(default=None, max_length=45)
    port: int | None = None
    reason: str = Field(max_length=300)


class TargetReport(_Model):
    """Observations for one target. A large target may arrive in several parts."""

    target: str = Field(max_length=260)
    kind: Literal["ip", "cidr", "hostname"]
    part: int = Field(default=0, ge=0, le=100_000)
    dns: dict[str, object] | None = None
    addresses: list[str] = Field(default_factory=list, max_length=4096)  # probed (part 0 only)
    responding: list[str] = Field(default_factory=list, max_length=4096)
    open: list[OpenPort] = Field(default_factory=list, max_length=BATCH_OPEN_PORTS)
    closed: int = Field(default=0, ge=0)
    filtered: int = Field(default=0, ge=0)
    refused: list[RefusedProbe] = Field(default_factory=list, max_length=200)


class DiscoveryBatch(_Model):
    profile: Literal["discovery"] = "discovery"
    reports: list[TargetReport] = Field(max_length=500)


class DiscoverySummary(_Model):
    """The final submission. `refused` lists targets the worker would not touch at all."""

    profile: Literal["discovery"] = "discovery"
    scanner_version: str = Field(max_length=50)
    started_at: str = Field(max_length=40)
    finished_at: str = Field(max_length=40)
    ports: int = Field(ge=0)
    probes: int = Field(ge=0)
    connections: int = Field(ge=0)
    batches: int = Field(ge=0)
    stopped: str | None = Field(default=None, max_length=300)
    refused: list[RefusedProbe] = Field(default_factory=list, max_length=10_000)
    reports: list[TargetReport] = Field(default_factory=list, max_length=500)
