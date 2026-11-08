"""VULNEX scanner worker (ADR-0006). Connects outbound to the worker endpoint over mTLS, verifies
every signed scope lease itself, and refuses anything outside it."""

__version__ = "0.1.0"
