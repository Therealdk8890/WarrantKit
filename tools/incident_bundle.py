"""Compatibility wrapper for the installed WarrantKit incident bundle API.

New consumers should import from :mod:`agentcontain.incident_bundle`.
"""
from agentcontain.incident_bundle import (
    verify_incident_bundle,
    write_incident_bundle,
)

__all__ = ["verify_incident_bundle", "write_incident_bundle"]
