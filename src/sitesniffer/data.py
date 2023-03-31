# -*- coding: UTF-8 -*-
"""This module defines a dataclass named DomainInfo, which contains domain registration information.
The class has five attributes, all of which are of the same type: WhoisEntry. WhoisEntry is a type alias for Any, which means it can be any Python object.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, TypeAlias

__all__: list = ["DomainInfo"]

WhoisEntry: TypeAlias = Any  # TypeAlias for type readability


@dataclass(frozen=True, slots=True, kw_only=True)
class DomainInfo:
    """Dataclass for the domain information."""

    name: WhoisEntry
    registrar: WhoisEntry
    creation_date: WhoisEntry
    expiration_date: WhoisEntry
    last_updated: WhoisEntry
