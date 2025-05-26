#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""
Ghauri Evasion Package
"""

from .quantum_waf_evasion import (
    QuantumWAFEvasion,
    apply_quantum_evasion,
    learn_from_response,
)

__all__ = [
    "QuantumWAFEvasion",
    "apply_quantum_evasion",
    "learn_from_response",
]
