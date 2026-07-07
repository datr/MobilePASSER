# coding=utf-8
"""Shared pytest fixtures."""

import json
import os

import pytest


HERE = os.path.dirname(os.path.abspath(__file__))


@pytest.fixture(scope="session")
def golden():
    with open(os.path.join(HERE, "golden_vectors.json")) as f:
        return json.load(f)


@pytest.fixture(scope="session")
def example_legacy_key():
    return "QVKYC-FM6KO-SY6F7-TR22W"


@pytest.fixture(scope="session")
def example_legacy_entropy_hex():
    # Captured from the Python 2 reference implementation.
    return "855582b3ca963c59c75a"
