"""
Pytest configuration and shared fixtures for all tests.
"""

import sys
from pathlib import Path

import pytest

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


@pytest.fixture
def temp_directories(tmp_path):
    """Create multiple temporary directories for shard storage."""
    dirs = []
    for i in range(5):
        d = tmp_path / f"shard_dir_{i}"
        d.mkdir()
        dirs.append(str(d))
    return dirs


@pytest.fixture
def sample_password():
    """A sample password meeting minimum requirements."""
    return "test-password-12"


@pytest.fixture
def sample_data():
    """Sample binary data for testing."""
    return b"This is sample test data for encryption testing."


@pytest.fixture
def large_sample_data():
    """Large sample data (1MB) for performance testing."""
    return b"x" * (1024 * 1024)
