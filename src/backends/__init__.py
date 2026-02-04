"""
Storage backends for the Text File Manager.

This package provides pluggable storage backends for storing encrypted shards
in different locations: local filesystem, AWS S3, and more.

Example:
    >>> from src.backends import LocalStorageBackend, S3StorageBackend
    >>> local = LocalStorageBackend('/secure/shards')
    >>> s3 = S3StorageBackend('my-bucket', region='us-east-1')
"""

from src.backends.base import StorageBackend, StorageLocation, StorageType
from src.backends.local import LocalStorageBackend
from src.backends.s3 import S3StorageBackend

__all__ = [
    "StorageBackend",
    "StorageLocation",
    "StorageType",
    "LocalStorageBackend",
    "S3StorageBackend",
]
