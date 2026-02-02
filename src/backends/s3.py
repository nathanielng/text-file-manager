"""
AWS S3 storage backend.

This module provides a storage backend for storing shards in AWS S3 buckets,
supporting cross-account access for enhanced security through distribution.
"""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING

from src.backends.base import StorageBackend, StorageLocation, StorageType
from src.exceptions import StorageError

if TYPE_CHECKING:
    from typing import Any

    from mypy_boto3_s3 import S3Client
    from mypy_boto3_sts import STSClient

logger = logging.getLogger(__name__)


class S3StorageBackend(StorageBackend):
    """
    Storage backend for AWS S3.

    Stores shards as objects in an S3 bucket with server-side encryption.
    Supports cross-account access using IAM roles or explicit credentials.

    Attributes:
        bucket_name: Name of the S3 bucket.
        prefix: Optional prefix (folder) for shard objects.
        account_id: AWS account ID (for identification in hybrid mode).

    Example:
        >>> backend = S3StorageBackend(
        ...     bucket_name='my-shards-bucket',
        ...     region='us-east-1',
        ...     account_id='123456789012'
        ... )
        >>> backend.write_shard('my-secret', 0, '{"data": "..."}')
    """

    def __init__(
        self,
        bucket_name: str,
        region: str = "us-east-1",
        prefix: str = "shards/",
        account_id: str | None = None,
        profile_name: str | None = None,
        role_arn: str | None = None,
        endpoint_url: str | None = None,
    ) -> None:
        """
        Initialize S3 storage backend.

        Args:
            bucket_name: Name of the S3 bucket for storing shards.
            region: AWS region for the bucket.
            prefix: Prefix (folder path) for shard objects.
            account_id: AWS account ID (auto-detected if not provided).
            profile_name: AWS profile name for credentials.
            role_arn: IAM role ARN for cross-account access.
            endpoint_url: Custom S3 endpoint URL (for testing/localstack).

        Raises:
            StorageError: If S3 client cannot be initialized.
        """
        self.bucket_name = bucket_name
        self.region = region
        self.prefix = prefix.rstrip("/") + "/" if prefix else ""
        self.profile_name = profile_name
        self.role_arn = role_arn
        self.endpoint_url = endpoint_url

        # Initialize S3 client
        self._client: S3Client | None = None
        self._account_id = account_id

        # Lazily initialize client and detect account ID
        self._location = StorageLocation(
            storage_type=StorageType.AWS_S3,
            identifier=f"{bucket_name}/{self.prefix}",
            config={
                "bucket": bucket_name,
                "region": region,
                "prefix": self.prefix,
            },
            account_id=account_id,
        )

        logger.info(
            f"Initialized S3 storage backend: s3://{bucket_name}/{self.prefix}"
        )

    @property
    def client(self) -> S3Client:
        """Get or create the S3 client."""
        if self._client is None:
            self._client = self._create_client()
        return self._client

    def _create_client(self) -> S3Client:
        """Create and configure the S3 client."""
        try:
            import boto3
            from botocore.config import Config
        except ImportError as e:
            raise StorageError(
                "boto3 is required for S3 storage backend. "
                "Install with: pip install boto3",
                backend="aws_s3",
            ) from e

        config = Config(
            region_name=self.region,
            retries={"max_attempts": 3, "mode": "adaptive"},
        )

        session_kwargs: dict[str, Any] = {}
        if self.profile_name:
            session_kwargs["profile_name"] = self.profile_name

        session = boto3.Session(**session_kwargs)

        # If role ARN provided, assume the role
        if self.role_arn:
            sts: STSClient = session.client("sts")
            assumed = sts.assume_role(
                RoleArn=self.role_arn,
                RoleSessionName="TextFileManagerSharding",
            )
            credentials = assumed["Credentials"]

            return session.client(
                "s3",
                aws_access_key_id=credentials["AccessKeyId"],
                aws_secret_access_key=credentials["SecretAccessKey"],
                aws_session_token=credentials["SessionToken"],
                config=config,
                endpoint_url=self.endpoint_url,
            )

        return session.client(
            "s3",
            config=config,
            endpoint_url=self.endpoint_url,
        )

    @property
    def account_id(self) -> str | None:
        """Get the AWS account ID (auto-detected if not set)."""
        if self._account_id is None:
            try:
                import boto3

                session_kwargs: dict[str, Any] = {}
                if self.profile_name:
                    session_kwargs["profile_name"] = self.profile_name

                session = boto3.Session(**session_kwargs)
                sts: STSClient = session.client("sts")
                self._account_id = sts.get_caller_identity()["Account"]
                # Update location with detected account ID
                self._location.account_id = self._account_id
            except Exception as e:
                logger.warning(f"Could not detect AWS account ID: {e}")

        return self._account_id

    @property
    def storage_type(self) -> StorageType:
        """Return AWS_S3 storage type."""
        return StorageType.AWS_S3

    @property
    def location(self) -> StorageLocation:
        """Return the storage location configuration."""
        return self._location

    def _get_object_key(self, key: str, shard_index: int) -> str:
        """Get the S3 object key for a shard."""
        shard_name = self.get_shard_path(key, shard_index)
        return f"{self.prefix}{shard_name}"

    def write_shard(self, key: str, shard_index: int, data: str) -> dict[str, Any]:
        """
        Write a shard to S3.

        Args:
            key: The original data key.
            shard_index: Index of this shard.
            data: JSON-encoded shard data.

        Returns:
            Dict with S3 location, size, and metadata.

        Raises:
            StorageError: If write fails.
        """
        object_key = self._get_object_key(key, shard_index)

        try:
            response = self.client.put_object(
                Bucket=self.bucket_name,
                Key=object_key,
                Body=data.encode("utf-8"),
                ContentType="application/json",
                ServerSideEncryption="AES256",
                Metadata={
                    "shard-index": str(shard_index),
                    "original-key": key,
                },
            )

            logger.info(f"Wrote shard {shard_index} to s3://{self.bucket_name}/{object_key}")

            return {
                "bucket": self.bucket_name,
                "key": object_key,
                "size": len(data),
                "etag": response.get("ETag", "").strip('"'),
                "version_id": response.get("VersionId"),
                "storage_type": self.storage_type.value,
                "location": str(self._location),
                "account_id": self.account_id,
            }

        except Exception as e:
            logger.error(f"Failed to write shard {shard_index} to S3: {e}")
            raise StorageError(
                f"Failed to write shard to S3: {e}",
                backend=self.storage_type.value,
                location=f"s3://{self.bucket_name}/{object_key}",
            ) from e

    def read_shard(self, key: str, shard_index: int) -> str | None:
        """
        Read a shard from S3.

        Args:
            key: The original data key.
            shard_index: Index of the shard.

        Returns:
            JSON-encoded shard data, or None if not found.

        Raises:
            StorageError: If read fails (other than not found).
        """
        object_key = self._get_object_key(key, shard_index)

        try:
            response = self.client.get_object(
                Bucket=self.bucket_name,
                Key=object_key,
            )

            data = response["Body"].read().decode("utf-8")
            logger.info(f"Read shard {shard_index} from s3://{self.bucket_name}/{object_key}")
            return data

        except self.client.exceptions.NoSuchKey:
            logger.debug(f"Shard {shard_index} not found at s3://{self.bucket_name}/{object_key}")
            return None
        except Exception as e:
            # Check if it's a not found error
            error_code = getattr(e, "response", {}).get("Error", {}).get("Code", "")
            if error_code in ("NoSuchKey", "404"):
                return None

            logger.error(f"Failed to read shard {shard_index} from S3: {e}")
            raise StorageError(
                f"Failed to read shard from S3: {e}",
                backend=self.storage_type.value,
                location=f"s3://{self.bucket_name}/{object_key}",
            ) from e

    def delete_shard(
        self, key: str, shard_index: int, secure: bool = True
    ) -> bool:
        """
        Delete a shard from S3.

        Note: S3 doesn't support secure overwrite, but objects are encrypted
        at rest and deleted permanently (unless versioning is enabled).

        Args:
            key: The original data key.
            shard_index: Index of the shard.
            secure: Ignored for S3 (encryption at rest provides security).

        Returns:
            True if deleted, False if not found.

        Raises:
            StorageError: If deletion fails.
        """
        object_key = self._get_object_key(key, shard_index)

        try:
            # Check if object exists first
            if not self.shard_exists(key, shard_index):
                return False

            self.client.delete_object(
                Bucket=self.bucket_name,
                Key=object_key,
            )

            logger.info(f"Deleted shard {shard_index} from s3://{self.bucket_name}/{object_key}")
            return True

        except Exception as e:
            logger.error(f"Failed to delete shard {shard_index} from S3: {e}")
            raise StorageError(
                f"Failed to delete shard from S3: {e}",
                backend=self.storage_type.value,
                location=f"s3://{self.bucket_name}/{object_key}",
            ) from e

    def shard_exists(self, key: str, shard_index: int) -> bool:
        """Check if a shard exists in S3."""
        object_key = self._get_object_key(key, shard_index)

        try:
            self.client.head_object(
                Bucket=self.bucket_name,
                Key=object_key,
            )
            return True
        except Exception:
            return False

    def list_shards(self, key: str | None = None) -> list[tuple[str, int]]:
        """
        List shards in the S3 bucket.

        Args:
            key: If provided, list only shards for this key.

        Returns:
            List of (key, shard_index) tuples.
        """
        shards: list[tuple[str, int]] = []
        pattern = re.compile(r"^(.+)\.shard(\d+)$")

        prefix = self.prefix
        if key:
            prefix = f"{self.prefix}{key}.shard"

        try:
            paginator = self.client.get_paginator("list_objects_v2")

            for page in paginator.paginate(Bucket=self.bucket_name, Prefix=prefix):
                for obj in page.get("Contents", []):
                    # Remove the prefix to get the shard path
                    obj_key = obj["Key"]
                    if obj_key.startswith(self.prefix):
                        relative = obj_key[len(self.prefix):]
                        match = pattern.match(relative)

                        if match:
                            shard_key = match.group(1)
                            shard_index = int(match.group(2))
                            shards.append((shard_key, shard_index))

        except Exception as e:
            logger.error(f"Failed to list shards in S3: {e}")
            raise StorageError(
                f"Failed to list shards in S3: {e}",
                backend=self.storage_type.value,
                location=f"s3://{self.bucket_name}/{self.prefix}",
            ) from e

        return sorted(shards)

    def ensure_bucket_exists(self) -> None:
        """
        Ensure the S3 bucket exists, creating it if necessary.

        Raises:
            StorageError: If bucket creation fails.
        """
        try:
            self.client.head_bucket(Bucket=self.bucket_name)
            logger.debug(f"Bucket {self.bucket_name} exists")
        except Exception:
            try:
                create_kwargs: dict[str, Any] = {"Bucket": self.bucket_name}

                # LocationConstraint is required for regions other than us-east-1
                if self.region != "us-east-1":
                    create_kwargs["CreateBucketConfiguration"] = {
                        "LocationConstraint": self.region
                    }

                self.client.create_bucket(**create_kwargs)
                logger.info(f"Created bucket {self.bucket_name}")

                # Enable default encryption
                self.client.put_bucket_encryption(
                    Bucket=self.bucket_name,
                    ServerSideEncryptionConfiguration={
                        "Rules": [
                            {
                                "ApplyServerSideEncryptionByDefault": {
                                    "SSEAlgorithm": "AES256"
                                }
                            }
                        ]
                    },
                )

            except Exception as e:
                raise StorageError(
                    f"Failed to create S3 bucket: {e}",
                    backend=self.storage_type.value,
                    location=self.bucket_name,
                ) from e
