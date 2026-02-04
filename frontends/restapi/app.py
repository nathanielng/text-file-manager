"""
REST API Frontend for Text File Manager.

This module provides a FastAPI-based REST API for the secure sharding backend,
enabling other applications to perform CRUD operations via HTTP.

Usage:
    # Development server
    uvicorn frontends.restapi.app:app --reload

    # Production with gunicorn
    gunicorn frontends.restapi.app:app -w 4 -k uvicorn.workers.UvicornWorker
"""

from __future__ import annotations

import base64
import logging
import os
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from typing import TYPE_CHECKING

from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware

# Add project root to path for imports
PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from frontends.restapi.models import (
    CloudConfigRequest,
    ConfigResponse,
    CredentialListResponse,
    CredentialLoadResponse,
    CredentialStoreResponse,
    DeleteDataRequest,
    DeleteResponse,
    ErrorResponse,
    HealthResponse,
    HybridConfigRequest,
    KeyListResponse,
    LoadCredentialsRequest,
    LocalConfigRequest,
    PasswordConfigRequest,
    PasswordModeEnum,
    RetrieveDataRequest,
    RetrieveResponse,
    ShardInfo,
    ShardStatusResponse,
    StatusResponse,
    StoreCredentialsRequest,
    StoreDataRequest,
    StoreResponse,
)
from src import (
    AWSCredentials,
    ConfigurationError,
    CredentialStore,
    DecryptionError,
    InsufficientShardsError,
    IntegrityError,
    PasswordConfig,
    PasswordTooShortError,
    SecureShardingClient,
    ShardManagerError,
    StorageMode,
)

if TYPE_CHECKING:
    from typing import Any, AsyncGenerator

__all__ = ["app", "create_app"]

logger = logging.getLogger(__name__)

# API Version
API_VERSION = "1.0.0"


# -----------------------------------------------------------------------------
# Application State
# -----------------------------------------------------------------------------


class AppState:
    """Application state container."""

    def __init__(self) -> None:
        self.client: SecureShardingClient | None = None
        self.passwords: PasswordConfig | None = None
        self.credential_store_path: Path | None = None

    def reset(self) -> None:
        """Reset application state."""
        self.client = None
        self.passwords = None
        self.credential_store_path = None


app_state = AppState()


# -----------------------------------------------------------------------------
# Helper Functions
# -----------------------------------------------------------------------------


def get_password_config(config: PasswordConfigRequest | None) -> PasswordConfig | None:
    """Convert PasswordConfigRequest to PasswordConfig."""
    if config is None:
        return None

    if config.mode == PasswordModeEnum.SINGLE:
        if not config.password:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Password required for single mode",
            )
        return PasswordConfig.single(config.password)

    elif config.mode == PasswordModeEnum.SEPARATE:
        if not all([config.local_password, config.aws1_password, config.aws2_password]):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="All three passwords required for separate mode",
            )
        return PasswordConfig.separate(
            local=config.local_password,
            aws_account1=config.aws1_password,
            aws_account2=config.aws2_password,
        )

    else:  # PREFIX_SUFFIX
        if not all([config.prefix, config.local_suffix, config.aws1_suffix, config.aws2_suffix]):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Prefix and all suffixes required for prefix_suffix mode",
            )
        return PasswordConfig.prefix_suffix(
            prefix=config.prefix,
            local_suffix=config.local_suffix,
            aws1_suffix=config.aws1_suffix,
            aws2_suffix=config.aws2_suffix,
        )


def get_aws_credentials(creds: Any) -> AWSCredentials | None:
    """Convert credentials request to AWSCredentials."""
    if creds is None:
        return None
    return AWSCredentials(
        access_key_id=creds.access_key_id,
        secret_access_key=creds.secret_access_key,
        session_token=creds.session_token,
        region=creds.region,
    )


def require_client() -> SecureShardingClient:
    """Get client or raise 409 if not configured."""
    if app_state.client is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Storage not configured. Call POST /api/config/* first.",
        )
    return app_state.client


def handle_exception(e: Exception) -> HTTPException:
    """Convert backend exceptions to HTTP exceptions."""
    if isinstance(e, PasswordTooShortError):
        return HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Password must be at least {e.min_length} characters",
        )
    elif isinstance(e, DecryptionError):
        return HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Decryption failed: wrong password or corrupted data",
        )
    elif isinstance(e, InsufficientShardsError):
        return HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Insufficient shards: {e.available}/{e.required} available",
        )
    elif isinstance(e, IntegrityError):
        return HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Data integrity verification failed",
        )
    elif isinstance(e, ConfigurationError):
        return HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    elif isinstance(e, ShardManagerError):
        return HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e),
        )
    else:
        logger.exception(f"Unexpected error: {e}")
        return HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal server error: {type(e).__name__}",
        )


# -----------------------------------------------------------------------------
# Application Factory
# -----------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan manager."""
    logger.info("Text File Manager REST API starting...")
    yield
    logger.info("Text File Manager REST API shutting down...")
    app_state.reset()


def create_app(
    cors_origins: list[str] | None = None,
    debug: bool = False,
) -> FastAPI:
    """
    Create and configure the FastAPI application.

    Args:
        cors_origins: List of allowed CORS origins. Defaults to ["*"].
        debug: Enable debug mode.

    Returns:
        Configured FastAPI application.
    """
    application = FastAPI(
        title="Text File Manager API",
        description=(
            "REST API for secure encrypted sharding using Shamir's Secret Sharing. "
            "Supports local, cloud (AWS S3), and hybrid storage modes with "
            "per-location password encryption."
        ),
        version=API_VERSION,
        lifespan=lifespan,
        debug=debug,
        responses={
            400: {"model": ErrorResponse, "description": "Bad Request"},
            401: {"model": ErrorResponse, "description": "Unauthorized"},
            404: {"model": ErrorResponse, "description": "Not Found"},
            409: {"model": ErrorResponse, "description": "Conflict - Storage not configured"},
            422: {"model": ErrorResponse, "description": "Unprocessable Entity"},
            500: {"model": ErrorResponse, "description": "Internal Server Error"},
        },
    )

    # Configure CORS
    cors_origins = cors_origins or ["*"]
    application.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    return application


# Create default application instance
app = create_app()


# -----------------------------------------------------------------------------
# Health & Status Endpoints
# -----------------------------------------------------------------------------


@app.get(
    "/health",
    response_model=HealthResponse,
    tags=["Health"],
    summary="Health check",
)
async def health_check() -> HealthResponse:
    """Check API health and configuration status."""
    return HealthResponse(
        status="ok",
        version=API_VERSION,
        configured=app_state.client is not None,
        storage_mode=app_state.client.storage_mode.value if app_state.client else None,
    )


@app.get(
    "/api/status",
    response_model=StatusResponse,
    tags=["Status"],
    summary="Get current status",
)
async def get_status() -> StatusResponse:
    """Get current configuration status."""
    if app_state.client is None:
        return StatusResponse(
            status="unconfigured",
            message="No storage configured. Use POST /api/config/* to configure.",
        )
    return StatusResponse(
        status="configured",
        message=f"Storage configured in {app_state.client.storage_mode.value} mode",
    )


@app.post(
    "/api/reset",
    response_model=StatusResponse,
    tags=["Status"],
    summary="Reset configuration",
)
async def reset_configuration() -> StatusResponse:
    """Reset the storage configuration."""
    app_state.reset()
    return StatusResponse(
        status="ok",
        message="Configuration reset successfully",
    )


# -----------------------------------------------------------------------------
# Configuration Endpoints
# -----------------------------------------------------------------------------


@app.post(
    "/api/config/local",
    response_model=ConfigResponse,
    tags=["Configuration"],
    summary="Configure local storage",
    status_code=status.HTTP_201_CREATED,
)
async def configure_local(config: LocalConfigRequest) -> ConfigResponse:
    """
    Configure local storage mode.

    All shards will be stored on the local filesystem across multiple directories.
    """
    try:
        passwords = get_password_config(config.passwords)
        password = None
        if passwords:
            password = passwords.get_password("local")

        app_state.client = SecureShardingClient.create_local(
            directories=config.directories,
            threshold=config.threshold,
            password=password,
        )
        app_state.passwords = passwords

        dist = app_state.client.distribution
        return ConfigResponse(
            status="ok",
            storage_mode="local",
            total_shards=dist.total_shards,
            threshold=dist.threshold,
            local_shards=dist.local_shards,
        )

    except Exception as e:
        raise handle_exception(e)


@app.post(
    "/api/config/cloud",
    response_model=ConfigResponse,
    tags=["Configuration"],
    summary="Configure cloud storage",
    status_code=status.HTTP_201_CREATED,
)
async def configure_cloud(config: CloudConfigRequest) -> ConfigResponse:
    """
    Configure cloud storage mode.

    All shards will be stored in AWS S3, distributed across 2 separate AWS accounts.
    """
    try:
        passwords = get_password_config(config.passwords)

        aws1_creds = get_aws_credentials(config.aws_account1_credentials)
        aws2_creds = get_aws_credentials(config.aws_account2_credentials)

        cred_store_path = config.credential_store_path
        if cred_store_path:
            app_state.credential_store_path = Path(cred_store_path)

        app_state.client = SecureShardingClient.create_cloud(
            aws_account1_config=config.aws_account1.model_dump(exclude_none=True),
            aws_account2_config=config.aws_account2.model_dump(exclude_none=True),
            threshold=config.threshold,
            account1_shards=config.account1_shards,
            account2_shards=config.account2_shards,
            aws_account1_credentials=aws1_creds,
            aws_account2_credentials=aws2_creds,
            passwords=passwords,
            credential_store_path=cred_store_path,
        )
        app_state.passwords = passwords

        dist = app_state.client.distribution
        return ConfigResponse(
            status="ok",
            storage_mode="cloud",
            total_shards=dist.total_shards,
            threshold=dist.threshold,
            cloud_account1_shards=dist.cloud_account1_shards,
            cloud_account2_shards=dist.cloud_account2_shards,
        )

    except Exception as e:
        raise handle_exception(e)


@app.post(
    "/api/config/hybrid",
    response_model=ConfigResponse,
    tags=["Configuration"],
    summary="Configure hybrid storage",
    status_code=status.HTTP_201_CREATED,
)
async def configure_hybrid(config: HybridConfigRequest) -> ConfigResponse:
    """
    Configure hybrid storage mode.

    Shards will be distributed between local storage and 2 AWS accounts.
    Security: No single storage type can reconstruct data alone.
    """
    try:
        passwords = get_password_config(config.passwords)

        aws1_creds = get_aws_credentials(config.aws_account1_credentials)
        aws2_creds = get_aws_credentials(config.aws_account2_credentials)

        cred_store_path = config.credential_store_path
        if cred_store_path:
            app_state.credential_store_path = Path(cred_store_path)

        app_state.client = SecureShardingClient.create_hybrid(
            local_directories=config.local_directories,
            aws_account1_config=config.aws_account1.model_dump(exclude_none=True),
            aws_account2_config=config.aws_account2.model_dump(exclude_none=True),
            local_shards=config.local_shards,
            account1_shards=config.account1_shards,
            account2_shards=config.account2_shards,
            aws_account1_credentials=aws1_creds,
            aws_account2_credentials=aws2_creds,
            passwords=passwords,
            credential_store_path=cred_store_path,
        )
        app_state.passwords = passwords

        dist = app_state.client.distribution
        return ConfigResponse(
            status="ok",
            storage_mode="hybrid",
            total_shards=dist.total_shards,
            threshold=dist.threshold,
            local_shards=dist.local_shards,
            cloud_account1_shards=dist.cloud_account1_shards,
            cloud_account2_shards=dist.cloud_account2_shards,
        )

    except Exception as e:
        raise handle_exception(e)


# -----------------------------------------------------------------------------
# Data Operation Endpoints
# -----------------------------------------------------------------------------


@app.get(
    "/api/keys",
    response_model=KeyListResponse,
    tags=["Data Operations"],
    summary="List all stored keys",
)
async def list_keys() -> KeyListResponse:
    """List all stored data keys."""
    client = require_client()
    try:
        keys = client.list_keys()
        return KeyListResponse(
            status="ok",
            keys=keys,
            count=len(keys),
        )
    except Exception as e:
        raise handle_exception(e)


@app.post(
    "/api/data/{key:path}",
    response_model=StoreResponse,
    tags=["Data Operations"],
    summary="Store encrypted data",
    status_code=status.HTTP_201_CREATED,
)
async def store_data(key: str, request: StoreDataRequest) -> StoreResponse:
    """
    Store data with encryption and sharding.

    The data can be provided as plain text or base64-encoded binary.
    Set `is_base64: true` for binary data.
    """
    client = require_client()

    try:
        # Decode data
        if request.is_base64:
            data = base64.b64decode(request.data)
        else:
            data = request.data.encode("utf-8")

        # Get password
        password: str | PasswordConfig | None = None
        if request.passwords:
            password = get_password_config(request.passwords)
        elif request.password:
            password = request.password
        elif app_state.passwords:
            password = app_state.passwords

        if password is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Password required. Provide password, passwords, or configure default.",
            )

        # Store
        result = client.store(key, data, password, request.metadata)

        return StoreResponse(
            status="ok",
            key=result.key,
            threshold=result.threshold,
            total_shares=result.total_shares,
            stored_shards=len(result.stored_shards),
            data_hash=result.data_hash,
            storage_mode=result.storage_mode.value,
        )

    except HTTPException:
        raise
    except Exception as e:
        raise handle_exception(e)


@app.post(
    "/api/data/{key:path}/retrieve",
    response_model=RetrieveResponse,
    tags=["Data Operations"],
    summary="Retrieve and decrypt data",
)
async def retrieve_data(key: str, request: RetrieveDataRequest) -> RetrieveResponse:
    """
    Retrieve and decrypt data.

    The data is returned as base64-encoded to support binary content.
    """
    client = require_client()

    try:
        # Get password
        password: str | PasswordConfig | None = None
        if request.passwords:
            password = get_password_config(request.passwords)
        elif request.password:
            password = request.password
        elif app_state.passwords:
            password = app_state.passwords

        if password is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Password required for decryption.",
            )

        # Retrieve
        data = client.retrieve(key, password, request.verify_integrity)

        return RetrieveResponse(
            status="ok",
            key=key,
            data=base64.b64encode(data).decode("ascii"),
            size=len(data),
            integrity_verified=request.verify_integrity,
        )

    except HTTPException:
        raise
    except Exception as e:
        raise handle_exception(e)


@app.delete(
    "/api/data/{key:path}",
    response_model=DeleteResponse,
    tags=["Data Operations"],
    summary="Delete stored data",
)
async def delete_data(
    key: str,
    request: DeleteDataRequest | None = None,
) -> DeleteResponse:
    """
    Delete all shards for a key.

    By default, uses secure deletion (overwrites with random data).
    """
    client = require_client()
    secure = request.secure if request else True

    try:
        result = client.delete(key, secure=secure)

        return DeleteResponse(
            status="ok",
            key=result.key,
            deleted_count=len(result.deleted),
            failed_count=len(result.failed),
        )

    except Exception as e:
        raise handle_exception(e)


@app.get(
    "/api/data/{key:path}/status",
    response_model=ShardStatusResponse,
    tags=["Data Operations"],
    summary="Get shard status",
)
async def get_shard_status(key: str) -> ShardStatusResponse:
    """Get detailed status of all shards for a key."""
    client = require_client()

    try:
        status_dict = client.get_shard_status(key)

        shards = [
            ShardInfo(
                index=s["index"],
                backend_type=s["backend_type"],
                location=s["location"],
                exists=s["exists"],
            )
            for s in status_dict["shards"]
        ]

        return ShardStatusResponse(
            status="ok",
            key=status_dict["key"],
            threshold=status_dict["threshold"],
            total_shards=status_dict["total_shards"],
            storage_mode=status_dict["storage_mode"],
            can_reconstruct=status_dict["can_reconstruct"],
            local_available=status_dict["local_available"],
            cloud_account1_available=status_dict["cloud_account1_available"],
            cloud_account2_available=status_dict["cloud_account2_available"],
            shards=shards,
        )

    except Exception as e:
        raise handle_exception(e)


# -----------------------------------------------------------------------------
# Credential Management Endpoints
# -----------------------------------------------------------------------------


@app.get(
    "/api/credentials",
    response_model=CredentialListResponse,
    tags=["Credentials"],
    summary="List stored credentials",
)
async def list_credentials(store_path: str | None = None) -> CredentialListResponse:
    """List all stored credential account IDs."""
    path = store_path or app_state.credential_store_path
    if not path:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Credential store path not configured. Provide store_path parameter.",
        )

    store_path_obj = Path(path)
    if not store_path_obj.exists():
        return CredentialListResponse(
            status="ok",
            accounts=[],
            count=0,
        )

    store = CredentialStore(store_path_obj)
    accounts = store.list_accounts()

    return CredentialListResponse(
        status="ok",
        accounts=accounts,
        count=len(accounts),
    )


@app.post(
    "/api/credentials",
    response_model=CredentialStoreResponse,
    tags=["Credentials"],
    summary="Store encrypted credentials",
    status_code=status.HTTP_201_CREATED,
)
async def store_credentials(
    request: StoreCredentialsRequest,
    store_path: str | None = None,
) -> CredentialStoreResponse:
    """Store AWS credentials encrypted with a password."""
    path = store_path or app_state.credential_store_path
    if not path:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Credential store path not configured. Provide store_path parameter.",
        )

    try:
        store = CredentialStore(path)
        creds = AWSCredentials(
            access_key_id=request.credentials.access_key_id,
            secret_access_key=request.credentials.secret_access_key,
            session_token=request.credentials.session_token,
            region=request.credentials.region,
        )

        result_path = store.store_credentials(
            request.account_id,
            creds,
            request.password,
            request.metadata,
        )

        return CredentialStoreResponse(
            status="ok",
            account_id=request.account_id,
            path=str(result_path),
        )

    except Exception as e:
        raise handle_exception(e)


@app.post(
    "/api/credentials/{account_id}",
    response_model=CredentialLoadResponse,
    tags=["Credentials"],
    summary="Load and verify credentials",
)
async def load_credentials(
    account_id: str,
    request: LoadCredentialsRequest,
    store_path: str | None = None,
) -> CredentialLoadResponse:
    """Load and decrypt credentials to verify the password."""
    path = store_path or app_state.credential_store_path
    if not path:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Credential store path not configured.",
        )

    try:
        store = CredentialStore(path)
        creds = store.load_credentials(account_id, request.password)

        return CredentialLoadResponse(
            status="ok",
            account_id=account_id,
            access_key_id_prefix=creds.access_key_id[:8] + "...",
            region=creds.region,
        )

    except Exception as e:
        raise handle_exception(e)


@app.delete(
    "/api/credentials/{account_id}",
    response_model=StatusResponse,
    tags=["Credentials"],
    summary="Delete stored credentials",
)
async def delete_credentials(
    account_id: str,
    store_path: str | None = None,
    secure: bool = True,
) -> StatusResponse:
    """Delete stored credentials for an account."""
    path = store_path or app_state.credential_store_path
    if not path:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Credential store path not configured.",
        )

    store = CredentialStore(path)
    if store.delete_credentials(account_id, secure=secure):
        return StatusResponse(
            status="ok",
            message=f"Credentials for {account_id} deleted",
        )
    else:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Credentials not found for account: {account_id}",
        )


# -----------------------------------------------------------------------------
# Entry Point
# -----------------------------------------------------------------------------


def main() -> None:
    """Run the API server."""
    import uvicorn

    host = os.environ.get("API_HOST", "127.0.0.1")
    port = int(os.environ.get("API_PORT", "8000"))
    reload = os.environ.get("API_RELOAD", "false").lower() == "true"

    print(f"Starting Text File Manager REST API on {host}:{port}")
    print(f"API Documentation: http://{host}:{port}/docs")

    uvicorn.run(
        "frontends.restapi.app:app",
        host=host,
        port=port,
        reload=reload,
    )


if __name__ == "__main__":
    main()
