import asyncio
import hashlib
import ipaddress
import json
import os
import random
import secrets
from datetime import datetime, timedelta, timezone
from ipaddress import IPv4Address
from typing import Any, Optional

import jwt
from bson import ObjectId
from fastapi import APIRouter, FastAPI, HTTPException, Path, Request, Security, status
from fastapi.encoders import jsonable_encoder
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, ConfigDict, Field, field_validator
from pymongo import ASCENDING
from pymongo.errors import DuplicateKeyError


MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
MONGO_DB = os.getenv("MONGO_DB", "forescout_connect_demo")
JWT_SECRET = os.getenv("JWT_SECRET", "forescout-connect-demo-change-me")
JWT_EXPIRES_SECONDS = int(os.getenv("JWT_EXPIRES_SECONDS", "3600"))
JWT_ALGORITHM = "HS256"

DEFAULT_GROUPS = ["dev", "prod", "critical", "isolated"]
HOST_DOCUMENT_FIELDS = {"_id", "hostIP", "registered", "groups", "createdAt", "updatedAt", "fieldChanges", "changeLog"}
RESERVED_FIELDS = {"_id", "id", "createdAt", "updatedAt", "fieldChanges", "changeLog"}


mongo_client: Optional[AsyncIOMotorClient] = None
db = None
subscribers: set[asyncio.Queue] = set()


class GenerateHostsRequest(BaseModel):
    subnet: str = Field(
        "192.0.2.0/24",
        description="IPv4 subnet to generate hosts from. Network and broadcast addresses are skipped.",
        examples=["192.0.2.0/24"],
    )
    count: int = Field(
        10,
        ge=1,
        le=4096,
        description="Number of unique host records to generate inside the subnet.",
        examples=[25],
    )

    @field_validator("subnet")
    @classmethod
    def validate_subnet(cls, value: str) -> str:
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError as exc:
            raise ValueError("subnet must be a valid IPv4 CIDR block") from exc
        if network.version != 4:
            raise ValueError("only IPv4 subnets are supported")
        return str(network)


class GenerateHostsResponse(BaseModel):
    generated: int = Field(description="Number of host records inserted.")
    skippedExisting: int = Field(description="Number of already existing addresses skipped.")
    hosts: list[dict[str, Any]] = Field(description="Generated host records.")


class ApiKeyCreateRequest(BaseModel):
    label: str = Field("Host Workbench Demo Client", min_length=1, max_length=80)


class ApiKeyCreatedResponse(BaseModel):
    apiKey: str = Field(description="Plain API key. Store it now; the UI masks it after this response.")
    keyPrefix: str
    createdAt: datetime


class CurrentApiKeyResponse(BaseModel):
    apiKey: Optional[str] = None
    keyPrefix: Optional[str] = None
    label: Optional[str] = None
    createdAt: Optional[datetime] = None
    lastUsedAt: Optional[datetime] = None


class ClearHostsResponse(BaseModel):
    deletedHosts: int


class GroupCreateRequest(BaseModel):
    name: str = Field(
        min_length=1,
        max_length=40,
        description="Group name. Use letters, numbers, underscore, or dash.",
        examples=["lab"],
    )


class TokenResponse(BaseModel):
    access_token: str = Field(description="JWT bearer token used with public host APIs.")
    token_type: str = Field("bearer")
    expires_in: int = Field(description="Token lifetime in seconds.")


class HostCreate(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "example": {
                "hostIP": "192.0.2.44",
                "registered": True,
                "groups": ["prod"],
            }
        },
    )

    hostIP: IPv4Address = Field(description="Unique IPv4 address for the host.")
    registered: bool = Field(
        False,
        description="Whether this host is currently registered in the host inventory.",
    )
    groups: list[str] = Field(
        default_factory=list,
        description="Groups this host belongs to. Missing groups are created automatically.",
        examples=[["dev", "critical"]],
    )


class HostUpdate(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "example": {
                "registered": True,
            }
        },
    )

    hostIP: Optional[IPv4Address] = Field(
        None,
        description="Optional. If present, it must match the path IP address.",
    )
    registered: Optional[bool] = Field(
        None,
        description="New registration state. This is the only host property external systems can update.",
    )


class HostDocument(BaseModel):
    id: str
    hostIP: str
    registered: bool
    groups: list[str] = Field(default_factory=list, description="Groups this host currently belongs to.")
    createdAt: datetime
    updatedAt: datetime
    fieldChanges: dict[str, Any] = Field(
        default_factory=dict,
        description="Latest registration or group-change metadata, used by the UI to highlight API-driven changes.",
    )


class GroupDocument(BaseModel):
    id: str
    name: str
    members: list[str] = Field(default_factory=list, description="Host IPs currently assigned to this group.")
    createdAt: datetime
    updatedAt: datetime


api_key_header = APIKeyHeader(
    name="X-API-Key",
    auto_error=False,
    description="API key generated from the web UI. Use it only to request a JWT token.",
)
bearer_auth = HTTPBearer(
    auto_error=False,
    description="JWT returned by /public/auth/token. Send as Authorization: Bearer <token>.",
)


app = FastAPI(
    title="Host Workbench - Public API",
    version="1.0.0",
    docs_url="/docs",
    redoc_url=None,
    openapi_url="/openapi.json",
    description=(
        "Host Workbench public API for demonstrating GET, POST, and PUT integrations from Forescout Connect Apps "
        "or another remote client. Generate an API key in the web UI, exchange it for a JWT at "
        "`POST /public/auth/token`, then call the host endpoints with `Authorization: Bearer <token>`. "
        "Internal web UI endpoints are intentionally excluded from this Swagger document."
    ),
    contact={"name": "Host Workbench"},
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

public_router = APIRouter(prefix="/public")
internal_router = APIRouter(prefix="/internal", include_in_schema=False)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def collection(name: str):
    if db is None:
        raise RuntimeError("Database is not initialized")
    return db[name]


def hash_api_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


def normalize_value(value: Any) -> Any:
    if isinstance(value, ObjectId):
        return str(value)
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, list):
        return [normalize_value(item) for item in value]
    if isinstance(value, dict):
        return {key: normalize_value(item) for key, item in value.items()}
    return value


def host_to_response(doc: dict[str, Any]) -> dict[str, Any]:
    result = {}
    for key, value in doc.items():
        if key not in HOST_DOCUMENT_FIELDS:
            continue
        if key == "_id":
            result["id"] = str(value)
        else:
            result[key] = normalize_value(value)
    result.setdefault("registered", False)
    result.setdefault("groups", [])
    result.setdefault("fieldChanges", {})
    result.setdefault("changeLog", [])
    return result


def group_to_response(doc: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": str(doc["_id"]),
        "name": doc["name"],
        "members": sorted(doc.get("members", []), key=ip_sort_key),
        "createdAt": normalize_value(doc.get("createdAt")),
        "updatedAt": normalize_value(doc.get("updatedAt")),
    }


def ip_sort_key(value: str) -> tuple[int, str]:
    try:
        return (int(ipaddress.ip_address(value)), value)
    except ValueError:
        return (0, value)


def validate_host_ip(value: str) -> str:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="host IP must be a valid IPv4 address") from exc
    if ip.version != 4:
        raise HTTPException(status_code=422, detail="only IPv4 addresses are supported")
    return str(ip)


def validate_group_name(value: str) -> str:
    name = value.strip().lower()
    if not name:
        raise HTTPException(status_code=422, detail="group name is required")
    if len(name) > 40:
        raise HTTPException(status_code=422, detail="group name must be 40 characters or fewer")
    allowed = set("abcdefghijklmnopqrstuvwxyz0123456789_-")
    if any(char not in allowed for char in name):
        raise HTTPException(
            status_code=422,
            detail="group name may contain only letters, numbers, underscore, or dash",
        )
    return name


def normalize_group_list(groups: list[Any]) -> list[str]:
    normalized = []
    seen = set()
    for group in groups:
        name = validate_group_name(str(group))
        if name not in seen:
            normalized.append(name)
            seen.add(name)
    return sorted(normalized)


def validate_mongo_field_name(name: str) -> None:
    if name in RESERVED_FIELDS:
        raise HTTPException(status_code=422, detail=f"'{name}' is a reserved field")
    if name.startswith("$") or "." in name:
        raise HTTPException(status_code=422, detail=f"'{name}' is not a valid MongoDB field name")


def validate_payload_value(value: Any, path: str) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            validate_mongo_field_name(key)
            validate_payload_value(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            validate_payload_value(child, f"{path}[{index}]")


def payload_from_model(model: BaseModel, *, exclude_unset: bool) -> dict[str, Any]:
    payload = model.model_dump(exclude_unset=exclude_unset)
    payload = jsonable_encoder(payload)
    for key, value in payload.items():
        validate_mongo_field_name(key)
        validate_payload_value(value, key)
    return payload


def build_created_host_payload(payload: dict[str, Any]) -> dict[str, Any]:
    host_ip = validate_host_ip(str(payload["hostIP"]))
    return {
        "hostIP": host_ip,
        "registered": bool(payload.get("registered", False)),
        "groups": normalize_group_list(payload.get("groups", [])),
    }


def change_record(
    field: str,
    old_value: Any,
    new_value: Any,
    changed_at: datetime,
    source: str,
    operation: str,
) -> dict[str, Any]:
    return {
        "field": field,
        "oldValue": normalize_value(old_value),
        "newValue": normalize_value(new_value),
        "changedAt": changed_at,
        "source": source,
        "operation": operation,
    }


async def ensure_group(name: str) -> dict[str, Any]:
    group_name = validate_group_name(name)
    now = utc_now()
    await collection("groups").update_one(
        {"name": group_name},
        {
            "$setOnInsert": {
                "name": group_name,
                "members": [],
                "createdAt": now,
                "updatedAt": now,
            }
        },
        upsert=True,
    )
    group = await collection("groups").find_one({"name": group_name})
    if group is None:
        raise HTTPException(status_code=500, detail="failed to create group")
    return group


async def ensure_groups(names: list[str]) -> list[str]:
    normalized = normalize_group_list(names)
    for name in normalized:
        await ensure_group(name)
    return normalized


async def ensure_default_groups() -> None:
    await ensure_groups(DEFAULT_GROUPS)


async def rebuild_group_memberships() -> None:
    now = utc_now()
    await ensure_default_groups()
    host_groups = await collection("hosts").distinct("groups")
    await ensure_groups([group for group in host_groups if isinstance(group, str)])
    await collection("groups").update_many({}, {"$set": {"members": [], "updatedAt": now}})
    async for host in collection("hosts").find({}):
        host_ip = host.get("hostIP")
        if not host_ip:
            continue
        for group in host.get("groups", []):
            await collection("groups").update_one(
                {"name": group},
                {"$addToSet": {"members": host_ip}, "$set": {"updatedAt": now}},
            )


async def normalize_host_documents() -> None:
    now = utc_now()
    async for doc in collection("hosts").find({}):
        unset_values = {key: "" for key in doc if key not in HOST_DOCUMENT_FIELDS}
        set_values: dict[str, Any] = {}

        if not isinstance(doc.get("registered"), bool):
            set_values["registered"] = bool(doc.get("registered", False))
        groups = doc.get("groups", [])
        if not isinstance(groups, list):
            groups = []
        normalized_groups = normalize_group_list(groups)
        if doc.get("groups") != normalized_groups:
            set_values["groups"] = normalized_groups
        if not isinstance(doc.get("createdAt"), datetime):
            set_values["createdAt"] = now
        if not isinstance(doc.get("updatedAt"), datetime):
            set_values["updatedAt"] = now

        field_changes = doc.get("fieldChanges")
        normalized_changes = {}
        if isinstance(field_changes, dict) and isinstance(field_changes.get("registered"), dict):
            normalized_changes["registered"] = field_changes["registered"]
        if isinstance(field_changes, dict) and isinstance(field_changes.get("groups"), dict):
            normalized_changes["groups"] = field_changes["groups"]
        if field_changes != normalized_changes:
            set_values["fieldChanges"] = normalized_changes

        change_log = doc.get("changeLog")
        normalized_log = []
        if isinstance(change_log, list):
            normalized_log = [
                entry
                for entry in change_log
                if isinstance(entry, dict) and entry.get("field") in {"registered", "groups"}
            ][-200:]
        if change_log != normalized_log:
            set_values["changeLog"] = normalized_log

        if unset_values or set_values:
            update_doc: dict[str, Any] = {}
            if unset_values:
                update_doc["$unset"] = unset_values
            if set_values:
                update_doc["$set"] = set_values
            await collection("hosts").update_one({"_id": doc["_id"]}, update_doc)
    await rebuild_group_memberships()


async def publish_event(event: dict[str, Any]) -> None:
    if not subscribers:
        return
    event = normalize_value(event)
    for queue in list(subscribers):
        try:
            queue.put_nowait(event)
        except asyncio.QueueFull:
            try:
                queue.get_nowait()
            except asyncio.QueueEmpty:
                pass
            queue.put_nowait(event)


async def create_host(payload: dict[str, Any], source: str) -> dict[str, Any]:
    now = utc_now()
    host_payload = build_created_host_payload(payload)
    await ensure_groups(host_payload["groups"])
    field_changes = {
        field: change_record(field, None, value, now, source, "created")
        for field, value in host_payload.items()
        if field != "hostIP"
    }
    doc = {
        **host_payload,
        "createdAt": now,
        "updatedAt": now,
        "fieldChanges": field_changes,
        "changeLog": list(field_changes.values()),
    }
    try:
        await collection("hosts").insert_one(doc)
    except DuplicateKeyError as exc:
        raise HTTPException(status_code=409, detail="hostIP already exists") from exc
    for group in host_payload["groups"]:
        await collection("groups").update_one(
            {"name": group},
            {"$addToSet": {"members": doc["hostIP"]}, "$set": {"updatedAt": now}},
        )
    await publish_event({"type": "host_created", "hostIP": doc["hostIP"], "changedAt": now.isoformat()})
    return doc


async def upsert_host(host_ip: str, payload: dict[str, Any], source: str) -> tuple[dict[str, Any], bool]:
    host_ip = validate_host_ip(host_ip)
    if "hostIP" in payload:
        body_ip = validate_host_ip(str(payload.pop("hostIP")))
        if body_ip != host_ip:
            raise HTTPException(status_code=422, detail="body hostIP must match the path host IP")

    existing = await collection("hosts").find_one({"hostIP": host_ip})
    if existing is None:
        payload["hostIP"] = host_ip
        created = await create_host(payload, source)
        return created, True

    now = utc_now()
    changes = {}
    set_values: dict[str, Any] = {"updatedAt": now}
    push_changes = []
    for field, new_value in payload.items():
        validate_mongo_field_name(field)
        old_value = existing.get(field)
        if old_value != new_value:
            record = change_record(field, old_value, new_value, now, source, "updated")
            set_values[field] = new_value
            set_values[f"fieldChanges.{field}"] = record
            push_changes.append(record)
            changes[field] = record

    if not changes:
        return existing, False

    update_doc: dict[str, Any] = {"$set": set_values}
    if push_changes:
        update_doc["$push"] = {"changeLog": {"$each": push_changes, "$slice": -200}}
    await collection("hosts").update_one({"hostIP": host_ip}, update_doc)
    updated = await collection("hosts").find_one({"hostIP": host_ip})
    await publish_event(
        {
            "type": "host_updated",
            "hostIP": host_ip,
            "fields": list(changes.keys()),
            "changedAt": now.isoformat(),
            "source": source,
        }
    )
    return updated, False


async def add_host_to_group(host_ip: str, group_name: str, source: str) -> dict[str, Any]:
    host_ip = validate_host_ip(host_ip)
    group_name = validate_group_name(group_name)
    host = await collection("hosts").find_one({"hostIP": host_ip})
    if host is None:
        raise HTTPException(status_code=404, detail="host not found")

    await ensure_group(group_name)
    old_groups = normalize_group_list(host.get("groups", []))
    if group_name in old_groups:
        return host_to_response(host)

    now = utc_now()
    new_groups = normalize_group_list([*old_groups, group_name])
    record = change_record("groups", old_groups, new_groups, now, source, "updated")
    await collection("hosts").update_one(
        {"hostIP": host_ip},
        {
            "$set": {
                "groups": new_groups,
                "updatedAt": now,
                "fieldChanges.groups": record,
            },
            "$push": {"changeLog": {"$each": [record], "$slice": -200}},
        },
    )
    await collection("groups").update_one(
        {"name": group_name},
        {"$addToSet": {"members": host_ip}, "$set": {"updatedAt": now}},
    )
    updated = await collection("hosts").find_one({"hostIP": host_ip})
    await publish_event(
        {
            "type": "host_group_added",
            "hostIP": host_ip,
            "group": group_name,
            "changedAt": now.isoformat(),
            "source": source,
        }
    )
    return host_to_response(updated)


async def remove_host_from_group(host_ip: str, group_name: str, source: str) -> dict[str, Any]:
    host_ip = validate_host_ip(host_ip)
    group_name = validate_group_name(group_name)
    host = await collection("hosts").find_one({"hostIP": host_ip})
    if host is None:
        raise HTTPException(status_code=404, detail="host not found")

    old_groups = normalize_group_list(host.get("groups", []))
    if group_name not in old_groups:
        await collection("groups").update_one({"name": group_name}, {"$pull": {"members": host_ip}})
        return host_to_response(host)

    now = utc_now()
    new_groups = [group for group in old_groups if group != group_name]
    record = change_record("groups", old_groups, new_groups, now, source, "updated")
    await collection("hosts").update_one(
        {"hostIP": host_ip},
        {
            "$set": {
                "groups": new_groups,
                "updatedAt": now,
                "fieldChanges.groups": record,
            },
            "$push": {"changeLog": {"$each": [record], "$slice": -200}},
        },
    )
    await collection("groups").update_one(
        {"name": group_name},
        {"$pull": {"members": host_ip}, "$set": {"updatedAt": now}},
    )
    updated = await collection("hosts").find_one({"hostIP": host_ip})
    await publish_event(
        {
            "type": "host_group_removed",
            "hostIP": host_ip,
            "group": group_name,
            "changedAt": now.isoformat(),
            "source": source,
        }
    )
    return host_to_response(updated)


async def require_public_token(
    credentials: Optional[HTTPAuthorizationCredentials] = Security(bearer_auth),
) -> dict[str, Any]:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing bearer token. Call /public/auth/token first.",
        )
    try:
        payload = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError as exc:
        raise HTTPException(status_code=401, detail="JWT token has expired") from exc
    except jwt.InvalidTokenError as exc:
        raise HTTPException(status_code=401, detail="Invalid JWT token") from exc
    return payload


@app.on_event("startup")
async def startup() -> None:
    global mongo_client, db
    mongo_client = AsyncIOMotorClient(MONGO_URI, serverSelectionTimeoutMS=10000)
    db = mongo_client[MONGO_DB]
    await db.command("ping")
    await db.hosts.create_index([("hostIP", ASCENDING)], unique=True)
    await db.hosts.create_index([("updatedAt", ASCENDING)])
    await db.api_keys.create_index([("keyHash", ASCENDING)], unique=True)
    await db.api_keys.create_index([("createdAt", ASCENDING)])
    await db.groups.create_index([("name", ASCENDING)], unique=True)
    await db.groups.create_index([("updatedAt", ASCENDING)])
    await normalize_host_documents()


@app.on_event("shutdown")
async def shutdown() -> None:
    if mongo_client is not None:
        mongo_client.close()


@app.get("/health", include_in_schema=False)
async def health() -> dict[str, str]:
    return {"status": "ok"}


@internal_router.post("/api-keys", response_model=ApiKeyCreatedResponse)
async def generate_api_key(payload: ApiKeyCreateRequest) -> dict[str, Any]:
    existing = await collection("api_keys").find_one({"enabled": True}, sort=[("createdAt", -1)])
    if existing is not None and existing.get("apiKey"):
        return {
            "apiKey": existing["apiKey"],
            "keyPrefix": existing["keyPrefix"],
            "createdAt": existing["createdAt"],
        }

    api_key = f"fsdemo_{secrets.token_urlsafe(32)}"
    now = utc_now()
    doc = {
        "label": payload.label,
        "apiKey": api_key,
        "keyHash": hash_api_key(api_key),
        "keyPrefix": api_key[:16],
        "enabled": True,
        "createdAt": now,
        "lastUsedAt": None,
    }
    await collection("api_keys").insert_one(doc)
    return {"apiKey": api_key, "keyPrefix": doc["keyPrefix"], "createdAt": now}


@internal_router.get("/api-keys/current", response_model=CurrentApiKeyResponse)
async def get_current_api_key() -> dict[str, Any]:
    existing = await collection("api_keys").find_one({"enabled": True}, sort=[("createdAt", -1)])
    if existing is None:
        return {}
    return {
        "apiKey": existing.get("apiKey"),
        "keyPrefix": existing.get("keyPrefix"),
        "label": existing.get("label"),
        "createdAt": existing.get("createdAt"),
        "lastUsedAt": existing.get("lastUsedAt"),
    }


@internal_router.get("/api-keys")
async def list_api_keys() -> list[dict[str, Any]]:
    cursor = collection("api_keys").find({}, {"apiKey": 0, "keyHash": 0}).sort("createdAt", -1)
    return [normalize_value(doc) async for doc in cursor]


@internal_router.get("/hosts")
async def internal_list_hosts() -> list[dict[str, Any]]:
    cursor = collection("hosts").find({}).sort("hostIP", 1)
    return [host_to_response(doc) async for doc in cursor]


@internal_router.get("/groups", response_model=list[GroupDocument])
async def internal_list_groups() -> list[dict[str, Any]]:
    await ensure_default_groups()
    cursor = collection("groups").find({}).sort("name", 1)
    return [group_to_response(doc) async for doc in cursor]


@internal_router.post("/groups", response_model=GroupDocument)
async def internal_create_group(payload: GroupCreateRequest) -> dict[str, Any]:
    group = await ensure_group(payload.name)
    await publish_event(
        {
            "type": "group_created",
            "group": group["name"],
            "changedAt": utc_now().isoformat(),
            "source": "web_ui",
        }
    )
    return group_to_response(group)


@internal_router.delete("/hosts", response_model=ClearHostsResponse)
async def clear_hosts() -> dict[str, int]:
    result = await collection("hosts").delete_many({})
    await collection("groups").update_many({}, {"$set": {"members": [], "updatedAt": utc_now()}})
    await publish_event(
        {
            "type": "hosts_cleared",
            "deletedHosts": result.deleted_count,
            "changedAt": utc_now().isoformat(),
        }
    )
    return {"deletedHosts": result.deleted_count}


@internal_router.post("/hosts/generate", response_model=GenerateHostsResponse)
async def generate_hosts(payload: GenerateHostsRequest) -> dict[str, Any]:
    await ensure_default_groups()
    network = ipaddress.ip_network(payload.subnet, strict=False)
    host_ips = [str(ip) for ip in network.hosts()]
    existing_ips = set(
        await collection("hosts").distinct(
            "hostIP",
            {"hostIP": {"$in": host_ips}},
        )
    )
    available_ips = [ip for ip in host_ips if ip not in existing_ips]
    if payload.count > len(available_ips):
        raise HTTPException(
            status_code=409,
            detail=f"requested {payload.count} hosts, but only {len(available_ips)} addresses are available",
        )

    now = utc_now()
    selected_ips = random.sample(available_ips, payload.count)
    docs = []
    for index, host_ip in enumerate(selected_ips):
        group_name = DEFAULT_GROUPS[index % len(DEFAULT_GROUPS)]
        docs.append(
            {
                "hostIP": host_ip,
                "registered": random.choice([True, False]),
                "groups": [group_name],
                "createdAt": now,
                "updatedAt": now,
                "fieldChanges": {},
                "changeLog": [],
            }
        )
    if docs:
        await collection("hosts").insert_many(docs, ordered=False)
        for doc in docs:
            for group in doc["groups"]:
                await collection("groups").update_one(
                    {"name": group},
                    {"$addToSet": {"members": doc["hostIP"]}, "$set": {"updatedAt": now}},
                )
        await publish_event(
            {
                "type": "hosts_generated",
                "count": len(docs),
                "subnet": str(network),
                "changedAt": now.isoformat(),
            }
        )
    return {
        "generated": len(docs),
        "skippedExisting": len(existing_ips),
        "hosts": [host_to_response(doc) for doc in docs],
    }


@internal_router.get("/events")
async def events(request: Request) -> StreamingResponse:
    queue: asyncio.Queue = asyncio.Queue(maxsize=50)
    subscribers.add(queue)

    async def stream():
        try:
            yield "event: ready\ndata: {\"status\":\"connected\"}\n\n"
            while True:
                if await request.is_disconnected():
                    break
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=15)
                except asyncio.TimeoutError:
                    yield ": keep-alive\n\n"
                    continue
                yield f"event: hosts_changed\ndata: {json.dumps(event)}\n\n"
        finally:
            subscribers.discard(queue)

    return StreamingResponse(stream(), media_type="text/event-stream")


@public_router.post(
    "/auth/token",
    response_model=TokenResponse,
    tags=["Authentication"],
    summary="Exchange an API key for a JWT token",
    description=(
        "Send the API key generated in the web UI as the `X-API-Key` header. "
        "The response JWT is required for every public host endpoint and expires after the configured lifetime."
    ),
)
async def create_public_token(api_key: Optional[str] = Security(api_key_header)) -> dict[str, Any]:
    if not api_key:
        raise HTTPException(status_code=401, detail="X-API-Key header is required")
    key_hash = hash_api_key(api_key)
    api_key_doc = await collection("api_keys").find_one({"keyHash": key_hash, "enabled": True})
    if api_key_doc is None:
        raise HTTPException(status_code=401, detail="Invalid API key")
    now = utc_now()
    expires_at = now + timedelta(seconds=JWT_EXPIRES_SECONDS)
    token = jwt.encode(
        {
            "sub": str(api_key_doc["_id"]),
            "scope": "public-api",
            "keyPrefix": api_key_doc["keyPrefix"],
            "iat": int(now.timestamp()),
            "exp": int(expires_at.timestamp()),
        },
        JWT_SECRET,
        algorithm=JWT_ALGORITHM,
    )
    await collection("api_keys").update_one({"_id": api_key_doc["_id"]}, {"$set": {"lastUsedAt": now}})
    return {"access_token": token, "token_type": "bearer", "expires_in": JWT_EXPIRES_SECONDS}


@public_router.get(
    "/hosts",
    response_model=list[HostDocument],
    tags=["Hosts"],
    summary="List hosts",
    description="Returns all generated or API-created hosts with registration state and group memberships. Requires a JWT bearer token.",
)
async def list_hosts(_: dict[str, Any] = Security(require_public_token)) -> list[dict[str, Any]]:
    cursor = collection("hosts").find({}).sort("hostIP", 1)
    return [host_to_response(doc) async for doc in cursor]


@public_router.get(
    "/hosts/{host_ip}",
    response_model=HostDocument,
    tags=["Hosts"],
    summary="Get one host by IP address",
    description="Returns one host, its registration state, group memberships, and latest change metadata. Requires a JWT bearer token.",
)
async def get_host(
    host_ip: str = Path(..., description="IPv4 address of the host to retrieve.", examples=["192.0.2.44"]),
    _: dict[str, Any] = Security(require_public_token),
) -> dict[str, Any]:
    host_ip = validate_host_ip(host_ip)
    doc = await collection("hosts").find_one({"hostIP": host_ip})
    if doc is None:
        raise HTTPException(status_code=404, detail="host not found")
    return host_to_response(doc)


@public_router.post(
    "/hosts",
    response_model=HostDocument,
    status_code=201,
    tags=["Hosts"],
    summary="Create a new host",
    description=(
        "Creates a host only when `hostIP` does not already exist. Host properties are `registered` and `groups`; "
        "missing groups are created automatically."
    ),
)
async def create_host_public(
    payload: HostCreate,
    _: dict[str, Any] = Security(require_public_token),
) -> dict[str, Any]:
    payload_dict = payload_from_model(payload, exclude_unset=False)
    created = await create_host(payload_dict, "public_api")
    return host_to_response(created)


@public_router.put(
    "/hosts/{host_ip}",
    response_model=HostDocument,
    tags=["Hosts"],
    summary="Create or update a host",
    description=(
        "Upserts by IP address. If the host does not exist, it is created. If it exists, the `registered` "
        "state is updated, timestamped, and sent to the web UI in real time. Use the group membership endpoints "
        "to add or remove group memberships."
    ),
)
async def upsert_host_public(
    payload: HostUpdate,
    host_ip: str = Path(..., description="IPv4 address to create or update.", examples=["192.0.2.44"]),
    _: dict[str, Any] = Security(require_public_token),
) -> dict[str, Any]:
    payload_dict = payload_from_model(payload, exclude_unset=True)
    updated, _ = await upsert_host(host_ip, payload_dict, "public_api")
    return host_to_response(updated)


@public_router.get(
    "/groups",
    response_model=list[GroupDocument],
    tags=["Groups"],
    summary="List groups and members",
    description="Returns all group names and their current host IP members. Requires a JWT bearer token.",
)
async def list_groups(_: dict[str, Any] = Security(require_public_token)) -> list[dict[str, Any]]:
    await ensure_default_groups()
    cursor = collection("groups").find({}).sort("name", 1)
    return [group_to_response(doc) async for doc in cursor]


@public_router.put(
    "/hosts/{host_ip}/groups/{group_name}",
    response_model=HostDocument,
    tags=["Groups"],
    summary="Add a host to a group",
    description=(
        "Adds an existing host to a group. If the group does not exist, it is created. "
        "Both the host `groups` list and the group `members` list are updated."
    ),
)
async def add_host_group_public(
    host_ip: str = Path(..., description="IPv4 address of the existing host.", examples=["192.0.2.44"]),
    group_name: str = Path(..., description="Group name to add the host to.", examples=["critical"]),
    _: dict[str, Any] = Security(require_public_token),
) -> dict[str, Any]:
    return await add_host_to_group(host_ip, group_name, "public_api")


@public_router.delete(
    "/hosts/{host_ip}/groups/{group_name}",
    response_model=HostDocument,
    tags=["Groups"],
    summary="Remove a host from a group",
    description=(
        "Removes an existing host from a group. Both the host `groups` list and the group `members` list "
        "are updated. The group object is kept so it can be reused later."
    ),
)
async def remove_host_group_public(
    host_ip: str = Path(..., description="IPv4 address of the existing host.", examples=["192.0.2.44"]),
    group_name: str = Path(..., description="Group name to remove the host from.", examples=["isolated"]),
    _: dict[str, Any] = Security(require_public_token),
) -> dict[str, Any]:
    return await remove_host_from_group(host_ip, group_name, "public_api")


app.include_router(internal_router)
app.include_router(public_router)
