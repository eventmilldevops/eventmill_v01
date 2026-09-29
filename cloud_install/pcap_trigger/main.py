"""
PCAP Ingest Trigger — Phase 1

Cloud Run function (Eventarc, gen2) triggered on
``google.cloud.storage.object.v1.finalized`` for the network-forensics
"bucket B". Validates the uploaded object, resolves the sensor_id from the
first path segment, checks it against the allow-list stored in the common
bucket, and writes an acknowledgment marker back to bucket B.

Phase 1 scope: prove the trigger fires reliably and the sensor_id is parsed
and validated correctly. No Event Mill code path is invoked here — this is a
standalone, independently deployed unit (see
docs/specs/pcap_ingest_trigger_phase1.md).
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
from datetime import datetime, timezone

import functions_framework
from cloudevents.http import CloudEvent
from pydantic import BaseModel, ValidationError, field_validator

logger = logging.getLogger("pcap_trigger")
logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))

_PCAP_EXTENSIONS = (".pcap", ".pcapng")
_SENSOR_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_-]+$")
_SENSOR_REGISTRY_TTL_SECONDS = int(os.environ.get("SENSOR_REGISTRY_TTL_SECONDS", "300"))

_STATUS_ACKNOWLEDGED = "acknowledged"
_STATUS_UNMAPPED = "unmapped"

# Module-level cache for the sensor allow-list, refreshed every
# _SENSOR_REGISTRY_TTL_SECONDS so registry edits don't require a redeploy.
_sensor_registry_cache: set[str] | None = None
_sensor_registry_loaded_at: float = 0.0


class PcapUploadEvent(BaseModel):
    """Validated fields extracted from a storage.object.v1.finalized event."""

    bucket: str
    object_name: str
    sensor_id: str
    size: int
    event_id: str

    @field_validator("sensor_id")
    @classmethod
    def _validate_sensor_id(cls, value: str) -> str:
        if not _SENSOR_ID_PATTERN.match(value):
            raise ValueError(f"sensor_id contains invalid characters: {value!r}")
        return value


def _common_bucket_name() -> str:
    """Return the shared common bucket name, following the resolver convention."""
    override = os.environ.get("EVENTMILL_BUCKET_COMMON")
    if override:
        return override
    prefix = os.environ.get("EVENTMILL_BUCKET_PREFIX", "eventmill")
    return f"{prefix}-common"


def _load_sensor_registry() -> set[str]:
    """Load (and cache) the sensor allow-list from the common bucket.

    Fails closed: any error loading the registry results in an empty
    allow-list, so every sensor_id is treated as unrecognized.
    """
    global _sensor_registry_cache, _sensor_registry_loaded_at

    now = time.monotonic()
    if (
        _sensor_registry_cache is not None
        and (now - _sensor_registry_loaded_at) < _SENSOR_REGISTRY_TTL_SECONDS
    ):
        return _sensor_registry_cache

    bucket_name = _common_bucket_name()
    try:
        from google.cloud import storage

        client = storage.Client()
        blob = client.bucket(bucket_name).blob("config/sensors.json")
        payload = json.loads(blob.download_as_bytes())
        sensor_ids = set(payload.get("sensor_ids", []))
        logger.info(
            "Loaded sensor registry from gs://%s/config/sensors.json (%d sensors)",
            bucket_name,
            len(sensor_ids),
        )
        _sensor_registry_cache = sensor_ids
        _sensor_registry_loaded_at = now
        return sensor_ids
    except Exception:
        logger.exception(
            "Failed to load sensor registry from gs://%s/config/sensors.json; "
            "failing closed (treating all sensors as unmapped)",
            bucket_name,
        )
        _sensor_registry_cache = set()
        _sensor_registry_loaded_at = now
        return _sensor_registry_cache


def _parse_sensor_id(object_name: str) -> str | None:
    """Return the first path segment of *object_name*, or None if there isn't one."""
    if "/" not in object_name:
        return None
    sensor_id, _, _rest = object_name.partition("/")
    return sensor_id or None


def _write_ack_marker(
    bucket_name: str,
    event: PcapUploadEvent,
    status: str,
) -> None:
    """Write a JSON acknowledgment marker to gs://<bucket>/acks/<sensor_id>/<event_id>.json."""
    from google.cloud import storage

    marker = {
        "sensor_id": event.sensor_id,
        "source_object": event.object_name,
        "size": event.size,
        "status": status,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    ack_path = f"acks/{event.sensor_id}/{event.event_id}.json"

    client = storage.Client()
    blob = client.bucket(bucket_name).blob(ack_path)
    blob.upload_from_string(json.dumps(marker), content_type="application/json")
    logger.info("Wrote ack marker gs://%s/%s (status=%s)", bucket_name, ack_path, status)


@functions_framework.cloud_event
def handle_pcap_upload(cloud_event: CloudEvent) -> None:
    """Entry point for the Eventarc storage.object.v1.finalized trigger."""
    data = cloud_event.data or {}
    object_name = data.get("name", "")

    if not object_name.lower().endswith(_PCAP_EXTENSIONS):
        logger.info("Ignoring non-PCAP object: %s", object_name)
        return

    sensor_id = _parse_sensor_id(object_name)
    if sensor_id is None:
        logger.info("Ignoring object with no sensor folder segment: %s", object_name)
        return

    try:
        event = PcapUploadEvent(
            bucket=data.get("bucket", ""),
            object_name=object_name,
            sensor_id=sensor_id,
            size=int(data.get("size", 0)),
            event_id=cloud_event["id"],
        )
    except (ValidationError, ValueError, TypeError):
        logger.exception("Malformed storage event, skipping: %s", data)
        return

    registry = _load_sensor_registry()
    status = _STATUS_ACKNOWLEDGED if event.sensor_id in registry else _STATUS_UNMAPPED

    try:
        _write_ack_marker(event.bucket, event, status)
    except Exception:
        logger.exception(
            "Failed to write ack marker for %s (sensor=%s)",
            event.object_name,
            event.sensor_id,
        )
