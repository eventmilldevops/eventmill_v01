"""
Event Mill Headless API — Phase 2 of the PCAP ingest pipeline.

Exposes the same investigation engine used by ``EventMillShell`` (session
management, PCAP parsing, tool execution, GCS export) over a small HTTP API
instead of the interactive REPL, so an automated caller (the Phase 1 PCAP
trigger) can run a full investigation without a human.

No session/tool/storage logic is duplicated here — this module drives the
existing ``EventMillShell`` instance methods directly (the same ``do_new``,
``do_pillar``, ``do_load``, ``do_connect``, ``do_run`` used by the shell),
then performs the export via the same ``StorageResolver.upload()`` the
shell's ``do_export`` command calls.

See docs/specs/pcap_ingest_trigger_phase2.md for the design.
"""

from __future__ import annotations

import io
import logging
import os
import re
from contextlib import redirect_stdout
from pathlib import Path

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, field_validator

from .shell import EventMillShell

logger = logging.getLogger("eventmill.api")

_SENSOR_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_-]+$")
_PCAP_EXTENSIONS = (".pcap", ".pcapng")

app = FastAPI(title="Event Mill Headless API")


class AnalyzeRequest(BaseModel):
    """Request body for POST /analyze."""

    pcap_uri: str
    sensor_id: str
    tool: str = "pcap_ai_analyzer"
    mode: str = "triage_summary"

    @field_validator("sensor_id")
    @classmethod
    def _validate_sensor_id(cls, value: str) -> str:
        if not _SENSOR_ID_PATTERN.match(value):
            raise ValueError(f"sensor_id contains invalid characters: {value!r}")
        return value

    @field_validator("pcap_uri")
    @classmethod
    def _validate_pcap_uri(cls, value: str) -> str:
        if not value.startswith("gs://"):
            raise ValueError("pcap_uri must be a gs:// URI")
        if not value.lower().endswith(_PCAP_EXTENSIONS):
            raise ValueError("pcap_uri must point to a .pcap/.pcapng file")
        return value


class AnalyzeResponse(BaseModel):
    """Response body for POST /analyze."""

    session_id: str
    status: str
    result_uri: str | None = None
    message: str | None = None


@app.get("/healthz")
def healthz() -> dict[str, str]:
    """Liveness check for Cloud Run."""
    return {"status": "ok"}


@app.post("/analyze", response_model=AnalyzeResponse)
def analyze(request: AnalyzeRequest) -> AnalyzeResponse:
    """Run a full headless investigation against a PCAP stored in GCS.

    Equivalent to the interactive sequence:
      new -> pillar network_forensics -> load <gs://...> -> connect ->
      run <tool> --mode <mode> -> export <artifact_id> <subfolder>
    """
    log_buffer = io.StringIO()
    shell = EventMillShell()

    with redirect_stdout(log_buffer):
        shell.do_new(f"pcap_pipeline:{request.sensor_id}")
    session = shell.session_manager.get_current_session()
    if session is None:
        logger.error("Failed to create session: %s", log_buffer.getvalue())
        raise HTTPException(status_code=500, detail="Failed to create session")

    try:
        with redirect_stdout(log_buffer):
            shell.do_pillar("network_forensics")
            shell.do_load(request.pcap_uri)
            shell.do_connect("")

        if shell.llm_client is None or not shell.llm_client.connected:
            logger.error(
                "LLM not connected for session %s: %s",
                session.session_id,
                log_buffer.getvalue(),
            )
            raise HTTPException(
                status_code=503,
                detail=(
                    "LLM not connected — check GEMINI_FLASH_API_KEY/"
                    "GEMINI_PRO_API_KEY environment variables."
                ),
            )

        artifacts_before = {
            a.artifact_id for a in shell.session_manager.list_artifacts()
        }

        with redirect_stdout(log_buffer):
            shell.do_run(f"{request.tool} --mode {request.mode}")

        new_artifacts = [
            a
            for a in shell.session_manager.list_artifacts()
            if a.artifact_id not in artifacts_before
        ]
        if not new_artifacts:
            logger.error(
                "Tool produced no artifacts for session %s: %s",
                session.session_id,
                log_buffer.getvalue(),
            )
            raise HTTPException(
                status_code=500,
                detail=f"{request.tool} completed but produced no artifact",
            )
        artifact = new_artifacts[-1]

        if shell.storage_resolver is None:
            raise HTTPException(
                status_code=500, detail="Storage resolver not initialized"
            )

        source_tool = getattr(artifact, "source_tool", None) or request.tool
        dest_folder = (
            f"exports/{source_tool}/pcap_pipeline/{request.sensor_id}/"
            f"{session.session_id}"
        )
        local_path = Path(artifact.file_path)
        resolved = shell.storage_resolver.upload(
            local_path=local_path,
            filename=local_path.name,
            pillar=session.active_pillar or "network_forensics",
            workspace_folder=dest_folder,
            target="common",
            metadata={
                "artifact_id": artifact.artifact_id,
                "artifact_type": artifact.artifact_type,
                "source_tool": source_tool,
                "sensor_id": request.sensor_id,
            },
        )

        logger.info(
            "Analysis complete for session %s, sensor %s -> %s",
            session.session_id,
            request.sensor_id,
            resolved.uri,
        )
        return AnalyzeResponse(
            session_id=session.session_id,
            status="completed",
            result_uri=resolved.uri,
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.error(
            "Headless analysis failed for session %s: %s\n%s",
            session.session_id,
            exc,
            log_buffer.getvalue(),
        )
        raise HTTPException(status_code=500, detail=str(exc)) from exc


def main() -> None:
    """Entry point for the headless API server (uvicorn)."""
    import uvicorn

    port = int(os.environ.get("PORT", "8080"))
    uvicorn.run(app, host="0.0.0.0", port=port)


if __name__ == "__main__":
    main()
