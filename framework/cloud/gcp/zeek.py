"""
Zeek Cloud Build Integration

Triggers and monitors Zeek PCAP processing jobs via Cloud Build.
Used by the EventMill CLI 'zeek' command to process large PCAPs
that exceed Cloud Run's memory/timeout limits.
"""

from __future__ import annotations

import logging
import os
import time
import uuid
from pathlib import Path
from typing import Any

logger = logging.getLogger("eventmill.framework.cloud.gcp.zeek")

# Cloud Build job status values
_STATUS_WORKING = "WORKING"
_STATUS_QUEUED = "QUEUED"
_STATUS_SUCCESS = "SUCCESS"
_STATUS_FAILURE = "FAILURE"
_STATUS_TIMEOUT = "TIMEOUT"
_STATUS_CANCELLED = "CANCELLED"
_ACTIVE_STATUSES = {_STATUS_WORKING, _STATUS_QUEUED}


class ZeekCloudBuildClient:
    """Manages Zeek PCAP processing jobs on Cloud Build.

    Submits cloudbuild-zeek.yaml jobs, polls for completion,
    and retrieves output log file URIs from GCS.
    """

    def __init__(
        self,
        project_id: str | None = None,
        region: str | None = None,
        bucket_prefix: str | None = None,
    ):
        self.project_id = (
            project_id
            or os.environ.get("GOOGLE_CLOUD_PROJECT")
            or os.environ.get("GCP_PROJECT_ID")
            or self._resolve_project_from_metadata()
            or self._resolve_project_from_gcloud()
        )
        self.region = region or os.environ.get("CLOUD_RUN_REGION", "northamerica-northeast2")
        self.bucket_prefix = bucket_prefix or os.environ.get("EVENTMILL_BUCKET_PREFIX", "")
        self._client = None

    @staticmethod
    def _resolve_project_from_metadata() -> str | None:
        """Resolve project ID from the GCE/Cloud Run metadata server."""
        try:
            import urllib.request

            req = urllib.request.Request(
                "http://metadata.google.internal/computeMetadata/v1/project/project-id",
                headers={"Metadata-Flavor": "Google"},
            )
            with urllib.request.urlopen(req, timeout=2) as resp:
                project = resp.read().decode("utf-8").strip()
                if project:
                    logger.debug("Resolved GCP project from metadata server: %s", project)
                    return project
        except Exception:
            pass
        return None

    @staticmethod
    def _resolve_project_from_gcloud() -> str | None:
        """Ask the locally authenticated gcloud for the active project."""
        try:
            import subprocess
            result = subprocess.run(
                ["gcloud", "config", "get-value", "project"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            project = result.stdout.strip()
            if project and project != "(unset)":
                logger.debug("Resolved GCP project from gcloud config: %s", project)
                return project
        except Exception:
            pass
        return None

    def _get_client(self):
        """Lazy-init Cloud Build client."""
        if self._client is None:
            try:
                from google.cloud.devtools import cloudbuild_v1
                self._client = cloudbuild_v1.CloudBuildClient()
                logger.info("Cloud Build client initialized (project=%s)", self.project_id)
            except ImportError:
                raise ImportError(
                    "google-cloud-build package required for Zeek integration. "
                    "Install with: pip install google-cloud-build"
                )
        return self._client

    def submit_zeek_job(
        self,
        pcap_uri: str,
        output_prefix: str | None = None,
    ) -> dict[str, str]:
        """Submit a Zeek processing job to Cloud Build.

        Args:
            pcap_uri: GCS URI of the PCAP file (gs://bucket/path/file.pcap).
            output_prefix: GCS URI prefix for output. Auto-generated if None.

        Returns:
            Dict with 'build_id', 'pcap_uri', 'output_prefix', 'status'.
        """
        if not pcap_uri.startswith("gs://"):
            raise ValueError(f"pcap_uri must be a gs:// URI, got: {pcap_uri}")

        if not self.project_id:
            raise ValueError(
                "GCP project ID not set. Set GOOGLE_CLOUD_PROJECT env var "
                "or pass project_id to ZeekCloudBuildClient."
            )

        client = self._get_client()
        from google.cloud.devtools import cloudbuild_v1

        # Generate output prefix if not provided
        if not output_prefix:
            run_id = datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:8]
            pcap_name = pcap_uri.rsplit("/", 1)[-1].rsplit(".", 1)[0]
            bucket = f"{self.bucket_prefix}-network-forensics" if self.bucket_prefix else pcap_uri.split("/")[2]
            output_prefix = f"gs://{bucket}/zeek-output/{pcap_name}-{run_id}"

        # Build the Cloud Build request inline (no YAML file needed at runtime)
        build = cloudbuild_v1.Build(
            steps=[
                # Step 1: Download PCAP
                cloudbuild_v1.BuildStep(
                    name="gcr.io/google.com/cloudsdktool/cloud-sdk",
                    id="download-pcap",
                    entrypoint="bash",
                    args=[
                        "-c",
                        f'mkdir -p /workspace/pcap /workspace/zeek-output && '
                        f'gsutil -o GSUtil:parallel_composite_upload_threshold=150M '
                        f'cp "{pcap_uri}" /workspace/pcap/capture.pcap && '
                        f'echo "Downloaded $(ls -lh /workspace/pcap/capture.pcap | awk \'{{print $5}}\')"',
                    ],
                ),
                # Step 2: Run Zeek
                cloudbuild_v1.BuildStep(
                    name="zeek/zeek:latest",
                    id="run-zeek",
                    entrypoint="bash",
                    args=[
                        "-c",
                        'cd /workspace/zeek-output && '
                        'zeek -r /workspace/pcap/capture.pcap '
                        'LogAscii::use_json=T '
                        'local '
                        '"Site::local_nets += { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 }" && '
                        'echo "Zeek complete: $(ls *.log 2>/dev/null | wc -l) log files"',
                    ],
                    wait_for=["download-pcap"],
                ),
                # Step 3: Upload results
                cloudbuild_v1.BuildStep(
                    name="gcr.io/google.com/cloudsdktool/cloud-sdk",
                    id="upload-results",
                    entrypoint="bash",
                    args=[
                        "-c",
                        f'for f in /workspace/zeek-output/*.log; do '
                        f'  [ -f "$f" ] && gsutil cp "$f" "{output_prefix}/$(basename $f)"; '
                        f'done && echo "Upload complete to {output_prefix}/"',
                    ],
                    wait_for=["run-zeek"],
                ),
            ],
            timeout={"seconds": 7200},
            options=cloudbuild_v1.BuildOptions(
                machine_type=cloudbuild_v1.BuildOptions.MachineType.E2_HIGHCPU_32,
                disk_size_gb=500,
                logging=cloudbuild_v1.BuildOptions.LoggingMode.CLOUD_LOGGING_ONLY,
            ),
        )

        # Submit
        operation = client.create_build(
            project_id=self.project_id,
            build=build,
        )

        # The operation metadata contains the build ID
        build_result = operation.metadata.build
        build_id = build_result.id

        logger.info("Zeek Cloud Build job submitted: %s", build_id)

        return {
            "build_id": build_id,
            "pcap_uri": pcap_uri,
            "output_prefix": output_prefix,
            "status": build_result.status.name if build_result.status else "QUEUED",
        }

    def get_build_status(self, build_id: str) -> dict[str, Any]:
        """Check status of a Zeek Cloud Build job.

        Returns:
            Dict with 'build_id', 'status', 'duration', 'log_url', 'output_files'.
        """
        client = self._get_client()

        build = client.get_build(project_id=self.project_id, id=build_id)

        result: dict[str, Any] = {
            "build_id": build_id,
            "status": build.status.name if build.status else "UNKNOWN",
        }

        if build.start_time and build.finish_time:
            duration = (build.finish_time - build.start_time).total_seconds()
            result["duration_seconds"] = int(duration)
            mins, secs = divmod(int(duration), 60)
            result["duration"] = f"{mins}m {secs}s"

        if build.log_url:
            result["log_url"] = build.log_url

        return result

    def wait_for_completion(
        self,
        build_id: str,
        poll_interval: int = 30,
        timeout: int = 7200,
        progress_callback=None,
    ) -> dict[str, Any]:
        """Poll until build completes or timeout.

        Args:
            build_id: Cloud Build build ID.
            poll_interval: Seconds between status checks.
            timeout: Max seconds to wait.
            progress_callback: Optional callable(status_dict) for progress updates.

        Returns:
            Final status dict.
        """
        elapsed = 0
        while elapsed < timeout:
            status = self.get_build_status(build_id)

            if progress_callback:
                progress_callback(status)

            if status["status"] not in _ACTIVE_STATUSES:
                return status

            time.sleep(poll_interval)
            elapsed += poll_interval

        return {"build_id": build_id, "status": "POLL_TIMEOUT", "elapsed": elapsed}

    def list_output_files(self, output_prefix: str) -> list[str]:
        """List Zeek output log files at the GCS prefix.

        Returns:
            List of gs:// URIs for each log file.
        """
        try:
            from google.cloud import storage

            # Parse bucket and prefix from gs:// URI
            parts = output_prefix.replace("gs://", "").split("/", 1)
            bucket_name = parts[0]
            prefix = parts[1] if len(parts) > 1 else ""
            if prefix and not prefix.endswith("/"):
                prefix += "/"

            client = storage.Client(project=self.project_id)
            bucket = client.bucket(bucket_name)
            blobs = bucket.list_blobs(prefix=prefix)

            return [f"gs://{bucket_name}/{blob.name}" for blob in blobs if blob.name.endswith(".log")]
        except ImportError:
            raise ImportError("google-cloud-storage required. Install with: pip install 'eventmill[gcp]'")


# Import guard for datetime
from datetime import datetime
