"""Evidence-backed reporting engine supporting JSON, CSV, and PDF with external-sharing redaction."""

from __future__ import annotations

import csv
import io
import json
import re
from datetime import UTC, datetime
from typing import Any

from fpdf import FPDF

_ACCOUNT_ID_RE = re.compile(r"\b\d{12}\b")
_UUID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _redact_for_external_sharing(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _redact_for_external_sharing(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact_for_external_sharing(v) for v in value]
    if isinstance(value, str):
        masked = _ACCOUNT_ID_RE.sub("[REDACTED-ACCOUNT]", value)
        masked = _UUID_RE.sub("[REDACTED-ID]", masked)
        masked = _IPV4_RE.sub("[REDACTED-IP]", masked)
        return masked
    return value


def build_report_payload(
    *,
    report_type: str,
    provider_scope: str,
    tenant_id: str,
    records: list[dict[str, Any]],
    collection_status: str,
    redact_external: bool = False,
) -> dict[str, Any]:
    """Assemble standardized report envelope with provenance and optional redaction."""
    generated_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    payload: dict[str, Any] = {
        "product": "CloudSentinel",
        "report_type": report_type,
        "generated_at": generated_at,
        "assessment_period": "latest_observed",
        "cloud_provider": provider_scope,
        "scope": {"tenant_id": tenant_id, "record_count": len(records)},
        "collection_status": collection_status,
        "redacted_for_external_sharing": redact_external,
        "records": records,
    }
    if redact_external:
        payload["scope"]["tenant_id"] = "[REDACTED-TENANT]"
        payload["records"] = _redact_for_external_sharing(records)
    return payload


def render_report_json(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, indent=2, default=str).encode("utf-8")


def render_report_csv(payload: dict[str, Any]) -> bytes:
    output = io.StringIO()
    records: list[dict[str, Any]] = payload.get("records", [])
    if not records:
        writer = csv.writer(output)
        writer.writerow(
            ["report_type", "generated_at", "cloud_provider", "collection_status", "records"]
        )
        writer.writerow(
            [
                payload["report_type"],
                payload["generated_at"],
                payload["cloud_provider"],
                payload["collection_status"],
                0,
            ]
        )
        return output.getvalue().encode("utf-8")

    fieldnames = list(records[0].keys())
    dict_writer = csv.DictWriter(output, fieldnames=fieldnames)
    dict_writer.writeheader()
    for row in records:
        dict_writer.writerow(
            {
                k: json.dumps(v, default=str) if isinstance(v, dict | list) else v
                for k, v in row.items()
            }
        )
    return output.getvalue().encode("utf-8")


def render_report_pdf(payload: dict[str, Any]) -> bytes:
    """Render a clean, valid PDF report using fpdf2."""
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(
        0,
        10,
        f"CloudSentinel Report: {payload['report_type'].upper()}",
        new_x="LMARGIN",
        new_y="NEXT",
    )

    pdf.set_font("Helvetica", "", 10)
    meta_lines = [
        f"Generated At (UTC): {payload['generated_at']}",
        f"Cloud Provider Scope: {payload['cloud_provider']}",
        f"Collection Status: {payload['collection_status']}",
        f"External Sharing Redaction: {'ENABLED' if payload['redacted_for_external_sharing'] else 'DISABLED'}",
        f"Total Records: {len(payload.get('records', []))}",
    ]
    for line in meta_lines:
        pdf.cell(0, 6, line, new_x="LMARGIN", new_y="NEXT")

    pdf.ln(4)
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(0, 8, "Evidence & Findings Summary", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 9)

    records: list[dict[str, Any]] = payload.get("records", [])
    if not records:
        pdf.cell(
            0, 6, "No records matched the selected report scope.", new_x="LMARGIN", new_y="NEXT"
        )
    else:
        for idx, rec in enumerate(records[:50], start=1):
            summary_parts = [
                f"{idx}.",
                str(rec.get("rule_id") or rec.get("control_id") or rec.get("id", ""))[:40],
                f"[{rec.get('severity', rec.get('status', 'info'))}]",
                str(rec.get("title") or rec.get("name") or rec.get("action_type", ""))[:80],
            ]
            line = " ".join(part for part in summary_parts if part)
            safe_line = line.encode("latin-1", "replace").decode("latin-1")
            pdf.multi_cell(0, 5, safe_line, new_x="LMARGIN", new_y="NEXT")

    return bytes(pdf.output())
