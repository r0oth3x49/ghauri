#!/usr/bin/python3
# -*- coding: utf-8 -*-
# pylint: disable=R,W,E,C

"""Flask-based web UI for ghauri."""

from __future__ import annotations

import logging
import os
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Optional
from urllib.parse import urlparse
import re

from flask import (
    Flask,
    abort,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)

from ghauri.ghauri import perform_injection
from ghauri.logger.colored_logger import logger

ENGINE_LOCK = threading.Lock()
JOBS_LOCK = threading.Lock()
DEFAULT_LANG = "en"
_thread_local = threading.local()


LANG_PACKS: Dict[str, Dict[str, Any]] = {
    "en": {
        "label": "English",
        "toggle_label": "繁體中文",
        "toggle_code": "zh-hant",
        "strings": {
            "app_title": "Ghauri Web Console",
            "tagline": "Run and monitor SQL injection probes from your browser.",
            "language": {
                "label": "Language",
                "toggle_hint": "Switch to Traditional Chinese",
            },
            "form": {
                "title": "Launch a scan",
                "subtitle": "Fill in the target details below.",
                "reminder": "Operate only on systems you are authorized to test.",
                "url_label": "Website address",
                "url_placeholder": "https://example.com/products?id=1",
                "data_label": "POST data (optional)",
                "headers_label": "Extra headers",
                "cookies_label": "Cookies",
                "proxy_label": "Proxy",
                "techniques_label": "Techniques",
                "level_label": "Detection level",
                "timeout_label": "Timeout (seconds)",
                "timesec_label": "Time delay for time-based checks",
                "threads_label": "Threads",
                "advanced_title": "Advanced settings",
                "advanced_hint": "Advanced options",
                "toggle_show": "Show advanced options",
                "toggle_hide": "Hide advanced options",
                "start_button": "Start scan",
            },
            "jobs": {
                "title": "Recent jobs",
                "empty": "No scans queued yet.",
                "id": "Job",
                "target": "Target",
                "status": "Status",
                "created": "Started",
                "view": "View details",
            },
            "status": {
                "pending": "Pending",
                "running": "Running…",
                "completed": "Completed",
                "failed": "Failed",
            },
            "job_detail": {
                "title": "Job details",
                "status": "Status",
                "started": "Started",
                "updated": "Updated",
                "summary_title": "Job summary",
                "target": "Target",
                "level": "Detection level",
                "techniques": "Techniques",
                "threads": "Threads",
                "live_log_title": "Live log",
                "live_log_hint": "New lines appear automatically.",
                "response_title": "Results",
                "response_waiting": "Waiting for results…",
                "response_success": "Injection confirmed.",
                "response_failure": "No injection detected.",
                "response_unknown": "Results not available yet.",
                "raw_json": "View raw response",
                "parameter": "Parameter",
                "dbms": "Database",
                "technique": "Technique",
                "logs_link": "Open full log",
                "dbms_summary": "DBMS probes",
                "last_technique": "Last technique",
                "warning_count": "Warnings",
                "log_controls": {
                    "auto_label": "Auto refresh",
                    "pause": "Pause",
                    "resume": "Resume",
                    "refresh": "Refresh",
                    "clear": "Clear view",
                    "download": "Download log",
                },
                "log_status_idle": "Watching for new output…",
                "log_status_paused": "Auto refresh paused.",
                "log_status_updated": "Log updated.",
                "log_status_cleared": "View cleared.",
                "log_status_error": "Unable to fetch log.",
                "error_title": "Engine error",
                "back": "Back to jobs",
            },
            "logs": {
                "title": "Log viewer",
                "empty": "No log output yet.",
            },
            "footer_note": "Always test responsibly and follow the law.",
        },
    },
    "zh-hant": {
        "label": "繁體中文",
        "toggle_label": "English",
        "toggle_code": "en",
        "strings": {
            "app_title": "Ghauri 網頁控制台",
            "tagline": "在線上操作與監控 SQL 注入測試。",
            "language": {
                "label": "語言",
                "toggle_hint": "切換為 English",
            },
            "form": {
                "title": "開始掃描",
                "subtitle": "請輸入目標的相關資訊。",
                "reminder": "請僅在取得授權的系統上操作。",
                "url_label": "網站地址",
                "url_placeholder": "https://example.com/products?id=1",
                "data_label": "POST 資料 (可選)",
                "headers_label": "額外標頭",
                "cookies_label": "Cookies",
                "proxy_label": "代理伺服器",
                "techniques_label": "測試技巧",
                "level_label": "測試層級",
                "timeout_label": "逾時 (秒)",
                "timesec_label": "時間型測試延遲",
                "threads_label": "執行緒",
                "advanced_title": "進階設定",
                "advanced_hint": "進階選項",
                "toggle_show": "展開進階選項",
                "toggle_hide": "收合進階選項",
                "start_button": "開始掃描",
            },
            "jobs": {
                "title": "最近的工作",
                "empty": "目前沒有排程，請先建立掃描。",
                "id": "工作",
                "target": "目標",
                "status": "狀態",
                "created": "建立時間",
                "view": "檢視詳情",
            },
            "status": {
                "pending": "等待中",
                "running": "執行中…",
                "completed": "已完成",
                "failed": "失敗",
            },
            "job_detail": {
                "title": "工作詳情",
                "status": "狀態",
                "started": "開始時間",
                "updated": "更新時間",
                "summary_title": "工作摘要",
                "target": "目標",
                "level": "測試層級",
                "techniques": "測試技巧",
                "threads": "執行緒",
                "live_log_title": "即時紀錄",
                "live_log_hint": "新的紀錄會自動出現。",
                "response_title": "結果",
                "response_waiting": "等待結果…",
                "response_success": "已確認存在注入。",
                "response_failure": "未偵測到注入。",
                "response_unknown": "尚無結果。",
                "raw_json": "檢視原始回應",
                "parameter": "參數",
                "dbms": "資料庫",
                "technique": "技巧",
                "logs_link": "開啟完整紀錄",
                "dbms_summary": "嘗試中的資料庫",
                "last_technique": "最新測試技巧",
                "warning_count": "警告數",
                "log_controls": {
                    "auto_label": "自動更新",
                    "pause": "暫停",
                    "resume": "恢復",
                    "refresh": "立即更新",
                    "clear": "清除畫面",
                    "download": "下載紀錄",
                },
                "log_status_idle": "等待新輸出…",
                "log_status_paused": "已暫停自動更新。",
                "log_status_updated": "紀錄已更新。",
                "log_status_cleared": "畫面已清除。",
                "log_status_error": "無法取得紀錄。",
                "error_title": "引擎錯誤",
                "back": "回到工作列表",
            },
            "logs": {
                "title": "紀錄檢視器",
                "empty": "目前尚無紀錄內容。",
            },
            "footer_note": "請遵循法律與授權範圍使用本工具。",
        },
    },
}


@dataclass
class Job:
    """Represents a web-driven scan run."""

    job_id: str
    status: str = "pending"
    params: Dict[str, Any] = field(default_factory=dict)
    response: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    log_path: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    lang: str = DEFAULT_LANG
    engine_kwargs: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        payload = {
            "id": self.job_id,
            "status": self.status,
            "params": self.params,
            "response": self.response,
            "error": self.error,
            "log_path": self.log_path,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "lang": self.lang,
        }
        return payload


JOBS: Dict[str, Job] = {}
JOB_LOG_BUFFERS: Dict[str, str] = {}
DBMS_PATTERNS = {
    "MySQL": re.compile(r"MySQL", re.IGNORECASE),
    "PostgreSQL": re.compile(r"PostgreSQL", re.IGNORECASE),
    "Oracle": re.compile(r"Oracle", re.IGNORECASE),
    "Microsoft SQL Server": re.compile(r"Microsoft SQL Server|Sybase", re.IGNORECASE),
    "SQLite": re.compile(r"SQLite", re.IGNORECASE),
    "DB2": re.compile(r"DB2", re.IGNORECASE),
}
TECHNIQUE_PATTERN = re.compile(r"testing '([^']+)'", re.IGNORECASE)


def _parse_int(value: Optional[str], default: Optional[int] = None) -> Optional[int]:
    try:
        if value is None or value == "":
            return default
        return int(value)
    except (TypeError, ValueError):
        return default


def _parse_bool(value: Optional[str]) -> bool:
    return value in {"on", "true", "True", "1"}


class JobLogHandler(logging.Handler):
    """Capture ghauri logger output for the active job thread."""

    def emit(self, record):
        job_id = getattr(_thread_local, "job_id", None)
        if not job_id:
            return
        try:
            message = record.getMessage()
        except Exception:  # pragma: no cover
            message = str(record.msg)
        if not message:
            return
        if not message.endswith("\n"):
            message = f"{message}\n"
        with JOBS_LOCK:
            existing = JOB_LOG_BUFFERS.get(job_id, "")
            JOB_LOG_BUFFERS[job_id] = (existing + message)[-120000:]


def _serialize_response(resp: Any) -> Optional[Dict[str, Any]]:
    if resp is None:
        return None
    if hasattr(resp, "_asdict"):
        data = resp._asdict()
    else:
        return None
    filepaths = data.get("filepaths")
    if hasattr(filepaths, "_asdict"):
        data["filepaths"] = filepaths._asdict()
    parameter = data.get("parameter")
    if parameter:
        data["parameter"] = {
            "key": getattr(parameter, "key", None),
            "value": getattr(parameter, "value", None),
            "type": getattr(parameter, "type", None),
        }
    attack = data.get("attack")
    if hasattr(attack, "_asdict"):
        data["attack"] = attack._asdict()
    vectors = data.get("vectors")
    if hasattr(vectors, "items"):
        serialized_vectors = {}
        for key, value in vectors.items():
            if hasattr(value, "_asdict"):
                serialized_vectors[key] = value._asdict()
            else:
                serialized_vectors[key] = value
        data["vectors"] = serialized_vectors
    return data


def _build_scan_kwargs(form_data: Dict[str, str]) -> Dict[str, Any]:
    kwargs: Dict[str, Any] = {
        "url": form_data.get("url", "").strip(),
        "data": form_data.get("data", "").strip(),
        "headers": form_data.get("headers", "").strip(),
        "cookies": form_data.get("cookies", "").strip(),
        "proxy": form_data.get("proxy", "").strip() or None,
        "ignore_code": form_data.get("ignore_code", "").strip(),
        "testparameter": [
            i.strip() for i in form_data.get("testparameter", "").split(",") if i.strip()
        ]
        or None,
        "batch": True,
        "verbosity": _parse_int(form_data.get("verbosity"), default=1) or 1,
        "level": _parse_int(form_data.get("level"), default=1) or 1,
        "timesec": _parse_int(form_data.get("timesec"), default=5) or 5,
        "delay": _parse_int(form_data.get("delay"), default=0) or 0,
        "timeout": _parse_int(form_data.get("timeout"), default=30) or 30,
        "threads": _parse_int(form_data.get("threads")) or None,
        "techniques": form_data.get("techniques", "BT").strip() or "BT",
        "skip_urlencoding": _parse_bool(form_data.get("skip_urlencode")),
        "confirm_payloads": _parse_bool(form_data.get("confirm_payloads")),
        "random_agent": _parse_bool(form_data.get("random_agent")),
        "mobile": _parse_bool(form_data.get("mobile")),
        "safe_chars": form_data.get("safe_chars", "").strip() or None,
        "fetch_using": form_data.get("fetch_using", "").strip() or None,
        "test_filter": form_data.get("test_filter", "").strip() or None,
        "user_agent": form_data.get("user_agent", "").strip(),
        "referer": form_data.get("referer", "").strip(),
        "host": form_data.get("host", "").strip(),
        "header": form_data.get("header", "").strip(),
    }
    if kwargs["threads"] and kwargs["threads"] < 1:
        kwargs["threads"] = None
    return kwargs


def _resolve_lang() -> str:
    lang = request.values.get("lang") or request.cookies.get("ghauri_lang") or DEFAULT_LANG
    if lang not in LANG_PACKS:
        lang = DEFAULT_LANG
    return lang


def _language_payload(lang: str) -> Dict[str, Any]:
    pack = LANG_PACKS[lang]
    return {
        "lang": lang,
        "strings": pack["strings"],
        "toggle_code": pack["toggle_code"],
        "toggle_label": pack["toggle_label"],
        "current_label": pack["label"],
    }


def _tail_log(log_path: Optional[str], max_chars: int = 6000) -> str:
    if not log_path or not os.path.exists(log_path):
        return ""
    try:
        with open(log_path, "r", encoding="utf-8", errors="ignore") as log_file:
            content = log_file.read()
        if len(content) > max_chars:
            content = content[-max_chars:]
        return content
    except OSError:
        return ""


def _read_log_chunk(
    log_path: Optional[str], offset: int = 0, max_bytes: int = 16000
) -> tuple[str, int, int, bool]:
    if not log_path or not os.path.exists(log_path):
        return "", offset, 0, False
    try:
        size = os.path.getsize(log_path)
    except OSError:
        return "", offset, 0, False
    reset = False
    if offset < 0:
        offset = 0
    if offset > size:
        offset = 0
        reset = True
    chunk = ""
    new_offset = offset
    if size > offset:
        try:
            with open(log_path, "rb") as log_file:
                log_file.seek(offset)
                data = log_file.read(max_bytes)
                new_offset = offset + len(data)
                chunk = data.decode("utf-8", errors="ignore")
        except OSError:
            chunk = ""
            new_offset = offset
    return chunk, new_offset, size, reset


def _predict_log_path(url: str) -> Optional[str]:
    if not url:
        return None
    parsed = urlparse(url)
    target = parsed.netloc or parsed.path
    if not target:
        return None
    host = target.split(":")[0].strip()
    if not host:
        return None
    base_dir = os.path.join(os.path.expanduser("~"), ".ghauri", host)
    return os.path.join(base_dir, "log")


def _get_combined_log(job: Job, limit: int = 20000) -> str:
    parts = []
    if job.log_path and os.path.exists(job.log_path):
        parts.append(_tail_log(job.log_path, max_chars=limit))
    buffer = JOB_LOG_BUFFERS.get(job.job_id, "")
    if buffer:
        parts.append(buffer[-limit:])
    return "\n".join([p for p in parts if p]).strip()


def _summarize_log(job: Job) -> Dict[str, Any]:
    text = _get_combined_log(job)
    if not text:
        return {"dbms": [], "last_test": None, "warnings": 0}
    found_dbms = []
    for label, pattern in DBMS_PATTERNS.items():
        if pattern.search(text):
            found_dbms.append(label)
    last_test = None
    for match in TECHNIQUE_PATTERN.finditer(text):
        last_test = match.group(1)
    warning_count = text.lower().count("[warning]")
    return {
        "dbms": found_dbms,
        "last_test": last_test,
        "warnings": warning_count,
    }


def _run_scan(job_id: str, kwargs: Dict[str, Any]) -> None:
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if not job:
            return
        job.status = "running"
        job.updated_at = datetime.utcnow()
        JOB_LOG_BUFFERS.setdefault(job_id, "")
    handler = JobLogHandler()
    logger.addHandler(handler)
    _thread_local.job_id = job_id
    try:
        with ENGINE_LOCK:
            response = perform_injection(**kwargs)
        serialized = _serialize_response(response)
        log_path = None
        if serialized and serialized.get("filepaths"):
            log_path = serialized["filepaths"].get("logs")
        with JOBS_LOCK:
            job = JOBS.get(job_id)
            if not job:
                return
            job.status = "completed"
            job.response = serialized
            job.log_path = log_path
            job.updated_at = datetime.utcnow()
    except SystemExit as exc:
        with JOBS_LOCK:
            job = JOBS.get(job_id)
            if not job:
                return
            job.status = "failed"
            job.error = str(exc)
            job.updated_at = datetime.utcnow()
    except Exception as exc:  # pragma: no cover
        logger.error(f"web ui job '{job_id}' errored: {exc}")
        with JOBS_LOCK:
            job = JOBS.get(job_id)
            if not job:
                return
            job.status = "failed"
            job.error = str(exc)
            job.updated_at = datetime.utcnow()
    finally:
        if hasattr(_thread_local, "job_id"):
            delattr(_thread_local, "job_id")
        logger.removeHandler(handler)


def create_app() -> Flask:
    app = Flask(__name__)

    @app.route("/", methods=["GET", "POST"])
    def index():
        if request.method == "POST":
            return start_scan()
        lang = _resolve_lang()
        lang_payload = _language_payload(lang)
        strings = lang_payload["strings"]
        with JOBS_LOCK:
            ordered_jobs = sorted(JOBS.values(), key=lambda j: j.created_at, reverse=True)
        response = make_response(
            render_template(
                "index.html",
                jobs=ordered_jobs,
                strings=strings,
                lang=lang,
                language_meta=lang_payload,
                status_labels=strings["status"],
            )
        )
        response.set_cookie("ghauri_lang", lang, max_age=30 * 24 * 60 * 60)
        return response

    @app.route("/scan", methods=["POST"])
    def start_scan():
        lang = _resolve_lang()
        lang_payload = _language_payload(lang)
        strings = lang_payload["strings"]
        form_data = request.form
        kwargs = _build_scan_kwargs(form_data)
        if not kwargs.get("url"):
            abort(400, description=strings["form"]["url_label"])
        job_id = uuid.uuid4().hex
        display_params = {
            "url": kwargs.get("url"),
            "level": kwargs.get("level"),
            "techniques": kwargs.get("techniques"),
            "threads": kwargs.get("threads") or 1,
        }
        job = Job(
            job_id=job_id,
            params=display_params,
            lang=lang,
            engine_kwargs=kwargs,
        )
        predicted_log_path = _predict_log_path(kwargs.get("url", ""))
        if predicted_log_path:
            job.log_path = predicted_log_path
        with JOBS_LOCK:
            JOBS[job_id] = job
        thread = threading.Thread(target=_run_scan, args=(job_id, kwargs), daemon=True)
        thread.start()
        return redirect(url_for("job_detail", job_id=job_id, lang=lang))

    @app.route("/jobs/<job_id>")
    def job_detail(job_id: str):
        lang = _resolve_lang()
        lang_payload = _language_payload(lang)
        strings = lang_payload["strings"]
        with JOBS_LOCK:
            job = JOBS.get(job_id)
        if not job:
            abort(404)
        summary = _summarize_log(job)
        response = make_response(
            render_template(
                "job_detail.html",
                job=job,
                strings=strings,
                lang=lang,
                language_meta=lang_payload,
                status_labels=strings["status"],
                summary=summary,
            )
        )
        response.set_cookie("ghauri_lang", lang, max_age=30 * 24 * 60 * 60)
        return response

    @app.route("/jobs/<job_id>/logs")
    def job_logs(job_id: str):
        lang = _resolve_lang()
        lang_payload = _language_payload(lang)
        strings = lang_payload["strings"]
        with JOBS_LOCK:
            job = JOBS.get(job_id)
        if not job:
            abort(404)
        logs_content = _tail_log(job.log_path)
        if not logs_content:
            logs_content = JOB_LOG_BUFFERS.get(job_id, "")
        response = make_response(
            render_template(
                "logs.html",
                job=job,
                logs=logs_content,
                strings=strings,
                lang=lang,
                language_meta=lang_payload,
            )
        )
        response.set_cookie("ghauri_lang", lang, max_age=30 * 24 * 60 * 60)
        return response

    @app.route("/api/jobs")
    def api_jobs():
        with JOBS_LOCK:
            payload = [job.to_dict() for job in JOBS.values()]
        return jsonify(payload)

    @app.route("/api/jobs/<job_id>")
    def api_job_detail(job_id: str):
        with JOBS_LOCK:
            job = JOBS.get(job_id)
        if not job:
            abort(404)
        payload = job.to_dict()
        payload["log_summary"] = _summarize_log(job)
        return jsonify(payload)

    @app.route("/api/jobs/<job_id>/logs")
    def api_job_logs(job_id: str):
        with JOBS_LOCK:
            job = JOBS.get(job_id)
        if not job:
            abort(404)
        offset = request.args.get("offset", 0, type=int)
        chunk = ""
        new_offset = offset
        size = 0
        reset = False
        if job.log_path:
            chunk, new_offset, size, reset = _read_log_chunk(
                job.log_path, offset=offset
            )
        if not chunk:
            buffer = JOB_LOG_BUFFERS.get(job_id, "")
            size = len(buffer)
            if offset > size:
                offset = 0
                reset = True
            chunk = buffer[offset:]
            new_offset = offset + len(chunk)
        response_payload = {
            "chunk": chunk,
            "offset": new_offset,
            "size": size,
            "reset": reset,
            "status": job.status,
            "updated_at": job.updated_at.isoformat(),
        }
        return jsonify(response_payload)

    @app.route("/jobs/<job_id>/logs/download")
    def job_logs_download(job_id: str):
        with JOBS_LOCK:
            job = JOBS.get(job_id)
        if not job:
            abort(404)
        buffer = JOB_LOG_BUFFERS.get(job_id)
        if job.log_path and os.path.exists(job.log_path) and os.path.getsize(job.log_path) > 0:
            return send_file(
                job.log_path,
                mimetype="text/plain",
                as_attachment=True,
                download_name=f"{job.job_id}.log",
            )
        if not buffer:
            abort(404)
        response = make_response(buffer)
        response.headers["Content-Type"] = "text/plain; charset=utf-8"
        response.headers["Content-Disposition"] = f"attachment; filename={job.job_id}.log"
        return response

    return app


def main() -> None:
    app = create_app()
    app.run(host="0.0.0.0", port=8000)


if __name__ == "__main__":
    main()
