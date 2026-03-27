"""
WebSecure MongoDB Models
Stores users, websites, scans, vulnerabilities, and alerts in MongoDB.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from flask_login import UserMixin
from pymongo import ReturnDocument

import app as app_module
from app import login_manager


def _now() -> datetime:
    return datetime.utcnow()


def _col(name: str):
    if app_module.mongo_db is None:
        raise RuntimeError('MongoDB is not initialized. Check MONGODB_URI and app startup.')
    return app_module.mongo_db[name]


def _next_id(counter_name: str) -> int:
    doc = _col("counters").find_one_and_update(
        {"_id": counter_name},
        {"$inc": {"seq": 1}},
        upsert=True,
        return_document=ReturnDocument.AFTER,
    )
    return int(doc["seq"])


class BaseDoc:
    def __init__(self, data: Dict[str, Any]):
        self._data = data

    def __getattr__(self, item: str):
        if item in self._data:
            return self._data[item]
        raise AttributeError(item)

    def to_dict(self) -> Dict[str, Any]:
        return dict(self._data)


@login_manager.user_loader
def load_user(user_id: str):
    try:
        return User.find_by_id(int(user_id))
    except (TypeError, ValueError):
        return None


class User(UserMixin, BaseDoc):
    @property
    def is_active(self):
        return bool(self._data.get("is_active", True))

    def get_id(self):
        return str(self.id)

    @staticmethod
    def find_by_id(user_id: int) -> Optional["User"]:
        doc = _col("users").find_one({"id": user_id})
        return User(doc) if doc else None

    @staticmethod
    def find_by_email(email: str) -> Optional["User"]:
        doc = _col("users").find_one({"email": email})
        return User(doc) if doc else None

    @staticmethod
    def find_by_username(username: str) -> Optional["User"]:
        doc = _col("users").find_one({"username": username})
        return User(doc) if doc else None

    @staticmethod
    def create(username: str, email: str, password_hash: str) -> "User":
        doc = {
            "id": _next_id("users"),
            "username": username,
            "email": email,
            "password_hash": password_hash,
            "created_at": _now(),
            "is_active": True,
        }
        _col("users").insert_one(doc)
        return User(doc)


class Website(BaseDoc):
    @staticmethod
    def create(user_id: int, url: str, label: str, auto_scan: bool) -> "Website":
        doc = {
            "id": _next_id("websites"),
            "user_id": user_id,
            "url": url,
            "label": label,
            "date_added": _now(),
            "auto_scan": auto_scan,
        }
        _col("websites").insert_one(doc)
        return Website(doc)

    @staticmethod
    def find_by_id(site_id: int) -> Optional["Website"]:
        doc = _col("websites").find_one({"id": site_id})
        return Website(doc) if doc else None

    @staticmethod
    def find_by_user_and_id(user_id: int, site_id: int) -> Optional["Website"]:
        doc = _col("websites").find_one({"id": site_id, "user_id": user_id})
        return Website(doc) if doc else None

    @staticmethod
    def find_by_user_and_url(user_id: int, url: str) -> Optional["Website"]:
        doc = _col("websites").find_one({"user_id": user_id, "url": url})
        return Website(doc) if doc else None

    @staticmethod
    def for_user(user_id: int) -> List["Website"]:
        docs = _col("websites").find({"user_id": user_id}).sort("date_added", -1)
        return [Website(d) for d in docs]

    @staticmethod
    def all_auto_scan() -> List["Website"]:
        docs = _col("websites").find({"auto_scan": True})
        return [Website(d) for d in docs]

    def save(self):
        _col("websites").update_one(
            {"id": self.id},
            {"$set": {
                "url": self.url,
                "label": self.label,
                "auto_scan": self.auto_scan,
            }}
        )

    def delete(self):
        scan_ids = [s.id for s in Scan.for_website(self.id)]
        if scan_ids:
            _col("vulnerabilities").delete_many({"scan_id": {"$in": scan_ids}})
            _col("alerts").delete_many({"scan_id": {"$in": scan_ids}})
            _col("scans").delete_many({"id": {"$in": scan_ids}})
        _col("websites").delete_one({"id": self.id})

    def latest_scan(self):
        scans = Scan.for_website(self.id, limit=1)
        return scans[0] if scans else None


class Scan(BaseDoc):
    @staticmethod
    def create_running(website_id: int) -> "Scan":
        doc = {
            "id": _next_id("scans"),
            "website_id": website_id,
            "scan_date": _now(),
            "status": "running",
            "result_summary": "",
            "total_vulns": 0,
            "risk_score": 0.0,
            "duration_secs": 0.0,
        }
        _col("scans").insert_one(doc)
        return Scan(doc)

    @staticmethod
    def find_by_id(scan_id: int) -> Optional["Scan"]:
        doc = _col("scans").find_one({"id": scan_id})
        return Scan(doc) if doc else None

    @staticmethod
    def for_website(website_id: int, limit: Optional[int] = None) -> List["Scan"]:
        cursor = _col("scans").find({"website_id": website_id}).sort("scan_date", -1)
        if limit:
            cursor = cursor.limit(limit)
        return [Scan(d) for d in cursor]

    @staticmethod
    def for_websites(website_ids: List[int], limit: Optional[int] = None) -> List["Scan"]:
        if not website_ids:
            return []
        cursor = _col("scans").find({"website_id": {"$in": website_ids}}).sort("scan_date", -1)
        if limit:
            cursor = cursor.limit(limit)
        return [Scan(d) for d in cursor]

    @property
    def website(self):
        return Website.find_by_id(self.website_id)

    def update_result(self, result: Dict[str, Any]):
        self._data.update({
            "status": "done",
            "result_summary": result["summary"],
            "total_vulns": int(result["total_vulns"]),
            "risk_score": float(result["risk_score"]),
            "duration_secs": float(result["duration"]),
        })
        _col("scans").update_one(
            {"id": self.id},
            {"$set": {
                "status": self.status,
                "result_summary": self.result_summary,
                "total_vulns": self.total_vulns,
                "risk_score": self.risk_score,
                "duration_secs": self.duration_secs,
            }}
        )

    def mark_failed(self, message: str):
        self._data["status"] = "failed"
        self._data["result_summary"] = message
        _col("scans").update_one(
            {"id": self.id},
            {"$set": {"status": "failed", "result_summary": message}}
        )

    def vuln_counts(self):
        return Vulnerability.counts_for_scan(self.id)


class Vulnerability(BaseDoc):
    @staticmethod
    def create_many(scan_id: int, findings: List[Dict[str, Any]]):
        docs = []
        for finding in findings:
            docs.append({
                "id": _next_id("vulnerabilities"),
                "scan_id": scan_id,
                "vulnerability_type": finding["vulnerability_type"],
                "risk_level": finding["risk_level"],
                "description": finding["description"],
                "recommendation": finding.get("recommendation") or "",
                "evidence": finding.get("evidence") or "",
                "severity_score": float(finding.get("severity_score", 0.0)),
            })
        if docs:
            _col("vulnerabilities").insert_many(docs)

    @staticmethod
    def for_scan(scan_id: int) -> List["Vulnerability"]:
        docs = _col("vulnerabilities").find({"scan_id": scan_id}).sort("severity_score", -1)
        return [Vulnerability(d) for d in docs]

    @staticmethod
    def count_for_scans(scan_ids: List[int]) -> int:
        if not scan_ids:
            return 0
        return _col("vulnerabilities").count_documents({"scan_id": {"$in": scan_ids}})

    @staticmethod
    def count_by_risk_for_scans(scan_ids: List[int], risk_level: str) -> int:
        if not scan_ids:
            return 0
        return _col("vulnerabilities").count_documents({
            "scan_id": {"$in": scan_ids},
            "risk_level": risk_level,
        })

    @staticmethod
    def counts_for_scan(scan_id: int):
        counts = {"High": 0, "Medium": 0, "Low": 0}
        pipeline = [
            {"$match": {"scan_id": scan_id}},
            {"$group": {"_id": "$risk_level", "count": {"$sum": 1}}},
        ]
        for row in _col("vulnerabilities").aggregate(pipeline):
            level = row.get("_id")
            if level in counts:
                counts[level] = int(row.get("count", 0))
        return counts

    @staticmethod
    def counts_for_scans(scan_ids: List[int]):
        counts = {"High": 0, "Medium": 0, "Low": 0}
        if not scan_ids:
            return counts
        pipeline = [
            {"$match": {"scan_id": {"$in": scan_ids}}},
            {"$group": {"_id": "$risk_level", "count": {"$sum": 1}}},
        ]
        for row in _col("vulnerabilities").aggregate(pipeline):
            level = row.get("_id")
            if level in counts:
                counts[level] = int(row.get("count", 0))
        return counts


class Alert(BaseDoc):
    @staticmethod
    def create(user_id: int, scan_id: int, message: str, alert_type: str = "dashboard"):
        doc = {
            "id": _next_id("alerts"),
            "user_id": user_id,
            "scan_id": scan_id,
            "message": message,
            "is_read": False,
            "created_at": _now(),
            "alert_type": alert_type,
        }
        _col("alerts").insert_one(doc)
        return Alert(doc)

    @staticmethod
    def count_unread(user_id: int) -> int:
        return _col("alerts").count_documents({"user_id": user_id, "is_read": False})

    @staticmethod
    def recent_for_user(user_id: int, limit: int = 5) -> List["Alert"]:
        docs = _col("alerts").find({"user_id": user_id}).sort("created_at", -1).limit(limit)
        return [Alert(d) for d in docs]

    @staticmethod
    def mark_all_read(user_id: int):
        _col("alerts").update_many({"user_id": user_id, "is_read": False}, {"$set": {"is_read": True}})

    @staticmethod
    def mark_read(user_id: int, alert_id: int) -> bool:
        res = _col("alerts").update_one(
            {"user_id": user_id, "id": alert_id},
            {"$set": {"is_read": True}}
        )
        return res.matched_count > 0


def ensure_indexes():
    _col("users").create_index("id", unique=True)
    _col("users").create_index("username", unique=True)
    _col("users").create_index("email", unique=True)

    _col("websites").create_index("id", unique=True)
    _col("websites").create_index([("user_id", 1), ("url", 1)], unique=True)
    _col("websites").create_index("user_id")

    _col("scans").create_index("id", unique=True)
    _col("scans").create_index("website_id")
    _col("scans").create_index("scan_date")

    _col("vulnerabilities").create_index("id", unique=True)
    _col("vulnerabilities").create_index("scan_id")
    _col("vulnerabilities").create_index("risk_level")

    _col("alerts").create_index("id", unique=True)
    _col("alerts").create_index("user_id")
    _col("alerts").create_index("scan_id")
    _col("alerts").create_index("created_at")
