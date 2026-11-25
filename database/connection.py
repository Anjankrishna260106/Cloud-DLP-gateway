"""
Database Connection Manager for MongoDB Atlas with zero-dependency fallback.
Connects to live MongoDB Atlas if MONGODB_URI is provided.
Falls back to high-fidelity Async Memory Store for offline testing.
"""

import os
import json
import asyncio
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone


class MockAsyncCollection:
    """In-memory async collection replicating Motor/PyMongo API."""

    def __init__(self, name: str, parent_db: "MockAsyncDatabase"):
        self.name = name
        self.parent_db = parent_db
        self.data: List[Dict[str, Any]] = []

    async def insert_one(self, doc: Dict[str, Any]):
        item = dict(doc)
        if "_id" not in item:
            item["_id"] = item.get("id") or str(len(self.data) + 1)
        self.data.append(item)
        self.parent_db.persist()
        return type("InsertResult", (), {"inserted_id": item["_id"]})()

    async def find_one(self, query: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        for item in self.data:
            match = True
            for k, v in query.items():
                if k == "_id" and str(item.get("_id")) == str(v):
                    continue
                if item.get(k) != v:
                    match = False
                    break
            if match:
                return dict(item)
        return None

    def find(self, query: Optional[Dict[str, Any]] = None):
        return MockAsyncCursor(self.data, query or {})

    async def update_one(self, query: Dict[str, Any], update: Dict[str, Any]):
        target = await self.find_one(query)
        if target:
            if "$set" in update:
                for k, v in update["$set"].items():
                    target[k] = v
            self.parent_db.persist()
            return type("UpdateResult", (), {"matched_count": 1, "modified_count": 1})()
        return type("UpdateResult", (), {"matched_count": 0, "modified_count": 0})()

    async def count_documents(self, query: Optional[Dict[str, Any]] = None) -> int:
        if not query:
            return len(self.data)
        count = 0
        for item in self.data:
            match = all(item.get(k) == v for k, v in query.items())
            if match:
                count += 1
        return count

    async def delete_many(self, query: Dict[str, Any]):
        self.data = [item for item in self.data if not all(item.get(k) == v for k, v in query.items())]
        self.parent_db.persist()


class MockAsyncCursor:
    """Async cursor supporting sorting, skipping, and to_list()."""

    def __init__(self, items: List[Dict[str, Any]], query: Dict[str, Any]):
        self.items = [dict(item) for item in items]
        if query:
            filtered = []
            for item in self.items:
                match = True
                for k, v in query.items():
                    if k == "_id" and str(item.get("_id")) == str(v):
                        continue
                    if item.get(k) != v:
                        match = False
                        break
                if match:
                    filtered.append(item)
            self.items = filtered
        self._sort_key = None
        self._reverse = False
        self._skip_count = 0
        self._limit_count = None

    def sort(self, key_or_list, direction=1):
        if isinstance(key_or_list, list):
            k, d = key_or_list[0]
            self._sort_key = k
            self._reverse = (d == -1)
        else:
            self._sort_key = key_or_list
            self._reverse = (direction == -1)
        return self

    def skip(self, n: int):
        self._skip_count = n
        return self

    def limit(self, n: int):
        self._limit_count = n
        return self

    async def to_list(self, length: Optional[int] = None) -> List[Dict[str, Any]]:
        results = list(self.items)
        if self._sort_key:
            results.sort(
                key=lambda x: str(x.get(self._sort_key, "")),
                reverse=self._reverse
            )
        if self._skip_count:
            results = results[self._skip_count:]
        lim = length if length is not None else self._limit_count
        if lim is not None:
            results = results[:lim]
        return results


class MockAsyncDatabase:
    """Simulates MongoDB database with lightweight JSON persistence."""

    def __init__(self, storage_path: str = "data/mock_db.json"):
        self.storage_path = storage_path
        self.collections: Dict[str, MockAsyncCollection] = {}
        self.load()

    def get_collection(self, name: str) -> MockAsyncCollection:
        if name not in self.collections:
            self.collections[name] = MockAsyncCollection(name, self)
        return self.collections[name]

    def __getitem__(self, name: str) -> MockAsyncCollection:
        return self.get_collection(name)

    def persist(self):
        try:
            os.makedirs(os.path.dirname(self.storage_path), exist_ok=True)
            serializable = {}
            for col_name, col in self.collections.items():
                items = []
                for item in col.data:
                    clean = {}
                    for k, v in item.items():
                        if isinstance(v, datetime):
                            clean[k] = v.isoformat()
                        else:
                            clean[k] = v
                    items.append(clean)
                serializable[col_name] = items
            with open(self.storage_path, "w", encoding="utf-8") as f:
                json.dump(serializable, f, indent=2)
        except Exception:
            pass

    def load(self):
        if os.path.exists(self.storage_path):
            try:
                with open(self.storage_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                for col_name, items in data.items():
                    col = self.get_collection(col_name)
                    col.data = items
            except Exception:
                pass


class DatabaseManager:
    """Database client lifecycle manager."""

    client = None
    db = None
    is_live_atlas: bool = False

    @classmethod
    async def connect(cls, uri: Optional[str] = None, db_name: str = "dlp_gateway"):
        mongodb_uri = uri or os.getenv("MONGODB_URI", "").strip()

        if mongodb_uri and (mongodb_uri.startswith("mongodb://") or mongodb_uri.startswith("mongodb+srv://")):
            try:
                from motor.motor_asyncio import AsyncIOMotorClient
                client = AsyncIOMotorClient(mongodb_uri, serverSelectionTimeoutMS=3000)
                # Quick ping test with short timeout
                await client.admin.command('ping')
                cls.client = client
                cls.db = client[db_name]
                cls.is_live_atlas = True
                print(f"[DB] Connected successfully to MongoDB Atlas (database: {db_name})")
                return cls.db
            except Exception as e:
                print(f"[DB Warning] Could not connect to MongoDB Atlas ({e}). Falling back to local data store.")

        # Fallback to MockAsyncDatabase
        cls.db = MockAsyncDatabase()
        cls.is_live_atlas = False
        print("[DB] Initialized persistent local database store.")
        return cls.db

    @classmethod
    def get_db(cls):
        if cls.db is None:
            # Synchronous initial fallback
            cls.db = MockAsyncDatabase()
        return cls.db

    @classmethod
    def get_users_col(cls):
        return cls.get_db()["users"]

    @classmethod
    def get_scan_events_col(cls):
        return cls.get_db()["scan_events"]

    @classmethod
    def get_policies_col(cls):
        return cls.get_db()["policies"]

    @classmethod
    def get_audit_logs_col(cls):
        return cls.get_db()["audit_logs"]
