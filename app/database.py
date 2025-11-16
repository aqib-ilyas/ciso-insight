"""Database operations for CISO Insight."""
import aiosqlite
import json
import logging
import time
from datetime import datetime
from typing import Optional, List, Dict, Any
from .config import settings

logger = logging.getLogger(__name__)


class Database:
    """SQLite database manager."""

    def __init__(self, db_path: str = None):
        self.db_path = db_path or settings.DATABASE_PATH

    async def init_db(self):
        """Initialize database schema."""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                CREATE TABLE IF NOT EXISTS assessments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    product_key TEXT UNIQUE NOT NULL,
                    product_name TEXT NOT NULL,
                    vendor_name TEXT,
                    category TEXT,
                    version TEXT,
                    trust_score INTEGER,
                    assessment_json TEXT NOT NULL,
                    sources_json TEXT NOT NULL,
                    timestamp INTEGER NOT NULL,
                    created_at TEXT NOT NULL
                )
            """)
            await db.execute("""
                CREATE INDEX IF NOT EXISTS idx_product_key
                ON assessments(product_key)
            """)
            await db.execute("""
                CREATE INDEX IF NOT EXISTS idx_timestamp
                ON assessments(timestamp DESC)
            """)
            await db.commit()
            logger.info("Database initialized successfully")

    def _normalize_product_key(self, product_name: str, version: str = "latest") -> str:
        """Normalize product name and version to cache key."""
        product_key = product_name.lower().strip().replace(" ", "_")
        version_key = version.lower().strip().replace(" ", "_") if version else "latest"
        return f"{product_key}_{version_key}"

    async def get_assessment(self, product_name: str, version: str = "latest") -> Optional[Dict[str, Any]]:
        """Get cached assessment if valid.

        Args:
            product_name: Product name (or composite product_key if version not provided)
            version: Product version (defaults to "latest")
        """
        product_key = self._normalize_product_key(product_name, version)
        current_time = int(time.time())
        ttl_seconds = settings.CACHE_TTL_HOURS * 3600

        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                """
                SELECT * FROM assessments
                WHERE product_key = ?
                AND (? - timestamp) < ?
                """,
                (product_key, current_time, ttl_seconds),
            ) as cursor:
                row = await cursor.fetchone()
                if row:
                    logger.info(f"Cache hit for {product_key}")
                    return {
                        "id": row["id"],
                        "product_key": row["product_key"],
                        "product_name": row["product_name"],
                        "vendor_name": row["vendor_name"],
                        "category": row["category"],
                        "version": row["version"],
                        "trust_score": row["trust_score"],
                        "assessment": json.loads(row["assessment_json"]),
                        "sources": json.loads(row["sources_json"]),
                        "timestamp": row["timestamp"],
                        "created_at": row["created_at"],
                    }
                else:
                    logger.info(f"Cache miss for {product_key}")
                    return None

    async def get_assessment_by_key(self, product_key: str) -> Optional[Dict[str, Any]]:
        """Get cached assessment by composite product key.

        Args:
            product_key: Composite product key (e.g., "docker_26.0.0")
        """
        current_time = int(time.time())
        ttl_seconds = settings.CACHE_TTL_HOURS * 3600

        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                """
                SELECT * FROM assessments
                WHERE product_key = ?
                AND (? - timestamp) < ?
                """,
                (product_key, current_time, ttl_seconds),
            ) as cursor:
                row = await cursor.fetchone()
                if row:
                    logger.info(f"Cache hit for {product_key}")
                    return {
                        "id": row["id"],
                        "product_key": row["product_key"],
                        "product_name": row["product_name"],
                        "vendor_name": row["vendor_name"],
                        "category": row["category"],
                        "version": row["version"],
                        "trust_score": row["trust_score"],
                        "assessment": json.loads(row["assessment_json"]),
                        "sources": json.loads(row["sources_json"]),
                        "timestamp": row["timestamp"],
                        "created_at": row["created_at"],
                    }
                else:
                    logger.info(f"Cache miss for {product_key}")
                    return None

    async def save_assessment(
        self,
        product_name: str,
        vendor_name: str,
        category: str,
        version: str,
        trust_score: int,
        assessment: Dict[str, Any],
        sources: List[Dict[str, Any]],
    ):
        """Save assessment to cache."""
        product_key = self._normalize_product_key(product_name, version)
        timestamp = int(time.time())
        created_at = datetime.utcnow().isoformat()

        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                INSERT OR REPLACE INTO assessments
                (product_key, product_name, vendor_name, category, version, trust_score,
                 assessment_json, sources_json, timestamp, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    product_key,
                    product_name,
                    vendor_name,
                    category,
                    version,
                    trust_score,
                    json.dumps(assessment),
                    json.dumps(sources),
                    timestamp,
                    created_at,
                ),
            )
            await db.commit()
            logger.info(f"Assessment saved for {product_key}")

    async def get_recent_assessments(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent assessments."""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                """
                SELECT product_key, product_name, vendor_name, category, version,
                       trust_score, created_at
                FROM assessments
                ORDER BY timestamp DESC
                LIMIT ?
                """,
                (limit,),
            ) as cursor:
                rows = await cursor.fetchall()
                return [
                    {
                        "product_key": row["product_key"],
                        "product_name": row["product_name"],
                        "vendor_name": row["vendor_name"],
                        "category": row["category"],
                        "version": row["version"],
                        "trust_score": row["trust_score"],
                        "created_at": row["created_at"],
                    }
                    for row in rows
                ]

    async def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row

            # Total assessments
            async with db.execute("SELECT COUNT(*) as count FROM assessments") as cursor:
                total = (await cursor.fetchone())["count"]

            # Valid (non-expired) assessments
            current_time = int(time.time())
            ttl_seconds = settings.CACHE_TTL_HOURS * 3600
            async with db.execute(
                "SELECT COUNT(*) as count FROM assessments WHERE (? - timestamp) < ?",
                (current_time, ttl_seconds),
            ) as cursor:
                valid = (await cursor.fetchone())["count"]

            return {
                "total_assessments": total,
                "valid_assessments": valid,
                "expired_assessments": total - valid,
                "ttl_hours": settings.CACHE_TTL_HOURS,
            }

    async def clear_cache(self):
        """Clear all cached assessments."""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("DELETE FROM assessments")
            await db.commit()
            logger.info("Cache cleared")


# Global database instance
db = Database()
