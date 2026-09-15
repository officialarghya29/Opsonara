"""Persistence stores for audit records and the human review queue.

``make_stores`` selects the backend from settings:

* ``memory`` (default) — in-memory stores, zero setup, data lives for the
  process lifetime;
* ``sqlite`` — persistent stores backed by a single database file
  (``OPSONARA_DB_PATH``), surviving restarts with tamper evidence intact.
"""

from opsonara.stores.audit_store import AuditStore
from opsonara.stores.review_store import ReviewStore
from opsonara.stores.sqlite_store import SqliteAuditStore, SqliteReviewStore, make_stores

__all__ = [
    "AuditStore",
    "ReviewStore",
    "SqliteAuditStore",
    "SqliteReviewStore",
    "make_stores",
]
