"""
One-time migration script: convert app owner_id fields from MongoDB ObjectId
to plain admin username strings, making them compatible with official KeyAuth SDKs.

Run once with:
    python migrate_ownerids.py
"""

from app import application
from models import db

with application.app_context():
    migrated = db.migrate_owner_ids_to_username()
    print(f"Done. {migrated} app(s) migrated.")
