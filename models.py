from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import secrets
import json
import os
import pymongo
from bson.objectid import ObjectId


class Database:
    def __init__(self):
        self.client = None
        self.db = None
        self.mode = 'mongo'

    def init_app(self, app):
        mongo_uri = app.config.get('MONGO_URI')
        if not mongo_uri:
            raise RuntimeError('MONGO_URI is required for MongoDB')
        self.client = pymongo.MongoClient(mongo_uri)
        db_name = app.config.get('DATABASE_NAME', 'SKYLINE')
        self.db = self.client[db_name]
        self.db.admins.create_index('username', unique=True)
        self.db.apps.create_index('secret_key', unique=True)
        # License keys must be globally unique (KeyAuth behaviour)
        self.db.app_users.create_index('key', unique=True)
        # Bug fix: usernames must be unique *per app*, not globally.
        # Drop any old global index, then create a compound (app_id, username)
        # unique index with a partial filter so that null / absent usernames
        # (un-registered license keys) are skipped entirely.
        for old_idx in ('username_1', 'app_username_unique'):
            try:
                self.db.app_users.drop_index(old_idx)
            except Exception:
                pass
        self.db.app_users.create_index(
            [('app_id', 1), ('username', 1)],
            unique=True,
            partialFilterExpression={'username': {'$type': 'string'}},
            name='app_username_unique',
        )
        self.db.sessions.create_index('session_id', unique=True)
        self.db.sessions.create_index('created_at', expireAfterSeconds=86400)

    def _to_id(self, val):
        if isinstance(val, ObjectId):
            return val
        if val is None:
            return None
        try:
            return ObjectId(str(val))
        except Exception:
            return None

    def _now(self):
        return datetime.utcnow()

    # ── Admin / Reseller account management ──────────────────────────

    def get_or_create_owner_key(self, admin_id):
        """Return the owner_key for an admin, generating one if it doesn't exist yet."""
        oid = self._to_id(admin_id)
        if not oid:
            return secrets.token_hex(6)
        admin = self.db.admins.find_one({'_id': oid})
        if not admin:
            return secrets.token_hex(6)
        if admin.get('owner_key'):
            return admin['owner_key']
        new_key = secrets.token_hex(6)
        self.db.admins.update_one({'_id': oid}, {'$set': {'owner_key': new_key}})
        return new_key

    def create_admin(self, username, password, email, role, created_by=None):
        if self.mode == 'mongo':
            if self.db.admins.find_one({'username': username}):
                return None
            doc = {
                'username': username,
                'password': generate_password_hash(password),
                'email': email,
                'role': role,
                'owner_key': secrets.token_hex(6),
                'credits': 0,
                'created_by': self._to_id(created_by) if created_by else None,
                'created_at': self._now(),
                'is_active': True,
                'last_login_ip': None,
                'last_login_at': None,
                'profile_pic': None,
                'assigned_packages': []
            }
            res = self.db.admins.insert_one(doc)
            return str(res.inserted_id)

    def verify_admin(self, username, password):
        if self.mode == 'mongo':
            admin = self.db.admins.find_one({'username': username, 'is_active': True})
            if admin and check_password_hash(admin.get('password', ''), password):
                return admin
        return None

    def verify_app_user(self, key, password):
        if self.mode == 'mongo':
            user = self.db.app_users.find_one({'key': key})
            if user and check_password_hash(user.get('password', ''), password):
                return user
        return None

    def get_admin_by_id(self, admin_id):
        if self.mode == 'mongo':
            oid = self._to_id(admin_id)
            admin = self.db.admins.find_one({'_id': oid})
            return admin if admin else None

    def get_admins(self, role=None):
        if self.mode == 'mongo':
            q = {}
            if role:
                q['role'] = role
            return list(self.db.admins.find(q).sort('created_at', -1))

    def update_admin(self, admin_id, data):
        if self.mode == 'mongo':
            oid = self._to_id(admin_id)
            update = {}
            if 'username' in data and data['username']:
                existing = self.db.admins.find_one({'username': data['username']})
                if existing and existing['_id'] != oid:
                    return False, 'Username already exists'
                update['username'] = data['username']
            if 'email' in data:
                update['email'] = data['email']
            if 'password' in data and data['password']:
                update['password'] = generate_password_hash(data['password'])
            if 'is_active' in data:
                update['is_active'] = data['is_active']
            if 'profile_pic' in data:
                update['profile_pic'] = data['profile_pic']
            res = self.db.admins.update_one({'_id': oid}, {'$set': update})
            return (res.modified_count > 0), None

    def update_login_ip(self, admin_id, ip_address):
        if self.mode == 'mongo':
            oid = self._to_id(admin_id)
            self.db.admins.update_one(
                {'_id': oid},
                {'$set': {'last_login_ip': ip_address, 'last_login_at': self._now()}}
            )

    def delete_admin(self, admin_id):
        if self.mode == 'mongo':
            oid = self._to_id(admin_id)
            self.db.admins.delete_one({'_id': oid})

    def count_admins(self, role=None):
        if self.mode == 'mongo':
            q = {}
            if role:
                q['role'] = role
            return self.db.admins.count_documents(q)

    # ── Application management ───────────────────────────────────────

    def create_app(self, name, owner_id):
        if self.mode == 'mongo':
            # Use the admin's owner_key (a 12-char hex string) as the ownerid.
            # This guarantees the ownerid is always >= 10 chars, compatible with all
            # official KeyAuth SDKs which enforce ownerid.Length >= 10.
            owner_key = self.get_or_create_owner_key(owner_id)
            doc = {
                'name': name,
                'secret_key': secrets.token_hex(32),
                'owner_id': owner_key,
                # Keep a reference to the admin ObjectId for internal dashboard lookups
                'owner_mongo_id': self._to_id(owner_id),
                'version': '1.0',
                'variables': {},
                'created_at': self._now(),
                'is_active': True,
                'is_paused': False,
                'hwid_check': True,
                'vpn_block': False,
                'hash_check': False,
                'server_hash': None,
                'app_disabled_msg': "Application is currently disabled.",
                'download_link': "",
                'force_encryption': False,
                'session_expiry': 3600,
                'minHwid': 0,
                'discord_webhook_url': '',   # per-app Discord event webhook
                'paused_msg': 'Application is currently paused, please wait for the developer to say otherwise.'
            }
            res = self.db.apps.insert_one(doc)
            return str(res.inserted_id)

    def _get_owner_username(self, owner_id):
        """Resolve an admin _id to their username string for KeyAuth ownerid compatibility."""
        try:
            oid = self._to_id(owner_id)
            admin = self.db.admins.find_one({'_id': oid})
            if admin:
                return admin.get('username', str(owner_id))
        except Exception:
            pass
        return str(owner_id)

    def update_app_settings(self, app_id, data):
        if self.mode == 'mongo':
            oid = self._to_id(app_id)
            update_fields = {}
            allowed = [
                'name', 'version', 'is_active', 'is_paused',
                'hwid_check', 'vpn_block', 'hash_check',
                'app_disabled_msg', 'paused_msg', 'download_link',
                'force_encryption', 'session_expiry', 'server_hash',
                'minHwid', 'discord_webhook_url',
            ]
            for field in allowed:
                if field in data:
                    update_fields[field] = data[field]
            if update_fields:
                self.db.apps.update_one({'_id': oid}, {'$set': update_fields})
                return True
            return False

    def update_app_version(self, app_id, version):
        if self.mode == 'mongo':
            oid = self._to_id(app_id)
            self.db.apps.update_one({'_id': oid}, {'$set': {'version': version}})
            return True

    def get_app_by_details(self, name, secret, owner_id):
        """
        FIX: Look up app by name + secret_key + owner_id (plain string).
        Official KeyAuth SDKs send ownerid as a plain username string,
        so we compare against the stored owner_id string field directly.
        We also fall back to owner_mongo_id for apps created before this fix.
        """
        if self.mode == 'mongo':
            # Primary lookup: owner_id stored as plain username string (new way)
            app = self.db.apps.find_one({
                'name': name,
                'secret_key': secret,
                'owner_id': str(owner_id),
                'is_active': True
            })
            if app:
                return app

            # Fallback: owner_mongo_id stored as ObjectId (old apps before fix)
            oid = self._to_id(owner_id)
            if oid:
                app = self.db.apps.find_one({
                    'name': name,
                    'secret_key': secret,
                    'owner_mongo_id': oid,
                    'is_active': True
                })
                if app:
                    return app

            # Last resort fallback: owner_id stored as ObjectId string (original broken behaviour)
            app = self.db.apps.find_one({
                'name': name,
                'secret_key': secret,
                'owner_id': oid,
                'is_active': True
            })
            return app

    def get_app_stats(self, app_id):
        if self.mode == 'mongo':
            oid = self._to_id(app_id)
            num_users = self.db.app_users.count_documents({'app_id': oid})
            num_keys = self.db.app_users.count_documents({'app_id': oid})
            recent = self._now() - timedelta(minutes=10)
            num_online = self.db.app_users.count_documents({
                'app_id': oid,
                'last_login': {'$gte': recent}
            })
            return {
                'numUsers': str(num_users),
                'numOnlineUsers': str(num_online),
                'numKeys': str(num_keys)
            }

    def get_app_var(self, app_id, varid):
        if self.mode == 'mongo':
            app = self.get_app_by_id(app_id)
            if app and 'variables' in app:
                return app['variables'].get(varid)
        return None

    def set_app_var(self, app_id, varid, vardata):
        if self.mode == 'mongo':
            oid = self._to_id(app_id)
            self.db.apps.update_one(
                {'_id': oid},
                {'$set': {f'variables.{varid}': vardata}}
            )
            return True

    def get_app_vars(self, app_id):
        if self.mode == 'mongo':
            app = self.get_app_by_id(app_id)
            return app.get('variables', {}) if app else {}

    def delete_app_var(self, app_id, varid):
        if self.mode == 'mongo':
            oid = self._to_id(app_id)
            self.db.apps.update_one(
                {'_id': oid},
                {'$unset': {f'variables.{varid}': ""}}
            )
            return True

    # ── Webhooks ─────────────────────────────────────────────────────

    def create_webhook(self, app_id, name, url, authed=True):
        if self.mode == 'mongo':
            webid = secrets.token_hex(8)
            doc = {
                'app_id': self._to_id(app_id),
                'name': name,
                'url': url,
                'authed': bool(authed),
                'webid': webid,
                'created_at': self._now()
            }
            res = self.db.webhooks.insert_one(doc)
            return str(res.inserted_id)

    def get_webhooks(self, app_id):
        if self.mode == 'mongo':
            return list(self.db.webhooks.find({'app_id': self._to_id(app_id)}))

    def get_webhook_by_webid(self, app_id, webid):
        if self.mode == 'mongo':
            return self.db.webhooks.find_one({'app_id': self._to_id(app_id), 'webid': webid})

    def delete_webhook(self, webhook_id):
        if self.mode == 'mongo':
            self.db.webhooks.delete_one({'_id': self._to_id(webhook_id)})
            return True

    # ── Files ────────────────────────────────────────────────────────

    def create_file(self, app_id, name, url, file_id=None, authed=True):
        if self.mode == 'mongo':
            doc = {
                'app_id': self._to_id(app_id),
                'name': name,
                'url': url,
                'file_id': file_id or secrets.token_hex(4),
                'authed': bool(authed),
                'created_at': self._now()
            }
            res = self.db.files.insert_one(doc)
            return str(res.inserted_id)

    def get_files(self, app_id):
        if self.mode == 'mongo':
            return list(self.db.files.find({'app_id': self._to_id(app_id)}))

    def get_file_by_fileid(self, app_id, fileid):
        if self.mode == 'mongo':
            return self.db.files.find_one({'app_id': self._to_id(app_id), 'file_id': fileid})

    def delete_file(self, file_id):
        if self.mode == 'mongo':
            self.db.files.delete_one({'_id': self._to_id(file_id)})
            return True

    def get_apps(self, owner_id=None):
        if self.mode == 'mongo':
            if owner_id:
                oid = self._to_id(owner_id)
                owner_key = self.get_or_create_owner_key(owner_id)
                owner_username = self._get_owner_username(owner_id)
                or_clauses = [{'owner_id': owner_key}, {'owner_id': owner_username}]
                if oid:
                    or_clauses += [{'owner_id': oid}, {'owner_mongo_id': oid}]
                apps = list(self.db.apps.find({'$or': or_clauses}).sort('created_at', -1))
                return apps
            return list(self.db.apps.find({}).sort('created_at', -1))

    def get_app_by_id(self, app_id):
        if self.mode == 'mongo':
            oid = self._to_id(app_id)
            app = self.db.apps.find_one({'_id': oid})
            return app if app else None

    def delete_app(self, app_id):
        if self.mode == 'mongo':
            oid = self._to_id(app_id)
            self.db.app_users.delete_many({'app_id': oid})
            self.db.packages.delete_many({'app_id': oid})
            self.db.apps.delete_one({'_id': oid})

    def toggle_app(self, app_id):
        if self.mode == 'mongo':
            oid = self._to_id(app_id)
            app = self.db.apps.find_one({'_id': oid})
            if app:
                self.db.apps.update_one(
                    {'_id': oid},
                    {'$set': {'is_active': not app.get('is_active', True)}}
                )

    def count_apps(self, owner_id=None):
        if self.mode == 'mongo':
            if owner_id:
                oid = self._to_id(owner_id)
                owner_key = self.get_or_create_owner_key(owner_id)
                owner_username = self._get_owner_username(owner_id)
                or_clauses = [{'owner_id': owner_key}, {'owner_id': owner_username}]
                if oid:
                    or_clauses += [{'owner_id': oid}, {'owner_mongo_id': oid}]
                return self.db.apps.count_documents({'$or': or_clauses})
            return self.db.apps.count_documents({})

    # ── Session management ─────────────────────────────────────────

    def create_session(self, app_id, sent_key):
        if self.mode == 'mongo':
            session_id = secrets.token_hex(16)
            doc = {
                'session_id': session_id,
                'app_id': self._to_id(app_id),
                'sent_key': sent_key,
                'validated': False,
                'credential': None,
                'created_at': self._now()
            }
            self.db.sessions.insert_one(doc)
            return session_id

    def set_session_validated(self, session_id, credential):
        if self.mode == 'mongo':
            self.db.sessions.update_one(
                {'session_id': session_id},
                {'$set': {'validated': True, 'credential': credential}}
            )

    def get_session(self, session_id):
        if self.mode == 'mongo':
            return self.db.sessions.find_one({'session_id': session_id})

    def delete_session(self, session_id):
        if self.mode == 'mongo':
            self.db.sessions.delete_one({'session_id': session_id})

    def get_online_users(self, app_id):
        if self.mode == 'mongo':
            oid = self._to_id(app_id)
            recent = self._now() - timedelta(minutes=10)
            users = self.db.app_users.find(
                {'app_id': oid, 'last_login': {'$gte': recent}},
                {'username': 1}
            )
            return [u.get('username', '') for u in users if u.get('username')]
        return []

    # ── Credit system ───────────────────────────────────────────────

    def get_credits(self, admin_id):
        admin = self.get_admin_by_id(admin_id)
        if not admin:
            return 0
        if admin['role'] == 'superadmin':
            return float('inf')
        return admin.get('credits', 0)

    def add_credits(self, admin_id, amount):
        if self.mode == 'mongo':
            oid = self._to_id(admin_id)
            self.db.admins.update_one({'_id': oid}, {'$inc': {'credits': int(amount)}})

    def deduct_credits(self, admin_id, amount=1):
        if self.mode == 'mongo':
            oid = self._to_id(admin_id)
            admin = self.db.admins.find_one({'_id': oid})
            if not admin:
                return False
            if admin.get('role') == 'superadmin':
                return True
            current = int(admin.get('credits', 0))
            if current < int(amount):
                return False
            self.db.admins.update_one({'_id': oid}, {'$inc': {'credits': -int(amount)}})
            return True

    def transfer_credits(self, from_id, to_id, amount):
        if self.mode == 'mongo':
            amount = int(amount)
            if amount <= 0:
                return False, 'Amount must be positive'
            from_oid = self._to_id(from_id)
            to_oid = self._to_id(to_id)
            from_admin = self.db.admins.find_one({'_id': from_oid})
            if not from_admin:
                return False, 'Source not found'
            to_admin = self.db.admins.find_one({'_id': to_oid})
            if not to_admin:
                return False, 'Destination not found'
            if from_admin.get('role') != 'superadmin':
                if int(from_admin.get('credits', 0)) < amount:
                    return False, 'Not enough credits'
            self.db.admins.update_one({'_id': from_oid}, {'$inc': {'credits': -amount}})
            self.db.admins.update_one({'_id': to_oid}, {'$inc': {'credits': amount}})
            return True, None

    # ── App Users (end-users) management ─────────────────────────────

    def create_user_direct(self, app_id, package_id, created_by, count=1, custom_days=None, hwid_lock=True,
                           username=None, password=None, force_user_account=False, custom_key=None):
        """
        Create license keys or direct user accounts.

        Parameters
        ----------
        username / password      : explicit user-account credentials (from Users page).
        force_user_account=True  : treat username as a user account, auto-generate password if missing.
        custom_key               : use this string as the license key (from Licenses page).
                                   Always creates a pure license entry — never a user account.
        """
        if self.mode == 'mongo':
            admin = self.db.admins.find_one({'_id': self._to_id(created_by)})
            if not admin:
                return None, 'Invalid admin'
            count = int(count)
            # User accounts are always singular
            if force_user_account and username:
                count = 1
            if admin.get('role') != 'superadmin':
                current_credits = int(admin.get('credits', 0))
                if current_credits < count:
                    return None, f'Not enough credits. You have {current_credits}, need {count}'
            pkg = self.db.packages.find_one({'_id': self._to_id(package_id)})
            if not pkg:
                return None, 'Invalid package'
            subscription_name = pkg.get('name', 'default')
            if custom_days:
                expiry_base = self._now() + timedelta(days=int(custom_days))
            else:
                expiry_base = self._now() + timedelta(days=int(pkg.get('duration_days', 30)))
            created_users = []
            for i in range(count):
                if force_user_account and username and i == 0:
                    # ── Direct user account ──────────────────────────────────────
                    # Admin explicitly creates a username + password account.
                    key = username.strip()
                    raw_password = password.strip() if password else secrets.token_urlsafe(10)
                    is_license = False
                    if self.db.app_users.find_one({'app_id': self._to_id(app_id), 'username': key}):
                        return None, f'Username "{key}" already exists in this application'
                    if self.db.app_users.find_one({'key': key}):
                        return None, f'Key "{key}" already exists'
                    doc = {
                        'app_id': self._to_id(app_id),
                        'key': key,
                        'username': key,
                        'password': generate_password_hash(raw_password),
                        'hwid': '',
                        'hwid_lock': bool(hwid_lock),
                        'expiry': expiry_base,
                        'package_id': self._to_id(package_id),
                        'subscription_name': subscription_name,
                        'created_by': self._to_id(created_by),
                        'created_at': self._now(),
                        'is_active': True,
                        'is_license': False,
                    }
                else:
                    # ── Pure license key ─────────────────────────────────────────
                    # Either auto-generate a key or use the supplied custom_key.
                    # A license key is NEVER a user account — no password is needed
                    # until the user optionally registers via type=register.
                    if custom_key and i == 0:
                        key = custom_key.strip()
                    else:
                        key = f"SKYLINE-{secrets.token_hex(4).upper()}-{secrets.token_hex(4).upper()}-{secrets.token_hex(4).upper()}"
                    is_license = True
                    if self.db.app_users.find_one({'key': key}):
                        if custom_key:
                            return None, f'Key "{key}" already exists'
                        continue  # collision on random key — skip (negligible probability)
                    doc = {
                        'app_id': self._to_id(app_id),
                        'key': key,
                        # No username/password stored — user registers via SDK type=register
                        'hwid': '',
                        'hwid_lock': bool(hwid_lock),
                        'expiry': expiry_base,
                        'package_id': self._to_id(package_id),
                        'subscription_name': subscription_name,
                        'created_by': self._to_id(created_by),
                        'created_at': self._now(),
                        'is_active': True,
                        'is_license': True,
                    }
                    raw_password = None  # License keys have no password to display
                self.db.app_users.insert_one(doc)
                created_users.append({'key': key, 'password': raw_password, 'is_license': is_license})
            if admin.get('role') != 'superadmin':
                self.db.admins.update_one({'_id': admin['_id']}, {'$inc': {'credits': -count}})
            return created_users, None

    def get_app_users(self, app_id=None, created_by=None):
        if self.mode == 'mongo':
            q = {}
            if app_id:
                q['app_id'] = self._to_id(app_id)
            if created_by:
                q['created_by'] = self._to_id(created_by)
            return list(self.db.app_users.find(q).sort('created_at', -1))

    def delete_app_user(self, user_id):
        if self.mode == 'mongo':
            self.db.app_users.delete_one({'_id': self._to_id(user_id)})

    def count_app_users(self, app_id=None, created_by=None):
        if self.mode == 'mongo':
            q = {}
            if app_id:
                q['app_id'] = self._to_id(app_id)
            if created_by:
                q['created_by'] = self._to_id(created_by)
            return self.db.app_users.count_documents(q)

    def toggle_app_user(self, user_id):
        if self.mode == 'mongo':
            user = self.db.app_users.find_one({'_id': self._to_id(user_id)})
            if user:
                self.db.app_users.update_one(
                    {'_id': user['_id']},
                    {'$set': {'is_active': not user.get('is_active', True)}}
                )

    # ── Package management ───────────────────────────────────────────

    def create_package(self, name, duration_days, app_id, created_by):
        if self.mode == 'mongo':
            doc = {
                'name': name,
                'duration_days': int(duration_days),
                'app_id': self._to_id(app_id),
                'created_by': self._to_id(created_by),
                'created_at': self._now(),
            }
            res = self.db.packages.insert_one(doc)
            return str(res.inserted_id)

    def get_packages(self, app_id=None):
        if self.mode == 'mongo':
            q = {}
            if app_id:
                q['app_id'] = self._to_id(app_id)
            return list(self.db.packages.find(q).sort('created_at', -1))

    def get_package_by_id(self, package_id):
        if self.mode == 'mongo':
            return self.db.packages.find_one({'_id': self._to_id(package_id)})

    def delete_package(self, package_id):
        if self.mode == 'mongo':
            self.db.packages.delete_one({'_id': self._to_id(package_id)})

    def count_packages(self, app_id=None):
        if self.mode == 'mongo':
            q = {}
            if app_id:
                q['app_id'] = self._to_id(app_id)
            return self.db.packages.count_documents(q)

    # ── API auth (for external app integration) ──────────────────────

    def _apply_hwid(self, user, hwid, app):
        """Apply HWID check/lock logic. Returns (user, error).

        Priority order (most permissive wins):
          1. App-level hwid_check=False  → skip HWID for ALL users of this app
          2. User-level hwid_lock=False  → skip HWID for this specific user
          3. No hwid supplied by client  → skip (can't lock what we don't have)
          4. HWID is set and matches     → OK
          5. HWID is set but mismatches  → Hardware ID mismatch error
          6. HWID not yet stored         → lock it now (first login on this machine)
        """
        if not app.get('hwid_check', True):
            return user, None
        if not user.get('hwid_lock', True):
            return user, None
        if not hwid:
            return user, None
        stored_hwid = user.get('hwid') or ''
        if stored_hwid and stored_hwid != hwid:
            return None, 'Hardware ID mismatch'
        if not stored_hwid:
            self.db.app_users.update_one({'_id': user['_id']}, {'$set': {'hwid': hwid}})
            user['hwid'] = hwid
        return user, None

    def api_login(self, app_secret, username, password, hwid=''):
        """Authenticate a registered user account (username + password)."""
        if self.mode == 'mongo':
            app = self.db.apps.find_one({'secret_key': app_secret})
            if not app:
                return None, 'Invalid application'
            user = self.db.app_users.find_one({
                'app_id': app['_id'],
                'username': username,
                'is_active': True
            })
            if not user:
                user = self.db.app_users.find_one({
                    'app_id': app['_id'],
                    'key': username,
                    'is_active': True
                })
            if not user:
                return None, 'Invalid username or password'
            if not check_password_hash(user.get('password', ''), password):
                return None, 'Invalid username or password'
            if user.get('expiry') and user['expiry'] < self._now():
                return None, 'Subscription expired'
            user, err = self._apply_hwid(user, hwid, app)
            if err:
                return None, err
            self.db.app_users.update_one({'_id': user['_id']}, {'$set': {'last_login': self._now()}})
            return user, None

    def api_license(self, app_secret, license_key, hwid=''):
        """Authenticate directly with a license key (no username/password needed)."""
        if self.mode == 'mongo':
            app = self.db.apps.find_one({'secret_key': app_secret})
            if not app:
                return None, 'Invalid application'
            user = self.db.app_users.find_one({
                'app_id': app['_id'],
                'key': license_key,
                'is_active': True
            })
            if not user:
                return None, 'Invalid license key'
            if user.get('expiry') and user['expiry'] < self._now():
                return None, 'License expired'
            user, err = self._apply_hwid(user, hwid, app)
            if err:
                return None, err
            self.db.app_users.update_one({'_id': user['_id']}, {'$set': {'last_login': self._now()}})
            return user, None

    def api_register(self, app_secret, username, password, license_key, hwid='', email=''):
        """Convert an unused license key into a registered user account."""
        if self.mode == 'mongo':
            app = self.db.apps.find_one({'secret_key': app_secret})
            if not app:
                return None, 'Invalid application'
            if not username or len(username) < 3:
                return None, 'Username too short'
            if len(username) > 70:
                return None, 'Username must be shorter than 70 characters'
            # Bug fix: per-app uniqueness check (not global)
            if self.db.app_users.find_one({'app_id': app['_id'], 'username': username}):
                return None, 'Username already taken'
            key_data = self.db.app_users.find_one({
                'app_id': app['_id'],
                'key': license_key,
                'is_active': True
            })
            if not key_data:
                return None, 'Invalid license key'
            # Bug fix: block direct-user accounts (is_license=False) from being used
            # as registration tokens.  Old records without the flag default to True
            # so existing data stays compatible.
            if key_data.get('is_license', True) is False:
                return None, 'That key is a user account, not a license key'
            # A license is considered "used" once it has a username assigned
            if key_data.get('username'):
                return None, 'License key already used'
            if key_data.get('expiry') and key_data['expiry'] < self._now():
                return None, 'License key expired'
            new_hwid = key_data.get('hwid') or hwid or ''
            update_fields = {
                'username': username,
                'password': generate_password_hash(password),
                'hwid': new_hwid,
                'last_login': self._now()
            }
            if email:
                import hashlib
                update_fields['email'] = hashlib.sha1(email.lower().encode()).hexdigest()
            self.db.app_users.update_one(
                {'_id': key_data['_id']},
                {'$set': update_fields}
            )
            key_data['username'] = username
            key_data['hwid'] = new_hwid
            return key_data, None

    def api_change_username(self, app_id, old_username, new_username):
        """Change the username of a registered user."""
        if self.mode == 'mongo':
            oid = self._to_id(app_id)
            if self.db.app_users.find_one({'app_id': oid, 'username': new_username}):
                return False, 'already_used'
            result = self.db.app_users.update_one(
                {'app_id': oid, 'username': old_username},
                {'$set': {'username': new_username, 'key': new_username}}
            )
            if result.modified_count > 0:
                return True, 'success'
            return False, 'failure'

    def get_user_var(self, app_id, username, var_name):
        """Get a user-specific variable."""
        if self.mode == 'mongo':
            doc = self.db.uservars.find_one({
                'app_id': self._to_id(app_id),
                'username': username,
                'name': var_name
            })
            return doc.get('data') if doc else None

    def set_user_var(self, app_id, username, var_name, var_data):
        """Set a user-specific variable (upsert)."""
        if self.mode == 'mongo':
            result = self.db.uservars.update_one(
                {'app_id': self._to_id(app_id), 'username': username, 'name': var_name},
                {'$set': {'data': var_data, 'updated_at': self._now()}},
                upsert=True
            )
            return result.acknowledged

    def api_forgot_password(self, app_secret, username, email):
        """Verify email matches and reset password. Returns (new_password, error)."""
        if self.mode == 'mongo':
            import hashlib
            app = self.db.apps.find_one({'secret_key': app_secret})
            if not app:
                return None, 'Invalid application'
            user = self.db.app_users.find_one({'app_id': app['_id'], 'username': username})
            if not user:
                return None, 'No user found with that username!'
            stored_email = user.get('email')
            if not stored_email:
                return None, 'Email address not provided during register, ask developer to edit your account.'
            if hashlib.sha1(email.lower().encode()).hexdigest() != stored_email:
                return None, 'Email address does not match!'
            new_password = secrets.token_urlsafe(10)
            self.db.app_users.update_one(
                {'_id': user['_id']},
                {'$set': {'password': generate_password_hash(new_password)}}
            )
            return new_password, None

    # ── Backup ───────────────────────────────────────────────────────

    def backup(self, backup_dir):
        os.makedirs(backup_dir, exist_ok=True)
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        backup_path = os.path.join(backup_dir, f'backup_{timestamp}.json')
        if self.mode == 'mongo':
            def serialize(obj):
                if isinstance(obj, datetime):
                    return obj.isoformat()
                if isinstance(obj, ObjectId):
                    return str(obj)
                return obj
            data = {
                'admins': list(self.db.admins.find()),
                'apps': list(self.db.apps.find()),
                'packages': list(self.db.packages.find()),
                'app_users': list(self.db.app_users.find()),
            }
            with open(backup_path, 'w') as f:
                json.dump(data, f, indent=2, default=serialize)
        return backup_path

    def get_last_backup_time(self, backup_dir):
        os.makedirs(backup_dir, exist_ok=True)
        files = [f for f in os.listdir(backup_dir) if f.endswith('.json')]
        if not files:
            return None
        files.sort(reverse=True)
        latest = os.path.getmtime(os.path.join(backup_dir, files[0]))
        return datetime.fromtimestamp(latest)

    # ── Reseller package assignment ──────────────────────────────────

    def assign_package_to_reseller(self, reseller_id, package_id):
        if self.mode == 'mongo':
            oid = self._to_id(reseller_id)
            pkg_oid = self._to_id(package_id)
            self.db.admins.update_one({'_id': oid}, {'$addToSet': {'assigned_packages': pkg_oid}})

    def remove_package_from_reseller(self, reseller_id, package_id):
        if self.mode == 'mongo':
            oid = self._to_id(reseller_id)
            pkg_oid = self._to_id(package_id)
            self.db.admins.update_one({'_id': oid}, {'$pull': {'assigned_packages': pkg_oid}})

    def get_reseller_packages(self, reseller_id):
        if self.mode == 'mongo':
            admin = self.db.admins.find_one({'_id': self._to_id(reseller_id)})
            if not admin or not admin.get('assigned_packages'):
                return []
            return list(self.db.packages.find({'_id': {'$in': admin['assigned_packages']}}))

    # ── Key operations (for resellers) ────────────────────────────────

    def reset_hwid(self, user_id):
        if self.mode == 'mongo':
            self.db.app_users.update_one({'_id': self._to_id(user_id)}, {'$set': {'hwid': ''}})

    def extend_license(self, user_id, days):
        if self.mode == 'mongo':
            user = self.db.app_users.find_one({'_id': self._to_id(user_id)})
            if user:
                current_expiry = user.get('expiry') or self._now()
                if current_expiry < self._now():
                    current_expiry = self._now()
                new_expiry = current_expiry + timedelta(days=int(days))
                self.db.app_users.update_one({'_id': user['_id']}, {'$set': {'expiry': new_expiry}})

    def ban_license(self, user_id):
        if self.mode == 'mongo':
            self.db.app_users.update_one({'_id': self._to_id(user_id)}, {'$set': {'is_active': False}})

    def unban_license(self, user_id):
        if self.mode == 'mongo':
            self.db.app_users.update_one({'_id': self._to_id(user_id)}, {'$set': {'is_active': True}})

    def get_app_user_by_id(self, user_id):
        if self.mode == 'mongo':
            return self.db.app_users.find_one({'_id': self._to_id(user_id)})

    def get_license_by_id(self, license_id):
        return self.get_app_user_by_id(license_id)

    # ── Blacklists ───────────────────────────────────────────────────

    def add_blacklist(self, app_id, item, blacklist_type):
        if self.mode == 'mongo':
            doc = {
                'app_id': self._to_id(app_id),
                'item': item,
                'type': blacklist_type,
                'created_at': self._now()
            }
            res = self.db.blacklists.insert_one(doc)
            return str(res.inserted_id)

    def get_blacklists(self, app_id):
        if self.mode == 'mongo':
            return list(self.db.blacklists.find({'app_id': self._to_id(app_id)}).sort('created_at', -1))

    def delete_blacklist(self, blacklist_id):
        if self.mode == 'mongo':
            self.db.blacklists.delete_one({'_id': self._to_id(blacklist_id)})

    def check_blacklisted(self, app_id, hwid=None, ip=None):
        if self.mode == 'mongo':
            q = {'app_id': self._to_id(app_id)}
            items = []
            if hwid: items.append(hwid)
            if ip: items.append(ip)
            if not items: return False
            q['item'] = {'$in': items}
            return self.db.blacklists.find_one(q) is not None

    # ── Logs ─────────────────────────────────────────────────────────

    def add_log(self, app_id, username, action, ip):
        if self.mode == 'mongo':
            doc = {
                'app_id': self._to_id(app_id),
                'username': username,
                'action': action,
                'ip': ip,
                'timestamp': self._now()
            }
            self.db.logs.insert_one(doc)

    def get_logs(self, app_id):
        if self.mode == 'mongo':
            return list(self.db.logs.find({'app_id': self._to_id(app_id)}).sort('timestamp', -1).limit(500))

    def clear_logs(self, app_id):
        if self.mode == 'mongo':
            self.db.logs.delete_many({'app_id': self._to_id(app_id)})

    # ── Chat ─────────────────────────────────────────────────────────

    def create_chat_channel(self, app_id, name, delay=1):
        if self.mode == 'mongo':
            doc = {
                'app_id': self._to_id(app_id),
                'name': name,
                'delay': int(delay),
                'created_at': self._now()
            }
            res = self.db.chats.insert_one(doc)
            return str(res.inserted_id)

    def get_chat_channels(self, app_id):
        if self.mode == 'mongo':
            return list(self.db.chats.find({'app_id': self._to_id(app_id)}))

    def delete_chat_channel(self, channel_id):
        if self.mode == 'mongo':
            channel_oid = self._to_id(channel_id)
            self.db.chats.delete_one({'_id': channel_oid})
            self.db.chat_messages.delete_many({'channel_id': channel_oid})

    def send_chat_message(self, app_id, channel_name, author, message):
        if self.mode == 'mongo':
            channel = self.db.chats.find_one({'app_id': self._to_id(app_id), 'name': channel_name})
            if not channel: return False
            doc = {
                'channel_id': channel['_id'],
                'app_id': self._to_id(app_id),
                'author': author,
                'message': message,
                'timestamp': self._now()
            }
            self.db.chat_messages.insert_one(doc)
            return True

    def get_chat_messages(self, app_id, channel_name):
        if self.mode == 'mongo':
            channel = self.db.chats.find_one({'app_id': self._to_id(app_id), 'name': channel_name})
            if not channel: return []
            return list(self.db.chat_messages.find({'channel_id': channel['_id']}).sort('timestamp', -1).limit(50))

    # ── Dashboard stats ──────────────────────────────────────────────

    def get_stats(self, admin=None):
        if admin and admin['role'] == 'reseller':
            admin_id = admin['_id']
            return {
                'users': self.count_app_users(created_by=admin_id),
                'credits': admin.get('credits', 0),
                'assigned_packages': len(admin.get('assigned_packages', [])),
            }
        if admin and admin['role'] == 'admin':
            return {
                'apps': self.count_apps(),
                'users': self.count_app_users(),
                'packages': self.count_packages(),
                'credits': admin.get('credits', 0),
                'admins': self.count_admins(role='admin'),
                'resellers': self.count_admins(role='reseller'),
            }
        return {
            'apps': self.count_apps(),
            'users': self.count_app_users(),
            'packages': self.count_packages(),
            'credits': '∞',
            'admins': self.count_admins(role='admin'),
            'resellers': self.count_admins(role='reseller'),
        }

    # ── Chat / Messaging ──────────────────────────────────────────────

    def _ensure_chat_indexes(self):
        self.db.chat_messages.create_index([('room_id', 1), ('timestamp', 1)])
        self.db.chat_messages.create_index('to_username')

    def save_chat_message(self, room_id, from_username, from_role, to_username, message):
        doc = {
            'room_id': room_id,
            'from_username': from_username,
            'from_role': from_role,
            'to_username': to_username,
            'message': message,
            'timestamp': self._now(),
            'read': False,
        }
        result = self.db.chat_messages.insert_one(doc)
        doc['_id'] = result.inserted_id
        return doc

    def get_chat_history(self, room_id, limit=100):
        return list(
            self.db.chat_messages.find({'room_id': room_id})
            .sort('timestamp', 1)
            .limit(limit)
        )

    def mark_messages_read(self, room_id, reader_username):
        self.db.chat_messages.update_many(
            {'room_id': room_id, 'to_username': reader_username, 'read': False},
            {'$set': {'read': True}},
        )

    def get_unread_count(self, room_id, reader_username):
        return self.db.chat_messages.count_documents(
            {'room_id': room_id, 'to_username': reader_username, 'read': False}
        )

    # ── Announcements ────────────────────────────────────────────────

    def create_announcement(self, title, message, created_by, pinned=False, tag='announcement'):
        if self.mode == 'mongo':
            doc = {
                'title': title,
                'message': message,
                'created_by': created_by,
                'pinned': bool(pinned),
                'tag': tag or 'announcement',
                'created_at': self._now(),
                'updated_at': self._now(),
            }
            res = self.db.announcements.insert_one(doc)
            return str(res.inserted_id)

    def get_announcements(self):
        if self.mode == 'mongo':
            return list(self.db.announcements.find().sort([('pinned', -1), ('created_at', -1)]))

    def get_announcement_by_id(self, ann_id):
        if self.mode == 'mongo':
            return self.db.announcements.find_one({'_id': self._to_id(ann_id)})

    def update_announcement(self, ann_id, title, message, pinned=False, tag='announcement'):
        if self.mode == 'mongo':
            self.db.announcements.update_one(
                {'_id': self._to_id(ann_id)},
                {'$set': {'title': title, 'message': message, 'pinned': bool(pinned), 'tag': tag or 'announcement', 'updated_at': self._now()}}
            )

    def delete_announcement(self, ann_id):
        if self.mode == 'mongo':
            self.db.announcements.delete_one({'_id': self._to_id(ann_id)})

    def count_announcements(self):
        if self.mode == 'mongo':
            return self.db.announcements.count_documents({})

    # ── Global Files (public download hub) ───────────────────────────

    def create_global_file(self, name, url, description, added_by, category='general'):
        if self.mode == 'mongo':
            doc = {
                'name': name,
                'url': url,
                'description': description,
                'added_by': added_by,
                'category': category,
                'created_at': self._now(),
            }
            res = self.db.global_files.insert_one(doc)
            return str(res.inserted_id)

    def get_global_files(self):
        if self.mode == 'mongo':
            return list(self.db.global_files.find().sort('created_at', -1))

    def get_global_file_by_id(self, file_id):
        if self.mode == 'mongo':
            return self.db.global_files.find_one({'_id': self._to_id(file_id)})

    def delete_global_file(self, file_id):
        if self.mode == 'mongo':
            self.db.global_files.delete_one({'_id': self._to_id(file_id)})
            return True

    def count_global_files(self):
        if self.mode == 'mongo':
            return self.db.global_files.count_documents({})

    # ── Migration helper ─────────────────────────────────────────────

    def migrate_owner_ids_to_username(self):
        """
        One-time migration: convert all apps with ObjectId owner_id to plain username strings.
        Call this once after deploying this fix on an existing database.
        Run from a Flask shell: from models import db; db.migrate_owner_ids_to_username()
        """
        if self.mode != 'mongo':
            return
        apps = list(self.db.apps.find({}))
        migrated = 0
        for app in apps:
            oid = app.get('owner_id')
            # Skip apps already migrated (owner_id is a string, not ObjectId)
            if isinstance(oid, str) and len(oid) != 24:
                continue
            # Try to resolve to username
            if isinstance(oid, ObjectId):
                admin = self.db.admins.find_one({'_id': oid})
            elif isinstance(oid, str):
                try:
                    admin = self.db.admins.find_one({'_id': ObjectId(oid)})
                except Exception:
                    admin = None
            else:
                admin = None

            if admin:
                username = admin.get('username')
                self.db.apps.update_one(
                    {'_id': app['_id']},
                    {'$set': {
                        'owner_id': username,
                        'owner_mongo_id': admin['_id']
                    }}
                )
                migrated += 1

        print(f"Migration complete: {migrated}/{len(apps)} apps updated.")
        return migrated


db = Database()
