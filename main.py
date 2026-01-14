#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AccBox - 通用账号管家 后端API v4.0
功能: 多用户隔离、加密存储、2FA验证、安全中间件
"""

import os
import json
import sqlite3
import hashlib
import secrets
import time
from datetime import datetime, timedelta
from contextlib import contextmanager
from typing import Optional, List, Dict

from fastapi import FastAPI, HTTPException, Depends, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from cryptography.fernet import Fernet
import uvicorn

# ============================================================
# 配置
# ============================================================

VERSION = "4.0"
UNSAFE_DEFAULT_KEY = "DEFAULT_INSECURE_KEY_CHANGE_ME_IMMEDIATELY"

DATA_DIR = os.environ.get("DATA_DIR", os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(DATA_DIR, "accounts.db")
ENCRYPTION_KEY_FILE = os.path.join(DATA_DIR, ".encryption_key")

MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_MINUTES = 15

# ============================================================
# FastAPI 应用初始化
# ============================================================

app = FastAPI(title=f"AccBox API v{VERSION}", version=VERSION)


@app.middleware("http")
async def security_middleware(request: Request, call_next):
    """安全中间件：阻止访问敏感文件"""
    path = request.url.path.lower()
    if (
        path.endswith(".py") or
        path.endswith(".db") or
        path.endswith(".key") or
        "/data/" in path or
        "/." in path
    ):
        return JSONResponse(status_code=403, content={"detail": "禁止访问敏感资源"})
    return await call_next(request)


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================
# 加密模块
# ============================================================


def get_or_create_encryption_key() -> bytes:
    """
    获取加密密钥，优先级：
    1. 环境变量 APP_MASTER_KEY (推荐生产环境使用)
    2. 文件 .encryption_key
    3. 自动生成新密钥
    """
    env_key = os.environ.get("APP_MASTER_KEY")
    if env_key and env_key != UNSAFE_DEFAULT_KEY:
        return env_key.encode()

    if os.path.exists(ENCRYPTION_KEY_FILE):
        with open(ENCRYPTION_KEY_FILE, 'rb') as f:
            return f.read()

    key = Fernet.generate_key()
    with open(ENCRYPTION_KEY_FILE, 'wb') as f:
        f.write(key)
    try:
        os.chmod(ENCRYPTION_KEY_FILE, 0o600)
    except Exception:
        pass
    return key


ENCRYPTION_KEY = get_or_create_encryption_key()
cipher = Fernet(ENCRYPTION_KEY)


def encrypt_password(password: str) -> str:
    if not password:
        return ""
    return cipher.encrypt(password.encode()).decode()


def decrypt_password(encrypted: str) -> str:
    if not encrypted:
        return ""
    try:
        return cipher.decrypt(encrypted.encode()).decode()
    except Exception:
        return encrypted


# ============================================================
# 数据模型
# ============================================================

class UserRegister(BaseModel):
    username: str
    password: str


class UserLogin(BaseModel):
    username: str
    password: str


class ChangePassword(BaseModel):
    old_password: str
    new_password: str


class UpdateAvatar(BaseModel):
    avatar: str


class TotpConfig(BaseModel):
    secret: str
    issuer: str = ""
    totp_type: str = "totp"
    algorithm: str = "SHA1"
    digits: int = 6
    period: int = 30


class AccountCreate(BaseModel):
    type_id: int
    email: str
    password: str = ""
    country: str = "🌍"
    customName: str = ""
    properties: Dict[int, int] = {}
    combos: List[List[int]] = []
    tags: List[str] = []
    notes: str = ""


class AccountUpdate(BaseModel):
    type_id: Optional[int] = None
    email: Optional[str] = None
    password: Optional[str] = None
    country: Optional[str] = None
    customName: Optional[str] = None
    properties: Optional[Dict[int, int]] = None
    combos: Optional[List[List[int]]] = None
    tags: Optional[List[str]] = None
    notes: Optional[str] = None
    is_favorite: Optional[bool] = None


class AccountTypeCreate(BaseModel):
    name: str
    icon: str
    color: str = "#8b5cf6"
    login_url: str = ""


class AccountTypeUpdate(BaseModel):
    name: Optional[str] = None
    icon: Optional[str] = None
    color: Optional[str] = None
    login_url: Optional[str] = None


class PropertyGroupCreate(BaseModel):
    name: str


class PropertyGroupUpdate(BaseModel):
    name: Optional[str] = None


class PropertyValueCreate(BaseModel):
    group_id: int
    name: str
    color: str = "#8b5cf6"


class PropertyValueUpdate(BaseModel):
    name: Optional[str] = None
    color: Optional[str] = None


# ============================================================
# 数据库
# ============================================================

@contextmanager
def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
    finally:
        conn.close()


def init_db():
    """初始化主用户表"""
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                token TEXT,
                avatar TEXT DEFAULT '👤',
                login_attempts INTEGER DEFAULT 0,
                locked_until TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        # 兼容旧版本：添加avatar列
        try:
            conn.execute("ALTER TABLE users ADD COLUMN avatar TEXT DEFAULT '👤'")
        except sqlite3.OperationalError:
            pass
        conn.commit()


def init_user_tables(user_id: int):
    """为新用户创建专属数据表"""
    with get_db() as conn:
        # 账号类型表
        conn.execute(f"""
            CREATE TABLE IF NOT EXISTS user_{user_id}_account_types (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                icon TEXT DEFAULT '🔑',
                color TEXT DEFAULT '#8b5cf6',
                login_url TEXT DEFAULT '',
                sort_order INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # 属性组表
        conn.execute(f"""
            CREATE TABLE IF NOT EXISTS user_{user_id}_property_groups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                sort_order INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # 属性值表
        conn.execute(f"""
            CREATE TABLE IF NOT EXISTS user_{user_id}_property_values (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                group_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                color TEXT DEFAULT '#8b5cf6',
                sort_order INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (group_id) REFERENCES user_{user_id}_property_groups(id) ON DELETE CASCADE
            )
        """)

        # 账号表
        conn.execute(f"""
            CREATE TABLE IF NOT EXISTS user_{user_id}_accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                type_id INTEGER,
                email TEXT NOT NULL,
                password TEXT DEFAULT '',
                country TEXT DEFAULT '🌍',
                custom_name TEXT DEFAULT '',
                properties TEXT DEFAULT '{json.dumps({})}',
                combos TEXT DEFAULT '[]',
                tags TEXT DEFAULT '[]',
                notes TEXT DEFAULT '',
                is_favorite INTEGER DEFAULT 0,
                last_used TIMESTAMP,
                totp_secret TEXT DEFAULT '',
                totp_issuer TEXT DEFAULT '',
                totp_type TEXT DEFAULT 'totp',
                totp_algorithm TEXT DEFAULT 'SHA1',
                totp_digits INTEGER DEFAULT 6,
                totp_period INTEGER DEFAULT 30,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # 初始化默认数据
        cursor = conn.execute(f"SELECT COUNT(*) FROM user_{user_id}_account_types")
        if cursor.fetchone()[0] == 0:
            _init_default_data(conn, user_id)

        conn.commit()


def _init_default_data(conn, user_id: int):
    """插入默认账号类型和属性"""
    default_types = [
        ('Google', 'G', '#4285f4', 'https://accounts.google.com/signin/v2/identifier?Email='),
        ('Microsoft', 'M', '#00a4ef', 'https://login.live.com/'),
        ('Discord', 'D', '#5865F2', 'https://discord.com/login'),
        ('Steam', '🎮', '#1b2838', 'https://store.steampowered.com/login/'),
        ('EA/FIFA', 'EA', '#ff4747', 'https://www.ea.com/login'),
    ]
    for i, (name, icon, color, url) in enumerate(default_types):
        conn.execute(f"""
            INSERT INTO user_{user_id}_account_types (name, icon, color, login_url, sort_order)
            VALUES (?, ?, ?, ?, ?)
        """, (name, icon, color, url, i))

    # 默认属性组：账号状态
    conn.execute(f"INSERT INTO user_{user_id}_property_groups (name, sort_order) VALUES ('账号状态', 0)")
    status_group_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    for i, (name, color) in enumerate([('正常', '#4ade80'), ('受限', '#facc15'), ('不可用', '#f87171')]):
        conn.execute(f"""
            INSERT INTO user_{user_id}_property_values (group_id, name, color, sort_order)
            VALUES (?, ?, ?, ?)
        """, (status_group_id, name, color, i))

    # 默认属性组：服务类型
    conn.execute(f"INSERT INTO user_{user_id}_property_groups (name, sort_order) VALUES ('服务类型', 1)")
    service_group_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    for i, (name, color) in enumerate([('CLI', '#a78bfa'), ('Antigravity', '#60a5fa'), ('GCP', '#fb923c'), ('APIKey', '#4ade80'), ('Build', '#22d3ee')]):
        conn.execute(f"""
            INSERT INTO user_{user_id}_property_values (group_id, name, color, sort_order)
            VALUES (?, ?, ?, ?)
        """, (service_group_id, name, color, i))


def migrate_database():
    """数据库结构迁移"""
    with get_db() as conn:
        cursor = conn.execute("SELECT id FROM users")
        for user in cursor.fetchall():
            uid = user["id"]
            # 迁移 combos 列
            try:
                conn.execute(f"SELECT combos FROM user_{uid}_accounts LIMIT 1")
            except sqlite3.OperationalError:
                try:
                    conn.execute(f"ALTER TABLE user_{uid}_accounts ADD COLUMN combos TEXT DEFAULT '[]'")
                    print(f"✅ 用户 {uid}: 添加 combos 列")
                except Exception:
                    pass

            # 迁移 2FA 列
            for col, typ in [
                ("totp_secret", "TEXT DEFAULT ''"),
                ("totp_issuer", "TEXT DEFAULT ''"),
                ("totp_type", "TEXT DEFAULT 'totp'"),
                ("totp_algorithm", "TEXT DEFAULT 'SHA1'"),
                ("totp_digits", "INTEGER DEFAULT 6"),
                ("totp_period", "INTEGER DEFAULT 30"),
            ]:
                try:
                    conn.execute(f"SELECT {col} FROM user_{uid}_accounts LIMIT 1")
                except sqlite3.OperationalError:
                    try:
                        conn.execute(f"ALTER TABLE user_{uid}_accounts ADD COLUMN {col} {typ}")
                        print(f"✅ 用户 {uid}: 添加 {col} 列")
                    except Exception:
                        pass
        conn.commit()


# ============================================================
# 工具函数
# ============================================================

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def generate_token() -> str:
    return secrets.token_hex(32)


def get_current_user(authorization: str = Header(None)) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="未授权")
    token = authorization.replace("Bearer ", "")
    with get_db() as conn:
        cursor = conn.execute("SELECT id, username FROM users WHERE token = ?", (token,))
        user = cursor.fetchone()
    if not user:
        raise HTTPException(status_code=401, detail="无效令牌")
    return {"id": user["id"], "username": user["username"]}


# ============================================================
# 用户 API
# ============================================================

@app.post("/api/register")
def register(data: UserRegister):
    if len(data.username) < 2:
        raise HTTPException(status_code=400, detail="用户名至少2个字符")
    if len(data.password) < 4:
        raise HTTPException(status_code=400, detail="密码至少4个字符")

    password_hash = hash_password(data.password)
    token = generate_token()

    with get_db() as conn:
        try:
            cursor = conn.execute(
                "INSERT INTO users (username, password_hash, token) VALUES (?, ?, ?)",
                (data.username, password_hash, token)
            )
            user_id = cursor.lastrowid
            conn.commit()
        except sqlite3.IntegrityError:
            raise HTTPException(status_code=400, detail="用户名已存在")

    init_user_tables(user_id)
    return {"message": "注册成功", "token": token, "user": {"id": user_id, "username": data.username, "avatar": "👤"}}


@app.post("/api/login")
def login(data: UserLogin):
    with get_db() as conn:
        # 检查锁定状态
        cursor = conn.execute("SELECT login_attempts, locked_until FROM users WHERE username = ?", (data.username,))
        row = cursor.fetchone()
        if row and row["locked_until"]:
            locked_until = datetime.fromisoformat(row["locked_until"])
            if datetime.now() < locked_until:
                remaining = (locked_until - datetime.now()).seconds // 60 + 1
                raise HTTPException(status_code=423, detail=f"账号已锁定，请 {remaining} 分钟后重试")
            else:
                conn.execute("UPDATE users SET login_attempts = 0, locked_until = NULL WHERE username = ?", (data.username,))

        password_hash = hash_password(data.password)
        cursor = conn.execute(
            "SELECT id, username, avatar FROM users WHERE username = ? AND password_hash = ?",
            (data.username, password_hash)
        )
        user = cursor.fetchone()

        if not user:
            cursor2 = conn.execute("SELECT id FROM users WHERE username = ?", (data.username,))
            if cursor2.fetchone():
                conn.execute("UPDATE users SET login_attempts = login_attempts + 1 WHERE username = ?", (data.username,))
                cursor3 = conn.execute("SELECT login_attempts FROM users WHERE username = ?", (data.username,))
                attempts = cursor3.fetchone()["login_attempts"]
                if attempts >= MAX_LOGIN_ATTEMPTS:
                    locked_until = (datetime.now() + timedelta(minutes=LOCKOUT_MINUTES)).isoformat()
                    conn.execute("UPDATE users SET locked_until = ? WHERE username = ?", (locked_until, data.username))
                    conn.commit()
                    raise HTTPException(status_code=423, detail=f"账号已锁定，请 {LOCKOUT_MINUTES} 分钟后重试")
                conn.commit()
                raise HTTPException(status_code=401, detail=f"密码错误，还剩 {MAX_LOGIN_ATTEMPTS - attempts} 次尝试")
            raise HTTPException(status_code=401, detail="用户名或密码错误")

        conn.execute("UPDATE users SET login_attempts = 0, locked_until = NULL WHERE username = ?", (data.username,))
        token = generate_token()
        conn.execute("UPDATE users SET token = ? WHERE id = ?", (token, user["id"]))
        conn.commit()

    init_user_tables(user["id"])
    return {"message": "登录成功", "token": token, "user": {"id": user["id"], "username": user["username"], "avatar": user["avatar"] or "👤"}}


@app.post("/api/update-avatar")
def update_avatar(data: UpdateAvatar, user: dict = Depends(get_current_user)):
    with get_db() as conn:
        conn.execute("UPDATE users SET avatar = ? WHERE id = ?", (data.avatar, user["id"]))
        conn.commit()
    return {"message": "头像更新成功", "avatar": data.avatar}


@app.post("/api/change-password")
def change_password(data: ChangePassword, user: dict = Depends(get_current_user)):
    old_hash = hash_password(data.old_password)
    new_hash = hash_password(data.new_password)
    with get_db() as conn:
        cursor = conn.execute("SELECT password_hash FROM users WHERE id = ?", (user["id"],))
        row = cursor.fetchone()
        if not row or row["password_hash"] != old_hash:
            raise HTTPException(status_code=400, detail="当前密码错误")
        conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (new_hash, user["id"]))
        conn.commit()
    return {"message": "密码修改成功"}


# ============================================================
# 账号类型 API
# ============================================================

@app.get("/api/account-types")
def get_account_types(user: dict = Depends(get_current_user)):
    with get_db() as conn:
        cursor = conn.execute(f"SELECT * FROM user_{user['id']}_account_types ORDER BY sort_order, id")
        rows = cursor.fetchall()
    return {"types": [dict(row) for row in rows]}


@app.post("/api/account-types")
def create_account_type(data: AccountTypeCreate, user: dict = Depends(get_current_user)):
    with get_db() as conn:
        cursor = conn.execute(f"""
            INSERT INTO user_{user['id']}_account_types (name, icon, color, login_url)
            VALUES (?, ?, ?, ?)
        """, (data.name, data.icon, data.color, data.login_url))
        conn.commit()
        return {"message": "创建成功", "id": cursor.lastrowid}


@app.put("/api/account-types/{type_id}")
def update_account_type(type_id: int, data: AccountTypeUpdate, user: dict = Depends(get_current_user)):
    updates, values = [], []
    if data.name is not None:
        updates.append("name = ?")
        values.append(data.name)
    if data.icon is not None:
        updates.append("icon = ?")
        values.append(data.icon)
    if data.color is not None:
        updates.append("color = ?")
        values.append(data.color)
    if data.login_url is not None:
        updates.append("login_url = ?")
        values.append(data.login_url)
    if not updates:
        raise HTTPException(status_code=400, detail="无更新字段")
    values.append(type_id)
    with get_db() as conn:
        conn.execute(f"UPDATE user_{user['id']}_account_types SET {', '.join(updates)} WHERE id = ?", values)
        conn.commit()
    return {"message": "更新成功"}


@app.delete("/api/account-types/{type_id}")
def delete_account_type(type_id: int, user: dict = Depends(get_current_user)):
    with get_db() as conn:
        conn.execute(f"UPDATE user_{user['id']}_accounts SET type_id = NULL WHERE type_id = ?", (type_id,))
        conn.execute(f"DELETE FROM user_{user['id']}_account_types WHERE id = ?", (type_id,))
        conn.commit()
    return {"message": "删除成功"}


# ============================================================
# 属性组 API
# ============================================================

@app.get("/api/property-groups")
def get_property_groups(user: dict = Depends(get_current_user)):
    with get_db() as conn:
        groups = []
        cursor = conn.execute(f"SELECT * FROM user_{user['id']}_property_groups ORDER BY sort_order, id")
        for row in cursor.fetchall():
            group = dict(row)
            values_cursor = conn.execute(f"""
                SELECT * FROM user_{user['id']}_property_values 
                WHERE group_id = ? ORDER BY sort_order, id
            """, (group['id'],))
            group['values'] = [dict(v) for v in values_cursor.fetchall()]
            groups.append(group)
    return {"groups": groups}


@app.post("/api/property-groups")
def create_property_group(data: PropertyGroupCreate, user: dict = Depends(get_current_user)):
    with get_db() as conn:
        cursor = conn.execute(f"INSERT INTO user_{user['id']}_property_groups (name) VALUES (?)", (data.name,))
        conn.commit()
    return {"message": "创建成功", "id": cursor.lastrowid}


@app.put("/api/property-groups/{group_id}")
def update_property_group(group_id: int, data: PropertyGroupUpdate, user: dict = Depends(get_current_user)):
    with get_db() as conn:
        conn.execute(f"UPDATE user_{user['id']}_property_groups SET name = ? WHERE id = ?", (data.name, group_id))
        conn.commit()
    return {"message": "更新成功"}


@app.delete("/api/property-groups/{group_id}")
def delete_property_group(group_id: int, user: dict = Depends(get_current_user)):
    with get_db() as conn:
        conn.execute(f"DELETE FROM user_{user['id']}_property_groups WHERE id = ?", (group_id,))
        conn.commit()
    return {"message": "删除成功"}


@app.post("/api/property-values")
def create_property_value(data: PropertyValueCreate, user: dict = Depends(get_current_user)):
    with get_db() as conn:
        cursor = conn.execute(f"""
            INSERT INTO user_{user['id']}_property_values (group_id, name, color)
            VALUES (?, ?, ?)
        """, (data.group_id, data.name, data.color))
        conn.commit()
    return {"message": "创建成功", "id": cursor.lastrowid}


@app.put("/api/property-values/{value_id}")
def update_property_value(value_id: int, data: PropertyValueUpdate, user: dict = Depends(get_current_user)):
    updates, values = [], []
    if data.name is not None:
        updates.append("name = ?")
        values.append(data.name)
    if data.color is not None:
        updates.append("color = ?")
        values.append(data.color)
    if not updates:
        raise HTTPException(status_code=400, detail="无更新字段")
    values.append(value_id)
    with get_db() as conn:
        conn.execute(f"UPDATE user_{user['id']}_property_values SET {', '.join(updates)} WHERE id = ?", values)
        conn.commit()
    return {"message": "更新成功"}


@app.delete("/api/property-values/{value_id}")
def delete_property_value(value_id: int, user: dict = Depends(get_current_user)):
    with get_db() as conn:
        conn.execute(f"DELETE FROM user_{user['id']}_property_values WHERE id = ?", (value_id,))
        conn.commit()
    return {"message": "删除成功"}


# ============================================================
# 账号 API
# ============================================================

@app.get("/api/accounts")
def get_accounts(user: dict = Depends(get_current_user)):
    with get_db() as conn:
        cursor = conn.execute(f"""
            SELECT * FROM user_{user['id']}_accounts 
            ORDER BY is_favorite DESC, last_used DESC NULLS LAST, created_at DESC
        """)
        rows = cursor.fetchall()

    accounts = []
    for row in rows:
        acc = dict(row)
        # 检测是否配置了 2FA
        has_2fa = bool(acc.get("totp_secret"))
        accounts.append({
            "id": acc["id"],
            "type_id": acc["type_id"],
            "email": acc["email"],
            "password": decrypt_password(acc["password"]),
            "country": acc["country"],
            "customName": acc["custom_name"] or "",
            "properties": json.loads(acc["properties"] or "{}"),
            "combos": json.loads(acc.get("combos") or "[]"),
            "tags": json.loads(acc["tags"] or "[]"),
            "notes": acc["notes"] or "",
            "is_favorite": bool(acc["is_favorite"]),
            "last_used": acc["last_used"],
            "created_at": acc["created_at"],
            "updated_at": acc["updated_at"],
            "has_2fa": has_2fa,
        })
    return {"accounts": accounts}


@app.post("/api/accounts")
def create_account(data: AccountCreate, user: dict = Depends(get_current_user)):
    now = datetime.now().isoformat()
    encrypted_pwd = encrypt_password(data.password) if data.password else ""
    with get_db() as conn:
        cursor = conn.execute(f"""
            INSERT INTO user_{user['id']}_accounts 
            (type_id, email, password, country, custom_name, properties, combos, tags, notes, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            data.type_id, data.email, encrypted_pwd, data.country, data.customName,
            json.dumps(data.properties), json.dumps(data.combos),
            json.dumps(data.tags, ensure_ascii=False), data.notes, now, now
        ))
        conn.commit()
    return {"message": "创建成功", "id": cursor.lastrowid}


@app.put("/api/accounts/{account_id}")
def update_account(account_id: int, data: AccountUpdate, user: dict = Depends(get_current_user)):
    now = datetime.now().isoformat()
    updates, values = [], []

    if data.type_id is not None:
        updates.append("type_id = ?")
        values.append(data.type_id)
    if data.email is not None:
        updates.append("email = ?")
        values.append(data.email)
    if data.password is not None:
        updates.append("password = ?")
        values.append(encrypt_password(data.password) if data.password else "")
    if data.country is not None:
        updates.append("country = ?")
        values.append(data.country)
    if data.customName is not None:
        updates.append("custom_name = ?")
        values.append(data.customName)
    if data.properties is not None:
        updates.append("properties = ?")
        values.append(json.dumps(data.properties))
    if data.combos is not None:
        updates.append("combos = ?")
        values.append(json.dumps(data.combos))
    if data.tags is not None:
        updates.append("tags = ?")
        values.append(json.dumps(data.tags, ensure_ascii=False))
    if data.notes is not None:
        updates.append("notes = ?")
        values.append(data.notes)
    if data.is_favorite is not None:
        updates.append("is_favorite = ?")
        values.append(1 if data.is_favorite else 0)

    if not updates:
        raise HTTPException(status_code=400, detail="无更新字段")

    updates.append("updated_at = ?")
    values.append(now)
    values.append(account_id)

    with get_db() as conn:
        cursor = conn.execute(f"UPDATE user_{user['id']}_accounts SET {', '.join(updates)} WHERE id = ?", values)
        conn.commit()
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="账号不存在")
    return {"message": "更新成功"}


@app.post("/api/accounts/{account_id}/use")
def record_account_use(account_id: int, user: dict = Depends(get_current_user)):
    now = datetime.now().isoformat()
    with get_db() as conn:
        conn.execute(f"UPDATE user_{user['id']}_accounts SET last_used = ? WHERE id = ?", (now, account_id))
        conn.commit()
    return {"message": "已记录"}


@app.post("/api/accounts/{account_id}/favorite")
def toggle_favorite(account_id: int, user: dict = Depends(get_current_user)):
    with get_db() as conn:
        cursor = conn.execute(f"SELECT is_favorite FROM user_{user['id']}_accounts WHERE id = ?", (account_id,))
        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="账号不存在")
        new_val = 0 if row["is_favorite"] else 1
        conn.execute(f"UPDATE user_{user['id']}_accounts SET is_favorite = ? WHERE id = ?", (new_val, account_id))
        conn.commit()
    return {"message": "已更新", "is_favorite": bool(new_val)}


@app.delete("/api/accounts/{account_id}")
def delete_account(account_id: int, user: dict = Depends(get_current_user)):
    with get_db() as conn:
        conn.execute(f"DELETE FROM user_{user['id']}_accounts WHERE id = ?", (account_id,))
        conn.commit()
    return {"message": "删除成功"}


# ============================================================
# 2FA API
# ============================================================

import hmac
import struct
import re

# Steam Guard 字符集
STEAM_CHARS = "23456789BCDFGHJKMNPQRTVWXY"


def generate_totp(secret: str, time_offset: int = 0, digits: int = 6, period: int = 30, algorithm: str = "SHA1") -> str:
    """生成标准 TOTP 验证码"""
    try:
        import base64
        # 补齐 Base32 填充
        secret_clean = secret.upper().replace(" ", "").replace("-", "")
        padding = (8 - len(secret_clean) % 8) % 8
        key = base64.b32decode(secret_clean + "=" * padding)
        
        counter = (int(time.time()) + time_offset) // period
        counter_bytes = struct.pack(">Q", counter)
        
        hash_func = {"SHA256": hashlib.sha256, "SHA512": hashlib.sha512}.get(algorithm.upper(), hashlib.sha1)
        h = hmac.new(key, counter_bytes, hash_func).digest()
        
        offset = h[-1] & 0x0F
        code = struct.unpack(">I", h[offset:offset + 4])[0] & 0x7FFFFFFF
        return str(code % (10 ** digits)).zfill(digits)
    except Exception as e:
        print(f"TOTP生成错误: {e}")
        return ""


def generate_steam_code(secret: str, time_offset: int = 0) -> str:
    """生成 Steam Guard 5位字母验证码"""
    try:
        import base64
        key = base64.b64decode(secret)
        counter = (int(time.time()) + time_offset) // 30
        h = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
        offset = h[-1] & 0x0F
        code = struct.unpack(">I", h[offset:offset + 4])[0] & 0x7FFFFFFF
        return "".join(STEAM_CHARS[code // (len(STEAM_CHARS) ** i) % len(STEAM_CHARS)] for i in range(5))
    except Exception as e:
        print(f"Steam Guard生成错误: {e}")
        return ""


def parse_otpauth_uri(uri: str) -> Optional[dict]:
    """解析 otpauth:// URI"""
    try:
        match = re.match(r'otpauth://(totp|hotp)/([^?]+)\?(.+)', uri)
        if not match:
            return None
        params = dict(p.split('=', 1) for p in match.group(3).split('&') if '=' in p)
        label = match.group(2)
        # URL 解码
        from urllib.parse import unquote
        label = unquote(label)
        return {
            "type": match.group(1),
            "label": label,
            "secret": params.get("secret", ""),
            "issuer": unquote(params.get("issuer", "")),
            "algorithm": params.get("algorithm", "SHA1").upper(),
            "digits": int(params.get("digits", 6)),
            "period": int(params.get("period", 30))
        }
    except Exception:
        return None


@app.get("/api/accounts/{account_id}/totp")
def get_totp_config(account_id: int, user: dict = Depends(get_current_user)):
    """获取 2FA 配置"""
    with get_db() as conn:
        cursor = conn.execute(f"""
            SELECT totp_secret, totp_issuer, totp_type, totp_algorithm, totp_digits, totp_period
            FROM user_{user['id']}_accounts WHERE id = ?
        """, (account_id,))
        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="账号不存在")

        secret = decrypt_password(row["totp_secret"]) if row["totp_secret"] else None
        if not secret:
            return {"secret": None}

        return {
            "secret": secret,
            "issuer": row["totp_issuer"] or "",
            "type": row["totp_type"] or "totp",
            "algorithm": row["totp_algorithm"] or "SHA1",
            "digits": row["totp_digits"] or 6,
            "period": row["totp_period"] or 30,
        }


@app.get("/api/accounts/{account_id}/totp/generate")
def generate_totp_code(account_id: int, user: dict = Depends(get_current_user)):
    """生成当前 2FA 验证码（支持标准TOTP和Steam Guard）"""
    with get_db() as conn:
        cursor = conn.execute(f"""
            SELECT totp_secret, totp_type, totp_algorithm, totp_digits, totp_period
            FROM user_{user['id']}_accounts WHERE id = ?
        """, (account_id,))
        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="账号不存在")
        
        secret = decrypt_password(row["totp_secret"]) if row["totp_secret"] else None
        if not secret:
            raise HTTPException(status_code=404, detail="未配置 2FA")
        
        totp_type = row["totp_type"] or "totp"
        
        if totp_type == "steam":
            code = generate_steam_code(secret)
        else:
            code = generate_totp(
                secret,
                digits=row["totp_digits"] or 6,
                period=row["totp_period"] or 30,
                algorithm=row["totp_algorithm"] or "SHA1"
            )
        
        # 计算剩余时间
        period = row["totp_period"] or 30
        remaining = period - (int(time.time()) % period)
        
        return {
            "code": code,
            "type": totp_type,
            "remaining": remaining,
            "period": period
        }


@app.post("/api/accounts/{account_id}/totp")
def update_totp_config(account_id: int, config: TotpConfig, user: dict = Depends(get_current_user)):
    """更新 2FA 配置"""
    encrypted_secret = encrypt_password(config.secret)
    now = datetime.now().isoformat()
    with get_db() as conn:
        conn.execute(f"""
            UPDATE user_{user['id']}_accounts 
            SET totp_secret = ?, totp_issuer = ?, totp_type = ?, 
                totp_algorithm = ?, totp_digits = ?, totp_period = ?, updated_at = ?
            WHERE id = ?
        """, (encrypted_secret, config.issuer, config.totp_type,
              config.algorithm, config.digits, config.period, now, account_id))
        conn.commit()
    return {"message": "2FA 配置已更新"}


@app.post("/api/accounts/{account_id}/totp/parse")
def parse_and_save_totp_uri(account_id: int, data: dict, user: dict = Depends(get_current_user)):
    """从 otpauth:// URI 导入 2FA 配置"""
    uri = data.get("uri", "")
    parsed = parse_otpauth_uri(uri)
    if not parsed:
        raise HTTPException(status_code=400, detail="无效的 otpauth URI")
    
    now = datetime.now().isoformat()
    with get_db() as conn:
        conn.execute(f"""
            UPDATE user_{user['id']}_accounts 
            SET totp_secret = ?, totp_issuer = ?, totp_type = ?, 
                totp_algorithm = ?, totp_digits = ?, totp_period = ?, updated_at = ?
            WHERE id = ?
        """, (
            encrypt_password(parsed["secret"]),
            parsed["issuer"] or parsed["label"],
            parsed["type"],
            parsed["algorithm"],
            parsed["digits"],
            parsed["period"],
            now,
            account_id
        ))
        conn.commit()
    
    return {
        "message": "2FA 配置已从 URI 导入",
        "issuer": parsed["issuer"] or parsed["label"],
        "type": parsed["type"],
        "digits": parsed["digits"]
    }


@app.delete("/api/accounts/{account_id}/totp")
def delete_totp_config(account_id: int, user: dict = Depends(get_current_user)):
    """删除 2FA 配置"""
    now = datetime.now().isoformat()
    with get_db() as conn:
        conn.execute(f"""
            UPDATE user_{user['id']}_accounts 
            SET totp_secret = '', totp_issuer = '', totp_type = '', updated_at = ?
            WHERE id = ?
        """, (now, account_id))
        conn.commit()
    return {"message": "2FA 配置已移除"}


# ============================================================
# 导入导出 API
# ============================================================

@app.get("/api/export")
def export_data(user: dict = Depends(get_current_user)):
    with get_db() as conn:
        types = [dict(row) for row in conn.execute(
            f"SELECT * FROM user_{user['id']}_account_types ORDER BY sort_order"
        ).fetchall()]

        groups = []
        for row in conn.execute(f"SELECT * FROM user_{user['id']}_property_groups ORDER BY sort_order").fetchall():
            group = dict(row)
            group['values'] = [dict(v) for v in conn.execute(
                f"SELECT * FROM user_{user['id']}_property_values WHERE group_id = ? ORDER BY sort_order",
                (group['id'],)
            ).fetchall()]
            groups.append(group)

        accounts = []
        for row in conn.execute(f"SELECT * FROM user_{user['id']}_accounts").fetchall():
            acc = dict(row)
            account_data = {
                "id": acc["id"],
                "type_id": acc["type_id"],
                "email": acc["email"],
                "password": decrypt_password(acc["password"]),
                "country": acc["country"],
                "customName": acc["custom_name"] or "",
                "properties": json.loads(acc["properties"] or "{}"),
                "combos": json.loads(acc.get("combos") or "[]"),
                "tags": json.loads(acc["tags"] or "[]"),
                "notes": acc["notes"] or "",
                "is_favorite": bool(acc["is_favorite"]),
                "created_at": acc["created_at"],
            }
            # 导出2FA配置
            if acc.get("totp_secret"):
                account_data["totp"] = {
                    "secret": decrypt_password(acc["totp_secret"]),
                    "issuer": acc.get("totp_issuer") or "",
                    "type": acc.get("totp_type") or "totp",
                    "algorithm": acc.get("totp_algorithm") or "SHA1",
                    "digits": acc.get("totp_digits") or 6,
                    "period": acc.get("totp_period") or 30,
                }
            accounts.append(account_data)

    return {
        "version": VERSION,
        "exported_at": datetime.now().isoformat(),
        "account_types": types,
        "property_groups": groups,
        "accounts": accounts
    }


@app.post("/api/import")
def import_data(data: dict, user: dict = Depends(get_current_user)):
    import_mode = data.get("mode", "all")
    now = datetime.now().isoformat()

    imported_types = imported_groups = imported_values = imported_accounts = 0
    updated_accounts = skipped_accounts = 0
    type_id_map = {}
    value_id_map = {}

    with get_db() as conn:
        # 导入账号类型
        existing_types = {}
        cursor = conn.execute(f"SELECT id, name FROM user_{user['id']}_account_types")
        for row in cursor.fetchall():
            existing_types[row["name"].lower()] = row["id"]

        for old_type in data.get("account_types", []):
            old_id = old_type.get("id")
            name = old_type.get("name", "")
            name_lower = name.lower()

            if name_lower in existing_types:
                type_id_map[old_id] = existing_types[name_lower]
            else:
                cursor = conn.execute(f"""
                    INSERT INTO user_{user['id']}_account_types (name, icon, color, login_url, sort_order)
                    VALUES (?, ?, ?, ?, ?)
                """, (name, old_type.get("icon", "🔑"), old_type.get("color", "#8b5cf6"),
                      old_type.get("login_url", ""), old_type.get("sort_order", 0)))
                type_id_map[old_id] = cursor.lastrowid
                existing_types[name_lower] = cursor.lastrowid
                imported_types += 1

        # 导入属性组和属性值
        existing_groups = {}
        cursor = conn.execute(f"SELECT id, name FROM user_{user['id']}_property_groups")
        for row in cursor.fetchall():
            existing_groups[row["name"].lower()] = row["id"]

        existing_values = {}
        cursor = conn.execute(f"SELECT id, group_id, name FROM user_{user['id']}_property_values")
        for row in cursor.fetchall():
            gid = row["group_id"]
            if gid not in existing_values:
                existing_values[gid] = {}
            existing_values[gid][row["name"].lower()] = row["id"]

        for old_group in data.get("property_groups", []):
            old_group_id = old_group.get("id")
            group_name = old_group.get("name", "")
            group_name_lower = group_name.lower()

            if group_name_lower in existing_groups:
                new_group_id = existing_groups[group_name_lower]
            else:
                cursor = conn.execute(f"""
                    INSERT INTO user_{user['id']}_property_groups (name, sort_order)
                    VALUES (?, ?)
                """, (group_name, old_group.get("sort_order", 0)))
                new_group_id = cursor.lastrowid
                existing_groups[group_name_lower] = new_group_id
                existing_values[new_group_id] = {}
                imported_groups += 1

            for old_value in old_group.get("values", []):
                old_value_id = old_value.get("id")
                value_name = old_value.get("name", "")
                value_name_lower = value_name.lower()

                group_values = existing_values.get(new_group_id, {})
                if value_name_lower in group_values:
                    value_id_map[old_value_id] = group_values[value_name_lower]
                else:
                    cursor = conn.execute(f"""
                        INSERT INTO user_{user['id']}_property_values (group_id, name, color, sort_order)
                        VALUES (?, ?, ?, ?)
                    """, (new_group_id, value_name, old_value.get("color", "#8b5cf6"), old_value.get("sort_order", 0)))
                    new_value_id = cursor.lastrowid
                    value_id_map[old_value_id] = new_value_id
                    if new_group_id not in existing_values:
                        existing_values[new_group_id] = {}
                    existing_values[new_group_id][value_name_lower] = new_value_id
                    imported_values += 1

        # 导入账号
        existing_accounts = {}
        if import_mode in ("skip", "overwrite"):
            cursor = conn.execute(f"SELECT id, email FROM user_{user['id']}_accounts WHERE email != ''")
            for row in cursor.fetchall():
                existing_accounts[row["email"].lower()] = row["id"]

        for acc in data.get("accounts", []):
            try:
                email = acc.get("email", "")
                email_lower = email.lower() if email else ""
                existing_id = existing_accounts.get(email_lower) if email_lower else None

                old_type_id = acc.get("type_id")
                new_type_id = type_id_map.get(old_type_id, old_type_id) if old_type_id else None

                old_combos = acc.get("combos", [])
                new_combos = []
                for combo in old_combos:
                    if isinstance(combo, list):
                        new_combo = [value_id_map.get(vid, vid) for vid in combo]
                        new_combos.append(new_combo)

                old_properties = acc.get("properties", {})
                new_properties = {}
                for k, v in old_properties.items():
                    new_properties[str(k)] = value_id_map.get(v, v)

                if existing_id:
                    if import_mode == "skip":
                        skipped_accounts += 1
                        continue
                    elif import_mode == "overwrite":
                        # 基本字段更新
                        conn.execute(f"""
                            UPDATE user_{user['id']}_accounts SET
                            type_id = ?, password = ?, country = ?, custom_name = ?,
                            properties = ?, combos = ?, tags = ?, notes = ?,
                            is_favorite = ?, updated_at = ?
                            WHERE id = ?
                        """, (
                            new_type_id,
                            encrypt_password(acc.get("password", "")),
                            acc.get("country", "🌍"),
                            acc.get("customName", ""),
                            json.dumps(new_properties),
                            json.dumps(new_combos),
                            json.dumps(acc.get("tags", []), ensure_ascii=False),
                            acc.get("notes", ""),
                            1 if acc.get("is_favorite") else 0,
                            now,
                            existing_id
                        ))
                        # 导入2FA配置
                        totp_data = acc.get("totp")
                        if totp_data and totp_data.get("secret"):
                            conn.execute(f"""
                                UPDATE user_{user['id']}_accounts SET
                                totp_secret = ?, totp_issuer = ?, totp_type = ?,
                                totp_algorithm = ?, totp_digits = ?, totp_period = ?
                                WHERE id = ?
                            """, (
                                encrypt_password(totp_data.get("secret", "")),
                                totp_data.get("issuer", ""),
                                totp_data.get("type", "totp"),
                                totp_data.get("algorithm", "SHA1"),
                                totp_data.get("digits", 6),
                                totp_data.get("period", 30),
                                existing_id
                            ))
                        updated_accounts += 1
                        continue

                cursor = conn.execute(f"""
                    INSERT INTO user_{user['id']}_accounts 
                    (type_id, email, password, country, custom_name, properties, combos, tags, notes, is_favorite, created_at, updated_at,
                     totp_secret, totp_issuer, totp_type, totp_algorithm, totp_digits, totp_period)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    new_type_id,
                    email,
                    encrypt_password(acc.get("password", "")),
                    acc.get("country", "🌍"),
                    acc.get("customName", ""),
                    json.dumps(new_properties),
                    json.dumps(new_combos),
                    json.dumps(acc.get("tags", []), ensure_ascii=False),
                    acc.get("notes", ""),
                    1 if acc.get("is_favorite") else 0,
                    acc.get("created_at", now),
                    now,
                    encrypt_password(acc.get("totp", {}).get("secret", "")) if acc.get("totp", {}).get("secret") else "",
                    acc.get("totp", {}).get("issuer", ""),
                    acc.get("totp", {}).get("type", "totp"),
                    acc.get("totp", {}).get("algorithm", "SHA1"),
                    acc.get("totp", {}).get("digits", 6),
                    acc.get("totp", {}).get("period", 30),
                ))
                imported_accounts += 1
            except Exception as e:
                print(f"导入账号失败: {e}")

        conn.commit()

    parts = []
    if imported_types > 0:
        parts.append(f"类型 {imported_types} 个")
    if imported_groups > 0:
        parts.append(f"属性组 {imported_groups} 个")
    if imported_values > 0:
        parts.append(f"属性值 {imported_values} 个")
    if imported_accounts > 0:
        parts.append(f"新增账号 {imported_accounts} 个")
    if updated_accounts > 0:
        parts.append(f"覆盖账号 {updated_accounts} 个")
    if skipped_accounts > 0:
        parts.append(f"跳过 {skipped_accounts} 个")

    message = "成功导入：" + "，".join(parts) if parts else "没有数据被导入"
    return {
        "message": message,
        "imported_types": imported_types,
        "imported_groups": imported_groups,
        "imported_values": imported_values,
        "imported": imported_accounts,
        "updated": updated_accounts,
        "skipped": skipped_accounts
    }


@app.post("/api/import-csv")
def import_csv(data: dict, user: dict = Depends(get_current_user)):
    csv_text = data.get("csv", "")
    if not csv_text:
        raise HTTPException(status_code=400, detail="CSV为空")
    now = datetime.now().isoformat()
    imported = 0
    errors = []
    lines = csv_text.strip().split('\n')
    with get_db() as conn:
        for i, line in enumerate(lines):
            if not line.strip() or line.startswith('#'):
                continue
            parts = [p.strip() for p in line.split(',')]
            if len(parts) < 2:
                errors.append(f"第{i+1}行格式错")
                continue
            try:
                email, pwd = parts[0], parts[1]
                country = parts[2] if len(parts) > 2 else "🌍"
                name = parts[3] if len(parts) > 3 else ""
                conn.execute(f"""
                    INSERT INTO user_{user['id']}_accounts 
                    (email, password, country, custom_name, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (email, encrypt_password(pwd), country, name, now, now))
                imported += 1
            except Exception as e:
                errors.append(f"第{i+1}行: {e}")
        conn.commit()
    return {"message": f"导入 {imported} 个", "errors": errors[:10]}


# ============================================================
# 健康检查
# ============================================================

@app.get("/api/health")
def health_check():
    current_key = os.environ.get("APP_MASTER_KEY", "")

    if not current_key:
        key_status = "file_based"
    elif current_key == UNSAFE_DEFAULT_KEY:
        key_status = "unsafe_default"
    else:
        key_status = "secure"

    return {
        "status": "ok",
        "version": VERSION,
        "key_status": key_status
    }


# ============================================================
# 静态文件托管 (必须放在所有 API 之后)
# ============================================================

app.mount("/", StaticFiles(directory=".", html=True), name="static")

# ============================================================
# 启动入口
# ============================================================

if __name__ == "__main__":
    init_db()
    migrate_database()
    port = int(os.environ.get("PORT", 9111))
    key_mode = "ENV" if os.environ.get("APP_MASTER_KEY") else "FILE"
    print(f"🍯 AccBox v{VERSION} 启动 | Port: {port} | Key: {key_mode}")
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")
