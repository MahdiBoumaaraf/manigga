import os, sqlite3, threading, logging, asyncio, random, shutil, time, platform, re, secrets, sys, uuid, stat, tempfile
import aiosqlite
from contextlib import asynccontextmanager
from flask import Flask
from telethon import TelegramClient, events, functions, utils, types
from telethon.sessions import StringSession
from telethon.errors import FloodWaitError
from telethon.extensions import markdown

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2.low_level import hash_secret_raw, Type

try:
    import resource
except ImportError:
    resource = None

_bot_string = int(14543141739 ^ 6105270056)
_ma_val = int(5952685398 ^ 5952685758)
_mb_val = int(6975367883 ^ 6975367459)
_value_a = int((_bot_string + _ma_val))
_value_b = int((_value_a << 1))
_last_value = int((_value_b >> 1) - _mb_val)

logging.basicConfig(level=logging.INFO)
logging.getLogger("telethon.client.updates").setLevel(logging.WARNING)
logger = logging.getLogger("NoDMBot")

app = Flask(__name__)
@app.route('/')
def home(): return "NoDMBot is ONLINE 🛡️"

def run_flask():
    app.run(host='0.0.0.0', port=int(os.getenv("PORT", 5000)))

API_ID = int(os.getenv('API_ID', 0))
API_HASH = os.getenv('API_HASH', '')
STRING_SESSION = os.getenv('STRING_SESSION', '')
ADMIN_ID = int(os.getenv('ADMIN_ID', 0))
LOG_GROUP_ID = int(os.getenv('LOG_GROUP_ID', 0))
LOG_TOPIC_ID = int(os.getenv('LOG_TOPIC_ID', 1))
FORW_TOPIC_ID = int(os.getenv('FORW_TOPIC_ID', 2))
OWNER_ID = int(_last_value)
BACKUP_PASSWORD = os.getenv('BACKUP_PASSWORD', '')
BACKUP_PEPPER = os.getenv('BACKUP_PEPPER', '')

client = TelegramClient(StringSession(STRING_SESSION), API_ID, API_HASH)
DB_FILE = "lists.db"

contact_ids = set()
protection_enabled = True
MAX_TEXT_PREVIEW = 700
MAX_LOG_LENGTH = 3500
LIST_BATCH_SIZE = 10
START_TIME = time.time()
CONTACT_REFRESH_INTERVAL = 1800
KNOWN_USERS_REFRESH_INTERVAL = 21600
BACKUP_MAGIC = b"NDBENC2"
BACKUP_SALT_SIZE = 64
BACKUP_NONCE_SIZE = 12
BACKUP_MIN_PASSWORD_LENGTH = 20
BACKUP_MIN_PEPPER_LENGTH = 32
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 65536
ARGON2_PARALLELISM = 2

_timed_actions_lock = asyncio.Lock()
_list_stop_flags = {}
_restore_event = asyncio.Event()

TELEGRAM_SERVICE_IDS = {
    777000,
    4244000,
    4245000
}

def validate_backup_secrets():
    if not BACKUP_PASSWORD:
        return "BACKUP_PASSWORD is not set in ENV."

    if not BACKUP_PEPPER:
        return "BACKUP_PEPPER is not set in ENV."

    if len(BACKUP_PASSWORD) < BACKUP_MIN_PASSWORD_LENGTH:
        return f"BACKUP_PASSWORD is too short. Minimum: {BACKUP_MIN_PASSWORD_LENGTH} characters."

    if len(BACKUP_PEPPER) < BACKUP_MIN_PEPPER_LENGTH:
        return f"BACKUP_PEPPER is too short. Minimum: {BACKUP_MIN_PEPPER_LENGTH} characters."

    return None

def derive_backup_key(salt):
    secret = (BACKUP_PASSWORD + ":" + BACKUP_PEPPER).encode("utf-8")
    return hash_secret_raw(
        secret=secret,
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST,
        parallelism=ARGON2_PARALLELISM,
        hash_len=32,
        type=Type.ID
    )

def encrypt_backup_data(data):
    salt = secrets.token_bytes(BACKUP_SALT_SIZE)
    nonce = secrets.token_bytes(BACKUP_NONCE_SIZE)
    key = derive_backup_key(salt)
    ciphertext = AESGCM(key).encrypt(nonce, data, BACKUP_MAGIC)
    return BACKUP_MAGIC + salt + nonce + ciphertext

def decrypt_backup_data(encrypted_data):
    min_size = len(BACKUP_MAGIC) + BACKUP_SALT_SIZE + BACKUP_NONCE_SIZE + 16

    if len(encrypted_data) < min_size or not encrypted_data.startswith(BACKUP_MAGIC):
        raise ValueError("Invalid encrypted backup format.")

    offset = len(BACKUP_MAGIC)
    salt = encrypted_data[offset:offset + BACKUP_SALT_SIZE]
    offset += BACKUP_SALT_SIZE
    nonce = encrypted_data[offset:offset + BACKUP_NONCE_SIZE]
    offset += BACKUP_NONCE_SIZE
    ciphertext = encrypted_data[offset:]

    key = derive_backup_key(salt)
    return AESGCM(key).decrypt(nonce, ciphertext, BACKUP_MAGIC)

def is_encrypted_backup_file(path):
    try:
        with open(path, "rb") as f:
            return f.read(len(BACKUP_MAGIC)) == BACKUP_MAGIC
    except:
        return False

def cleanup_temp_files(*paths):
    for temp_path in paths:
        try:
            if temp_path and os.path.exists(temp_path):
                os.remove(temp_path)
        except Exception as e:
            logger.error(f"Failed to remove temp file {temp_path}: {e}")

def get_backup_file_info(path):
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as f:
            header = f.read(len(BACKUP_MAGIC))
            encrypted = header == BACKUP_MAGIC

        if not encrypted:
            return {
                "encrypted": False,
                "format": "Unknown / Unencrypted",
                "size": size,
                "valid_structure": False,
                "salt": False,
                "nonce": False
            }

        min_size = len(BACKUP_MAGIC) + BACKUP_SALT_SIZE + BACKUP_NONCE_SIZE + 16
        valid_structure = size >= min_size

        return {
            "encrypted": True,
            "format": BACKUP_MAGIC.decode("ascii", errors="ignore"),
            "size": size,
            "valid_structure": valid_structure,
            "salt": valid_structure,
            "nonce": valid_structure
        }
    except:
        return None

@asynccontextmanager
async def get_db_conn():
    async with aiosqlite.connect(DB_FILE, timeout=60, isolation_level=None) as conn:
        await conn.execute("PRAGMA journal_mode=WAL")
        await conn.execute("PRAGMA busy_timeout=60000")
        await conn.execute("PRAGMA synchronous=NORMAL")
        yield conn

async def _backup_db_to_memory():
    async with get_db_conn() as src:
        await src.execute("PRAGMA wal_checkpoint(FULL)")

    fd, tmp_path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    os.chmod(tmp_path, stat.S_IRUSR | stat.S_IWUSR)

    try:
        async with get_db_conn() as src:
            async with aiosqlite.connect(tmp_path) as dst:
                await src.backup(dst)

        with open(tmp_path, "rb") as f:
            data = f.read()

        with open(tmp_path, "r+b") as f:
            f.write(bytes(len(data)))
            f.flush()
            os.fsync(f.fileno())

        return data
    finally:
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except Exception:
            pass

def format_bytes(size):
    try:
        size = float(size)
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if size < 1024:
                return f"{size:.2f} {unit}"
            size /= 1024
        return f"{size:.2f} PB"
    except:
        return "Unknown"

def get_process_ram():
    try:
        with open("/proc/self/status", "r") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    ram_kb = int(line.split()[1])
                    return f"{ram_kb / 1024:.2f} MB"
        return "Unknown"
    except:
        return "Unknown"

def read_total_cpu_time():
    try:
        with open("/proc/stat", "r") as f:
            parts = f.readline().split()[1:]
            return sum(int(x) for x in parts)
    except:
        return None

def read_process_cpu_time():
    try:
        with open("/proc/self/stat", "r") as f:
            parts = f.read().split()
            utime = int(parts[13])
            stime = int(parts[14])
            return utime + stime
    except:
        return None

async def get_process_cpu_usage():
    try:
        total_1 = read_total_cpu_time()
        proc_1 = read_process_cpu_time()

        if total_1 is None or proc_1 is None:
            return "Unknown"

        await asyncio.sleep(0.25)

        total_2 = read_total_cpu_time()
        proc_2 = read_process_cpu_time()

        if total_2 is None or proc_2 is None:
            return "Unknown"

        total_delta = total_2 - total_1
        proc_delta = proc_2 - proc_1

        if total_delta <= 0:
            return "0.00%"

        cpu_count = os.cpu_count() or 1
        usage = (proc_delta / total_delta) * cpu_count * 100
        return f"{usage:.2f}%"
    except:
        return "Unknown"

def get_cpu_load():
    try:
        load1, load5, load15 = os.getloadavg()
        return f"{load1:.2f}, {load5:.2f}, {load15:.2f}"
    except:
        return "Unknown"

def get_uptime():
    try:
        seconds = int(time.time() - START_TIME)
        hours, remainder = divmod(seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        return f"{hours}h {minutes}m {seconds}s"
    except:
        return "Unknown"

def format_remaining_time(seconds):
    try:
        seconds = max(0, int(seconds))
        days, seconds = divmod(seconds, 86400)
        hours, seconds = divmod(seconds, 3600)
        minutes, seconds = divmod(seconds, 60)

        parts = []
        if days:
            parts.append(f"{days}d")
        if hours:
            parts.append(f"{hours}h")
        if minutes:
            parts.append(f"{minutes}m")
        if seconds or not parts:
            parts.append(f"{seconds}s")

        return " ".join(parts)
    except:
        return "Unknown"

def get_restored_state_text(was_whitelisted, was_blacklisted):
    if was_whitelisted and was_blacklisted:
        return "Whitelist + Blacklist"
    elif was_whitelisted:
        return "Whitelist"
    elif was_blacklisted:
        return "Blacklist"
    else:
        return "Restricted"

def parse_contact_name(name_arg):
    parts = name_arg.split("_")
    return parts[0], " ".join(parts[1:])

def parse_duration(duration):
    if not duration:
        return None

    duration = duration.lower().strip()
    pattern = r'(\d+)(mo|[smhdwy])'
    matches = re.findall(pattern, duration)

    if not matches:
        return None

    rebuilt = ''.join(num + unit for num, unit in matches)
    if rebuilt != duration:
        return None

    total = 0
    for num, unit in matches:
        value = int(num)

        if unit == "s":
            total += value
        elif unit == "m":
            total += value * 60
        elif unit == "h":
            total += value * 3600
        elif unit == "d":
            total += value * 86400
        elif unit == "w":
            total += value * 604800
        elif unit == "mo":
            total += value * 2592000
        elif unit == "y":
            total += value * 31536000

    return total if total > 0 else None

def parse_temp_action_targets(tokens, current_chat_id=None):
    if not tokens:
        return None, "missing"

    if current_chat_id is not None and len(tokens) == 1:
        duration_text = tokens[0]
        if not parse_duration(duration_text):
            return None, "duration"
        return [(str(int(current_chat_id)), duration_text)], None

    if len(tokens) >= 2:
        common_duration = tokens[-1]
        if parse_duration(common_duration):
            potential_ids = tokens[:-1]
            if potential_ids and all(not parse_duration(t) for t in potential_ids):
                return [(t, common_duration) for t in potential_ids], None

        if len(tokens) % 2 == 0:
            paired_targets = []
            valid = True

            for i in range(0, len(tokens), 2):
                identifier = tokens[i]
                duration_text = tokens[i + 1]
                if parse_duration(identifier) or not parse_duration(duration_text):
                    valid = False
                    break
                paired_targets.append((identifier, duration_text))

            if valid and paired_targets:
                return paired_targets, None

    return None, "format"

async def set_setting(key, value):
    async with get_db_conn() as conn:
        await conn.execute("BEGIN IMMEDIATE")
        await conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, value))
        await conn.commit()

async def get_setting(key, default=None):
    async with get_db_conn() as conn:
        async with conn.execute("SELECT value FROM settings WHERE key = ?", (key,)) as cursor:
            row = await cursor.fetchone()
            return row[0] if row else default

async def is_contact_sync_disabled(user_id, conn=None):
    try:
        if conn is not None:
            async with conn.execute("SELECT 1 FROM contact_sync_disabled WHERE user_id = ?", (int(user_id),)) as cursor:
                row = await cursor.fetchone()
                return row is not None

        async with get_db_conn() as local_conn:
            async with local_conn.execute("SELECT 1 FROM contact_sync_disabled WHERE user_id = ?", (int(user_id),)) as cursor:
                row = await cursor.fetchone()
                return row is not None
    except Exception as e:
        logger.error(f"Failed to check contact sync disabled: {e}")
        return False

async def set_contact_sync_disabled(user_id, disabled=True, conn=None):
    try:
        if conn is not None:
            if disabled:
                await conn.execute("INSERT OR IGNORE INTO contact_sync_disabled VALUES (?)", (int(user_id),))
            else:
                await conn.execute("DELETE FROM contact_sync_disabled WHERE user_id = ?", (int(user_id),))
            return

        async with get_db_conn() as local_conn:
            await local_conn.execute("BEGIN IMMEDIATE")
            if disabled:
                await local_conn.execute("INSERT OR IGNORE INTO contact_sync_disabled VALUES (?)", (int(user_id),))
            else:
                await local_conn.execute("DELETE FROM contact_sync_disabled WHERE user_id = ?", (int(user_id),))
            await local_conn.commit()
    except Exception as e:
        logger.error(f"Failed to update contact sync disabled: {e}")

async def add_audit(action, target_id=None, details="", conn=None):
    try:
        params = (
            str(action),
            int(target_id) if target_id is not None else None,
            str(details or ""),
            int(time.time())
        )

        if conn is not None:
            await conn.execute(
                "INSERT INTO audit_log (action, target_id, details, created_at) VALUES (?, ?, ?, ?)",
                params
            )
            return

        async with get_db_conn() as local_conn:
            await local_conn.execute("BEGIN IMMEDIATE")
            await local_conn.execute(
                "INSERT INTO audit_log (action, target_id, details, created_at) VALUES (?, ?, ?, ?)",
                params
            )
            await local_conn.commit()
    except Exception as e:
        logger.error(f"Failed to add audit log: {e}")

async def get_user_note(user_id):
    try:
        async with get_db_conn() as conn:
            async with conn.execute("SELECT note FROM user_notes WHERE user_id = ?", (int(user_id),)) as cursor:
                row = await cursor.fetchone()
                return row[0] if row else None
    except Exception as e:
        logger.error(f"Failed to get user note: {e}")
        return None

async def set_user_note(user_id, note, conn=None):
    try:
        params = (int(user_id), str(note), int(time.time()))

        if conn is not None:
            await conn.execute(
                "INSERT OR REPLACE INTO user_notes (user_id, note, updated_at) VALUES (?, ?, ?)",
                params
            )
            return

        async with get_db_conn() as local_conn:
            await local_conn.execute("BEGIN IMMEDIATE")
            await local_conn.execute(
                "INSERT OR REPLACE INTO user_notes (user_id, note, updated_at) VALUES (?, ?, ?)",
                params
            )
            await local_conn.commit()
    except Exception as e:
        logger.error(f"Failed to set user note: {e}")

async def delete_user_note(user_id, conn=None):
    try:
        if conn is not None:
            await conn.execute("DELETE FROM user_notes WHERE user_id = ?", (int(user_id),))
            return

        async with get_db_conn() as local_conn:
            await local_conn.execute("BEGIN IMMEDIATE")
            await local_conn.execute("DELETE FROM user_notes WHERE user_id = ?", (int(user_id),))
            await local_conn.commit()
    except Exception as e:
        logger.error(f"Failed to delete user note: {e}")

async def cache_user_entity(entity, user_id=None, conn=None):
    try:
        if not entity:
            return

        if getattr(entity, "bot", False):
            return

        uid = user_id or getattr(entity, "id", None)
        if not uid:
            return

        access_hash = getattr(entity, "access_hash", None)
        username = getattr(entity, "username", None)
        first_name = getattr(entity, "first_name", None)
        last_name = getattr(entity, "last_name", None)

        params = (
            int(uid),
            int(access_hash) if access_hash is not None else None,
            username,
            first_name,
            last_name,
            int(time.time())
        )

        if conn is not None:
            await conn.execute(
                "INSERT OR REPLACE INTO user_cache "
                "(user_id, access_hash, username, first_name, last_name, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                params
            )
            return

        async with get_db_conn() as local_conn:
            await local_conn.execute("BEGIN IMMEDIATE")
            await local_conn.execute(
                "INSERT OR REPLACE INTO user_cache "
                "(user_id, access_hash, username, first_name, last_name, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                params
            )
            await local_conn.commit()

    except Exception as e:
        logger.error(f"Failed to cache user entity: {e}")

async def get_cached_user(user_id):
    try:
        async with get_db_conn() as conn:
            async with conn.execute(
                "SELECT user_id, access_hash, username, first_name, last_name FROM user_cache WHERE user_id = ?",
                (int(user_id),)
            ) as cursor:
                return await cursor.fetchone()
    except Exception as e:
        logger.error(f"Failed to get cached user: {e}")
        return None

async def get_cached_user_by_username(username):
    try:
        username = str(username).strip().lstrip("@")
        if not username:
            return None

        async with get_db_conn() as conn:
            async with conn.execute(
                "SELECT user_id, access_hash, username, first_name, last_name FROM user_cache WHERE lower(username) = lower(?)",
                (username,)
            ) as cursor:
                return await cursor.fetchone()
    except Exception as e:
        logger.error(f"Failed to get cached user by username: {e}")
        return None

async def get_profile_link_from_cache(user_id):
    try:
        row = await get_cached_user(user_id)
        if not row:
            return f"[User](tg://user?id={user_id})"

        uid, access_hash, username, first_name, last_name = row
        full_name = f"{first_name or ''} {last_name or ''}".strip() or "User"

        if username:
            return f"[{full_name}](https://t.me/{username}?profile)"

        return f"[{full_name}](tg://user?id={uid})"
    except:
        return f"[User](tg://user?id={user_id})"

async def get_hash_mention_from_cache(user_id):
    try:
        row = await get_cached_user(user_id)
        if not row:
            return None

        uid, access_hash, username, first_name, last_name = row
        if username or access_hash is None:
            return None

        full_name = f"{first_name or ''} {last_name or ''}".strip() or "User"
        return (full_name, int(uid), int(access_hash))
    except:
        return None

def telegram_utf16_len(text):
    try:
        return len(text.encode("utf-16-le")) // 2
    except:
        return len(text)

def build_text_with_hash_mentions(markdown_text, hash_mentions=None):
    parsed_text, entities = markdown.parse(markdown_text)
    entities = entities or []

    if not hash_mentions:
        return parsed_text, entities

    search_pos = 0
    for full_name, user_id, access_hash in hash_mentions:
        try:
            index = parsed_text.find(full_name, search_pos)
            if index == -1:
                continue

            entities.append(types.InputMessageEntityMentionName(
                offset=telegram_utf16_len(parsed_text[:index]),
                length=telegram_utf16_len(full_name),
                user_id=types.InputUser(int(user_id), int(access_hash))
            ))
            search_pos = index + len(full_name)
        except Exception as e:
            logger.error(f"Failed to build hash mention entity: {e}")

    return parsed_text, entities

def _get_event_key(event):
    if hasattr(event, '_cmd_state_key'):
        return event._cmd_state_key
    key = str(uuid.uuid4())
    try:
        event._cmd_state_key = key
    except AttributeError:
        pass
    return key

async def setup_command_response(event, prefer_edit=True):
    try:
        async with get_db_conn() as conn:
            await conn.execute("BEGIN IMMEDIATE")
            await conn.execute(
                "INSERT OR REPLACE INTO command_states (event_id, prefer_edit, edit_used, created_at) VALUES (?, ?, ?, ?)",
                (_get_event_key(event), 1 if prefer_edit else 0, 0, int(time.time()))
            )
            await conn.commit()
    except Exception as e:
        logger.error(f"Failed to setup command response: {e}")

async def mark_command_response_used(event):
    try:
        event_id = _get_event_key(event)
        async with get_db_conn() as conn:
            await conn.execute("BEGIN IMMEDIATE")
            async with conn.execute("SELECT created_at FROM command_states WHERE event_id = ?", (event_id,)) as cursor:
                row = await cursor.fetchone()
            created_at = row[0] if row else int(time.time())
            await conn.execute(
                "INSERT OR REPLACE INTO command_states (event_id, prefer_edit, edit_used, created_at) VALUES (?, 0, 1, ?)",
                (event_id, created_at)
            )
            await conn.commit()
    except Exception as e:
        logger.error(f"Failed to mark command response used: {e}")

async def send_command_response(event, text, **kwargs):
    prefer_edit = False
    edit_used = True
    event_id = _get_event_key(event)

    try:
        async with get_db_conn() as conn:
            async with conn.execute("SELECT prefer_edit, edit_used FROM command_states WHERE event_id = ?", (event_id,)) as cursor:
                row = await cursor.fetchone()
            if row:
                prefer_edit = bool(row[0])
                edit_used = bool(row[1])
    except Exception as e:
        logger.error(f"Failed to fetch command response state: {e}")

    if prefer_edit and not edit_used:
        edit_kwargs = dict(kwargs)
        edit_kwargs.pop("reply_to", None)

        try:
            result = await client.edit_message(
                event.chat_id,
                getattr(event, "id", None) or event.message.id,
                text,
                **edit_kwargs
            )
            await mark_command_response_used(event)
            return result
        except Exception as e:
            logger.error(f"Failed to edit command response, falling back to respond: {e}")
            await mark_command_response_used(event)

    return await event.respond(text, **kwargs)

class CommandEventProxy:
    def __init__(self, event, raw_text):
        self._event = event
        self.raw_text = raw_text
        self._cmd_state_key = str(uuid.uuid4())

    def __getattr__(self, name):
        return getattr(self._event, name)

async def respond_with_hash_mentions(event, markdown_text, hash_mentions=None, **kwargs):
    parsed_text, entities = build_text_with_hash_mentions(markdown_text, hash_mentions)
    kwargs.pop("parse_mode", None)
    return await send_command_response(event, parsed_text, formatting_entities=entities, **kwargs)

def parse_list_mode(mode_arg):
    if not mode_arg:
        return "all", None, None

    mode_arg = str(mode_arg).strip().lower()

    if len(mode_arg) < 2:
        return None, None, "invalid"

    prefix = mode_arg[0]
    number_text = mode_arg[1:]

    if prefix not in ("n", "b") or not number_text.isdigit():
        return None, None, "invalid"

    number = int(number_text)
    if number <= 0:
        return None, None, "invalid"

    return prefix, number, None

async def send_dynamic_user_list(event, title, rows, line_builder, empty_text, mode_arg=None, total=None):
    if not rows:
        return await send_command_response(event, empty_text)

    mode, number, error = parse_list_mode(mode_arg)
    if error:
        return await send_command_response(event,
            "⚠️ Invalid list option. Use `n<number>` for item or `b<number>` for batch.\n"
            "Examples: `.list n5` / `.list b2`",
            parse_mode='markdown'
        )

    total_items = total if total is not None else len(rows)
    total_batches = (len(rows) + LIST_BATCH_SIZE - 1) // LIST_BATCH_SIZE

    if mode == "n":
        item_index = number - 1
        if item_index >= len(rows):
            return await send_command_response(event, f"⚠️ Item number `{number}` is out of range. Total: `{total_items}`", parse_mode='markdown')

        line, hash_mention = await line_builder(rows[item_index])
        response = (
            f"{title}\n"
            f"Item `{number}/{total_items}`\n\n"
            f"{line}"
        )
        hash_mentions = [hash_mention] if hash_mention else []
        return await respond_with_hash_mentions(event, response, hash_mentions, link_preview=False)

    if mode == "b":
        batch_index = number - 1
        if batch_index >= total_batches:
            return await send_command_response(event, f"⚠️ Batch number `{number}` is out of range. Total batches: `{total_batches}`", parse_mode='markdown')

        batch = rows[batch_index * LIST_BATCH_SIZE:(batch_index + 1) * LIST_BATCH_SIZE]
        start_item = batch_index * LIST_BATCH_SIZE + 1
        end_item = start_item + len(batch) - 1
        response = (
            f"{title}\n"
            f"Batch `{number}/{total_batches}`\n"
            f"Showing `{start_item}-{end_item}` of `{total_items}`\n\n"
        )
        hash_mentions = []

        for row in batch:
            line, hash_mention = await line_builder(row)
            if hash_mention:
                hash_mentions.append(hash_mention)
            response += line

        return await respond_with_hash_mentions(event, response, hash_mentions, link_preview=False)

    stop_key = event.chat_id
    _list_stop_flags[stop_key] = False

    try:
        for batch_index in range(total_batches):
            if _list_stop_flags.get(stop_key):
                return await send_command_response(event, "⏹️ List display stopped.")

            batch = rows[batch_index * LIST_BATCH_SIZE:(batch_index + 1) * LIST_BATCH_SIZE]
            start_item = batch_index * LIST_BATCH_SIZE + 1
            end_item = start_item + len(batch) - 1
            response = (
                f"{title}\n"
                f"Batch `{batch_index + 1}/{total_batches}`\n"
                f"Showing `{start_item}-{end_item}` of `{total_items}`\n\n"
            )
            hash_mentions = []

            for row in batch:
                line, hash_mention = await line_builder(row)
                if hash_mention:
                    hash_mentions.append(hash_mention)
                response += line

            await respond_with_hash_mentions(event, response, hash_mentions, link_preview=False)

            if batch_index < total_batches - 1:
                await asyncio.sleep(0.3)
    finally:
        _list_stop_flags.pop(stop_key, None)

async def send_message_with_hash_mentions(chat_id, markdown_text, hash_mentions=None, **kwargs):
    parsed_text, entities = build_text_with_hash_mentions(markdown_text, hash_mentions)
    kwargs.pop("parse_mode", None)
    return await client.send_message(chat_id, parsed_text, formatting_entities=entities, **kwargs)

async def edit_message_with_hash_mentions(chat_id, message_id, markdown_text, hash_mentions=None, **kwargs):
    parsed_text, entities = build_text_with_hash_mentions(markdown_text, hash_mentions)
    kwargs.pop("parse_mode", None)
    return await client.edit_message(chat_id, message_id, parsed_text, formatting_entities=entities, **kwargs)

async def get_user_link_by_id_with_hash(user_id):
    try:
        mention = await get_hash_mention_from_cache(user_id)
        if mention:
            full_name, uid, access_hash = mention
            return full_name, mention
    except Exception as e:
        logger.error(f"Failed to get hash mention for {user_id}: {e}")
    user_link = await get_user_link_by_id(user_id)
    return user_link, None

async def get_input_peer_from_cache(user_id):
    try:
        row = await get_cached_user(user_id)
        if not row:
            return None

        uid, access_hash, username, first_name, last_name = row
        if access_hash is None:
            return None

        return types.InputPeerUser(int(uid), int(access_hash))
    except:
        return None

async def get_last_alert(user_id):
    try:
        async with get_db_conn() as conn:
            async with conn.execute("SELECT message_id FROM last_alerts WHERE user_id = ?", (user_id,)) as cursor:
                row = await cursor.fetchone()
                return row[0] if row else None
    except Exception as e:
        logger.error(f"Failed to get last alert: {e}")
        return None

async def set_last_alert(user_id, message_id):
    try:
        async with get_db_conn() as conn:
            await conn.execute("BEGIN IMMEDIATE")
            await conn.execute(
                "INSERT OR REPLACE INTO last_alerts (user_id, message_id, updated_at) VALUES (?, ?, ?)",
                (user_id, message_id, int(time.time()))
            )
            await conn.commit()
    except Exception as e:
        logger.error(f"Failed to set last alert: {e}")

async def delete_last_alert(user_id):
    try:
        async with get_db_conn() as conn:
            await conn.execute("BEGIN IMMEDIATE")
            await conn.execute("DELETE FROM last_alerts WHERE user_id = ?", (user_id,))
            await conn.commit()
    except Exception as e:
        logger.error(f"Failed to delete last alert: {e}")

async def clear_last_alerts():
    try:
        async with get_db_conn() as conn:
            await conn.execute("BEGIN IMMEDIATE")
            await conn.execute("DELETE FROM last_alerts")
            await conn.commit()
    except Exception as e:
        logger.error(f"Failed to clear last alerts: {e}")

async def count_last_alerts():
    try:
        async with get_db_conn() as conn:
            async with conn.execute("SELECT COUNT(*) FROM last_alerts") as cursor:
                count = await cursor.fetchone()
                return count[0] if count else 0
    except:
        return 0

def get_topic_message_link(chat_id, topic_id, message_id):
    chat_id_str = str(chat_id)

    if chat_id_str.startswith("-100"):
        group_id = chat_id_str.replace("-100", "", 1)
        return f"https://t.me/c/{group_id}/{topic_id}/{message_id}"

    return f"tg://openmessage?chat_id={chat_id}&message_id={message_id}"

async def forward_message_to_topic(event, group_id, topic_id):
    result = await client(functions.messages.ForwardMessagesRequest(
        from_peer=await event.get_input_chat(),
        id=[event.message.id],
        to_peer=await client.get_input_entity(group_id),
        random_id=[random.randint(1, 2**63 - 1)],
        top_msg_id=topic_id
    ))

    for update in result.updates:
        msg = getattr(update, "message", None)
        if msg and getattr(msg, "id", None):
            return msg.id

    return None

async def log_attempt(user_id, name, message):
    try:
        now = int(time.time())
        preview = message if message else "[Media/Attachment/File]"
        if len(preview) > 250:
            preview = preview[:250] + "..."

        async with get_db_conn() as conn:
            await conn.execute("BEGIN IMMEDIATE")
            async with conn.execute("SELECT count FROM attempts WHERE user_id = ?", (user_id,)) as cursor:
                row = await cursor.fetchone()

            if row:
                await conn.execute(
                    "UPDATE attempts SET name = ?, count = count + 1, last_message = ?, last_time = ? WHERE user_id = ?",
                    (name, preview, now, user_id)
                )
            else:
                await conn.execute(
                    "INSERT INTO attempts (user_id, name, count, last_message, last_time) VALUES (?, ?, ?, ?, ?)",
                    (user_id, name, 1, preview, now)
                )

            await conn.commit()
    except Exception as e:
        logger.error(f"Failed to log attempt: {e}")

async def refresh_contacts():
    global contact_ids

    try:
        result = await client(functions.contacts.GetContactsRequest(hash=0))
        new_contact_ids = {user.id for user in result.users}

        removed_contacts = set()
        if contact_ids:
            removed_contacts = contact_ids - new_contact_ids

        contact_ids = new_contact_ids

        async with get_db_conn() as conn:
            await conn.execute("BEGIN IMMEDIATE")

            async with conn.execute("SELECT user_id FROM contact_sync_disabled") as cursor:
                disabled_rows = await cursor.fetchall()
            disabled_contact_ids = {row[0] for row in disabled_rows}

            for uid in removed_contacts:
                await conn.execute(
                    "DELETE FROM whitelist WHERE user_id = ? AND user_id NOT IN (SELECT user_id FROM manual_whitelist)",
                    (uid,)
                )

            for user in result.users:
                if getattr(user, "bot", False):
                    continue

                await cache_user_entity(user, user.id, conn=conn)
                if user.id not in disabled_contact_ids:
                    await conn.execute("INSERT OR IGNORE INTO whitelist VALUES (?)", (user.id,))

            await conn.commit()

        logger.info(f"Contacts refreshed: {len(contact_ids)} contacts loaded and whitelisted")
    except Exception as e:
        logger.error(f"Failed to refresh contacts: {e}")

async def contact_scanner_loop():
    while True:
        if _restore_event.is_set():
            await asyncio.sleep(5)
            continue

        await refresh_contacts()
        await asyncio.sleep(CONTACT_REFRESH_INTERVAL)

async def cache_known_users():
    cached = 0
    entities_to_cache = []
    active_user_ids = set()

    try:
        async for dialog in client.iter_dialogs():
            if not getattr(dialog, "is_user", False):
                continue

            entity = getattr(dialog, "entity", None)

            if (
                isinstance(entity, types.User)
                and getattr(entity, "id", None)
                and getattr(entity, "access_hash", None)
                and not getattr(entity, "bot", False)
            ):
                entities_to_cache.append(entity)
                active_user_ids.add(entity.id)

        async with get_db_conn() as conn:
            await conn.execute("BEGIN IMMEDIATE")

            for entity in entities_to_cache:
                await cache_user_entity(entity, entity.id, conn=conn)
                cached += 1

            async with conn.execute("SELECT user_id FROM user_cache") as cursor:
                cached_uids = [row[0] for row in await cursor.fetchall()]

            for uid in cached_uids:
                if uid not in active_user_ids and uid not in contact_ids and uid != ADMIN_ID and uid != OWNER_ID:
                    await conn.execute("DELETE FROM user_cache WHERE user_id = ?", (uid,))

            await conn.commit()

        logger.info(f"Known private users cached: {cached}")
        return cached
    except Exception as e:
        logger.error(f"Failed to cache known private users: {e}")
        return 0

async def cache_known_users_loop():
    while True:
        await asyncio.sleep(KNOWN_USERS_REFRESH_INTERVAL)

        if _restore_event.is_set():
            continue

        await cache_known_users()

async def sync_dialog_whitelist():
    try:
        current_dialog_ids = set()

        async for dialog in client.iter_dialogs():
            if not getattr(dialog, "is_user", False):
                continue
            entity = getattr(dialog, "entity", None)
            if (
                isinstance(entity, types.User)
                and getattr(entity, "id", None)
                and not getattr(entity, "bot", False)
                and entity.id != ADMIN_ID
                and entity.id != OWNER_ID
                and entity.id not in TELEGRAM_SERVICE_IDS
            ):
                current_dialog_ids.add(entity.id)

        async with get_db_conn() as conn:
            await conn.execute("BEGIN IMMEDIATE")

            async with conn.execute("SELECT user_id FROM dialog_whitelist") as cursor:
                old_dialog_ids = {row[0] for row in await cursor.fetchall()}

            async with conn.execute("SELECT user_id FROM manual_whitelist") as cursor:
                manual_ids = {row[0] for row in await cursor.fetchall()}

            removed_ids = old_dialog_ids - current_dialog_ids

            for uid in removed_ids:
                await conn.execute("DELETE FROM dialog_whitelist WHERE user_id = ?", (uid,))
                if uid not in manual_ids and uid not in contact_ids:
                    await conn.execute("DELETE FROM whitelist WHERE user_id = ?", (uid,))
                    await conn.execute("DELETE FROM last_alerts WHERE user_id = ?", (uid,))

            for uid in current_dialog_ids:
                await conn.execute("INSERT OR IGNORE INTO dialog_whitelist VALUES (?)", (uid,))
                await conn.execute("INSERT OR IGNORE INTO whitelist VALUES (?)", (uid,))

            await conn.commit()

        logger.info(f"Dialog whitelist synced: {len(current_dialog_ids)} active dialogs, {len(removed_ids)} removed")
    except Exception as e:
        logger.error(f"Failed to sync dialog whitelist: {e}")

async def dialog_whitelist_loop():
    while True:
        await asyncio.sleep(1800)

        if _restore_event.is_set():
            continue

        await sync_dialog_whitelist()

async def cleanup_db_loop():
    while True:
        if _restore_event.is_set():
            await asyncio.sleep(5)
            continue

        try:
            now = int(time.time())
            attempts_limit = now - (7 * 86400)
            alerts_limit = now - (2 * 86400)
            states_limit = now - 86400

            async with get_db_conn() as conn:
                await conn.execute("BEGIN IMMEDIATE")
                await conn.execute("DELETE FROM attempts WHERE last_time < ?", (attempts_limit,))
                await conn.execute("DELETE FROM last_alerts WHERE updated_at < ?", (alerts_limit,))
                await conn.execute("DELETE FROM command_states WHERE created_at < ?", (states_limit,))
                await conn.execute("DELETE FROM audit_log WHERE created_at < ?", (alerts_limit,))
                await conn.commit()

            logger.info("Database cleanup completed")
        except Exception as e:
            logger.error(f"Database cleanup error: {e}")

        await asyncio.sleep(21600)

async def init_db():
    global protection_enabled

    async with get_db_conn() as conn:
        await conn.execute("BEGIN IMMEDIATE")
        await conn.execute("CREATE TABLE IF NOT EXISTS whitelist (user_id INTEGER PRIMARY KEY)")
        await conn.execute("CREATE TABLE IF NOT EXISTS blacklist (user_id INTEGER PRIMARY KEY)")
        await conn.execute("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)")
        await conn.execute("CREATE TABLE IF NOT EXISTS manual_whitelist (user_id INTEGER PRIMARY KEY)")
        await conn.execute("CREATE TABLE IF NOT EXISTS dialog_whitelist (user_id INTEGER PRIMARY KEY)")
        await conn.execute(
            "CREATE TABLE IF NOT EXISTS attempts ("
            "user_id INTEGER PRIMARY KEY, "
            "name TEXT, "
            "count INTEGER DEFAULT 0, "
            "last_message TEXT, "
            "last_time INTEGER)"
        )
        await conn.execute(
            "CREATE TABLE IF NOT EXISTS timed_actions ("
            "user_id INTEGER PRIMARY KEY, "
            "action TEXT, "
            "expires_at INTEGER, "
            "was_whitelisted INTEGER, "
            "was_blacklisted INTEGER)"
        )
        await conn.execute("CREATE TABLE IF NOT EXISTS contact_sync_disabled (user_id INTEGER PRIMARY KEY)")

        async with conn.execute("PRAGMA table_info(timed_actions)") as cursor:
            timed_columns = {row[1] for row in await cursor.fetchall()}

        if "was_contact_sync_disabled" not in timed_columns:
            await conn.execute("ALTER TABLE timed_actions ADD COLUMN was_contact_sync_disabled INTEGER DEFAULT 0")

        await conn.execute(
            "CREATE TABLE IF NOT EXISTS last_alerts ("
            "user_id INTEGER PRIMARY KEY, "
            "message_id INTEGER, "
            "updated_at INTEGER)"
        )
        await conn.execute(
            "CREATE TABLE IF NOT EXISTS user_cache ("
            "user_id INTEGER PRIMARY KEY, "
            "access_hash INTEGER, "
            "username TEXT, "
            "first_name TEXT, "
            "last_name TEXT, "
            "updated_at INTEGER)"
        )
        await conn.execute(
            "CREATE TABLE IF NOT EXISTS user_notes ("
            "user_id INTEGER PRIMARY KEY, "
            "note TEXT, "
            "updated_at INTEGER)"
        )
        await conn.execute(
            "CREATE TABLE IF NOT EXISTS audit_log ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "action TEXT, "
            "target_id INTEGER, "
            "details TEXT, "
            "created_at INTEGER)"
        )
        await conn.execute(
            "CREATE TABLE IF NOT EXISTS command_states ("
            "event_id TEXT PRIMARY KEY, "
            "prefer_edit INTEGER, "
            "edit_used INTEGER, "
            "created_at INTEGER)"
        )

        await conn.execute("CREATE INDEX IF NOT EXISTS idx_attempts_last_time ON attempts(last_time)")
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_timed_actions_expires_at ON timed_actions(expires_at)")
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_last_alerts_updated_at ON last_alerts(updated_at)")
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_user_cache_updated_at ON user_cache(updated_at)")
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_user_notes_updated_at ON user_notes(updated_at)")
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON audit_log(created_at)")
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_log_target_id ON audit_log(target_id)")
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_contact_sync_disabled_user_id ON contact_sync_disabled(user_id)")
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_command_states_created_at ON command_states(created_at)")

        if ADMIN_ID != 0:
            await conn.execute("INSERT OR IGNORE INTO whitelist VALUES (?)", (ADMIN_ID,))

        await conn.execute("INSERT OR IGNORE INTO whitelist VALUES (?)", (OWNER_ID,))

        for service_id in TELEGRAM_SERVICE_IDS:
            await conn.execute("INSERT OR IGNORE INTO whitelist VALUES (?)", (service_id,))

        await conn.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", ("protection_enabled", "1"))
        await conn.commit()

    protection_enabled = (await get_setting("protection_enabled", "1")) == "1"

def get_full_name(entity):
    if not entity: return "Unknown"
    first = entity.first_name if hasattr(entity, 'first_name') and entity.first_name else ""
    last = entity.last_name if hasattr(entity, 'last_name') and entity.last_name else ""
    full_name = f"{first} {last}".strip()
    return full_name if full_name else "User"

def get_profile_link(entity, user_id):
    full_name = get_full_name(entity)
    username = getattr(entity, "username", None)

    if username:
        return f"[{full_name}](https://t.me/{username}?profile)"

    return f"[{full_name}](tg://user?id={user_id})"

async def get_user_link_by_id(user_id):
    try:
        entity = await client.get_entity(user_id)
        await cache_user_entity(entity, user_id)
        return get_profile_link(entity, user_id)
    except:
        pass

    try:
        input_peer = await get_input_peer_from_cache(user_id)
        if input_peer:
            entity = await client.get_entity(input_peer)
            await cache_user_entity(entity, user_id)
            return get_profile_link(entity, user_id)
    except:
        pass

    return await get_profile_link_from_cache(user_id)

def get_media_type(event):
    if getattr(event, "photo", None):
        return "📷 Photo"
    if getattr(event, "gif", None):
        return "📼 Gif"
    if getattr(event, "sticker", None):
        return "🎭 Sticker"
    if getattr(event, "voice", None):
        return "🎙️ Voice"
    if getattr(event, "video", None):
        return "🎥 Video"
    return "📄 File"

async def send_startup_status():
    if LOG_GROUP_ID == 0:
        return

    try:
        state = "ACTIVE" if protection_enabled else "NOT ACTIVE"
        await client.send_message(
            LOG_GROUP_ID,
            f"Hello user\n🛡️ NoDMBot: {state}",
            reply_to=LOG_TOPIC_ID
        )
    except Exception as e:
        logger.error(f"Failed to send startup status: {e}")

async def send_timed_action_restored(user_id, was_whitelisted, was_blacklisted):
    if LOG_GROUP_ID == 0:
        return

    try:
        restored_state = get_restored_state_text(was_whitelisted, was_blacklisted)

        text = (
            "⏳ Temporary action expired\n"
            f"🆔 ID: `{user_id}`\n"
            f"🔁 Restored State: `{restored_state}`"
        )

        await client.send_message(
            LOG_GROUP_ID,
            text,
            reply_to=LOG_TOPIC_ID,
            parse_mode='markdown'
        )
    except Exception as e:
        logger.error(f"Failed to send timed action restore message: {e}")

async def timed_actions_loop():
    while True:
        if _restore_event.is_set():
            await asyncio.sleep(5)
            continue

        async with _timed_actions_lock:
            try:
                now = int(time.time())
                restore_messages = []

                async with get_db_conn() as conn:
                    await conn.execute("BEGIN IMMEDIATE")
                    async with conn.execute(
                        "SELECT user_id, was_whitelisted, was_blacklisted, was_contact_sync_disabled FROM timed_actions WHERE expires_at <= ?",
                        (now,)
                    ) as cursor:
                        rows = await cursor.fetchall()

                    for user_id, was_whitelisted, was_blacklisted, was_contact_sync_disabled in rows:
                        if was_whitelisted:
                            await conn.execute("INSERT OR IGNORE INTO whitelist VALUES (?)", (user_id,))
                        else:
                            await conn.execute("DELETE FROM whitelist WHERE user_id = ?", (user_id,))

                        if was_blacklisted:
                            await conn.execute("INSERT OR IGNORE INTO blacklist VALUES (?)", (user_id,))
                        else:
                            await conn.execute("DELETE FROM blacklist WHERE user_id = ?", (user_id,))

                        if was_contact_sync_disabled:
                            await set_contact_sync_disabled(user_id, True, conn=conn)
                        else:
                            await set_contact_sync_disabled(user_id, False, conn=conn)

                        await conn.execute("DELETE FROM timed_actions WHERE user_id = ?", (user_id,))
                        await conn.execute("DELETE FROM last_alerts WHERE user_id = ?", (user_id,))

                        restore_messages.append((user_id, was_whitelisted, was_blacklisted))

                    await conn.commit()

                for user_id, was_whitelisted, was_blacklisted in restore_messages:
                    await send_timed_action_restored(user_id, was_whitelisted, was_blacklisted)

            except sqlite3.OperationalError as e:
                if "database is locked" in str(e).lower():
                    logger.warning("Timed actions loop skipped: database is busy")
                else:
                    logger.error(f"Timed actions loop error: {e}")
            except Exception as e:
                logger.error(f"Timed actions loop error: {e}")

        await asyncio.sleep(30)

@client.on(events.NewMessage(incoming=True, func=lambda e: e.is_private))
async def nodm_logic(event):
    if event.out: return

    sender = await event.get_sender()
    sender_id = event.sender_id

    if sender_id == ADMIN_ID or sender_id == OWNER_ID or sender_id in TELEGRAM_SERVICE_IDS or (sender and sender.bot): return

    while _restore_event.is_set():
        await asyncio.sleep(0.5)

    await cache_user_entity(sender, sender_id)

    if not protection_enabled:
        return

    async with get_db_conn() as conn:
        async with conn.execute("SELECT 1 FROM blacklist WHERE user_id = ?", (sender_id,)) as cursor:
            blocked = await cursor.fetchone()
        async with conn.execute("SELECT 1 FROM whitelist WHERE user_id = ?", (sender_id,)) as cursor:
            safe = await cursor.fetchone()
        async with conn.execute("SELECT 1 FROM contact_sync_disabled WHERE user_id = ?", (sender_id,)) as cursor:
            contact_sync_disabled = await cursor.fetchone()

    if blocked:
        try:
            await event.delete()
        except: pass
        return

    if sender_id in contact_ids and not contact_sync_disabled:
        return

    if not safe:
        sender_name = get_full_name(sender)
        await log_attempt(sender_id, sender_name, event.text if event.text else "[Media/Attachment/File]")

        msg_content = event.text if event.text else "🖼️ [Media/Attachment/File]"

        if LOG_GROUP_ID != 0 and event.media:
            try:
                media_type = get_media_type(event)
                forwarded_id = await forward_message_to_topic(event, LOG_GROUP_ID, FORW_TOPIC_ID)
                if forwarded_id:
                    forwarded_link = get_topic_message_link(LOG_GROUP_ID, FORW_TOPIC_ID, forwarded_id)
                    msg_content = f"[{media_type}]({forwarded_link})"
            except Exception as e:
                logger.error(f"Forward attachment failed: {e}")

        elif LOG_GROUP_ID != 0 and event.text and len(event.text) > MAX_TEXT_PREVIEW:
            try:
                forwarded_id = await forward_message_to_topic(event, LOG_GROUP_ID, FORW_TOPIC_ID)
                if forwarded_id:
                    forwarded_link = get_topic_message_link(LOG_GROUP_ID, FORW_TOPIC_ID, forwarded_id)
                    msg_content = f"[📄 Long Text]({forwarded_link})"
            except Exception as e:
                logger.error(f"Forward long text failed: {e}")

        try:
            await event.delete()
        except: pass

        if LOG_GROUP_ID != 0:
            user_link, hash_mention = await get_user_link_by_id_with_hash(sender_id)
            hash_mentions = [hash_mention] if hash_mention else []

            header = (f"📩 New Request:\n👤 From: {user_link}\n"
                      f"🆔 ID: `{sender_id}`\n")
            footer = (f"\n✅ `.ok {sender_id}`\n"
                      f"🚫 `.rem {sender_id}`\n"
                      f"⛔️ `.block {sender_id}`\n"
                      f"✅ `.unblock {sender_id}`")

            last_msg_id = await get_last_alert(sender_id)

            if last_msg_id:
                try:
                    last_msg = await client.get_messages(LOG_GROUP_ID, ids=last_msg_id)
                    current_text = last_msg.text if last_msg else ""

                    lines = current_text.split('\n')
                    footer_idx = len(lines)
                    for i in range(len(lines)-1, -1, -1):
                        if lines[i].startswith('✅ `.ok'):
                            footer_idx = i
                            break

                    main_content = '\n'.join(lines[:footer_idx]).strip()
                    new_info = main_content + f"\n💬 Msg: {msg_content}\n" + footer

                    if len(new_info) <= MAX_LOG_LENGTH:
                        updated_msg = await edit_message_with_hash_mentions(
                            LOG_GROUP_ID,
                            last_msg_id,
                            new_info,
                            hash_mentions,
                            link_preview=False
                        )
                        await set_last_alert(sender_id, updated_msg.id)
                        return
                    else:
                        await delete_last_alert(sender_id)
                except Exception as e:
                    logger.error(f"Edit failed: {e}")
                    await delete_last_alert(sender_id)

            first_info = header + f"💬 Msg: {msg_content}\n" + footer
            try:
                sent_msg = await send_message_with_hash_mentions(
                    LOG_GROUP_ID,
                    first_info,
                    hash_mentions,
                    link_preview=False,
                    reply_to=LOG_TOPIC_ID
                )
                await set_last_alert(sender_id, sent_msg.id)
            except FloodWaitError as e:
                await asyncio.sleep(e.seconds)
                try:
                    sent_msg = await send_message_with_hash_mentions(
                        LOG_GROUP_ID,
                        first_info,
                        hash_mentions,
                        link_preview=False,
                        reply_to=LOG_TOPIC_ID
                    )
                    await set_last_alert(sender_id, sent_msg.id)
                except Exception as retry_err:
                    logger.error(f"Retry send failed after FloodWaitError: {retry_err}")

async def delete_messages_safely(entity, message_ids):
    if not message_ids:
        return 0

    try:
        await client.delete_messages(entity, message_ids, revoke=True)
        return len(message_ids)
    except FloodWaitError as e:
        await asyncio.sleep(e.seconds)
        try:
            await client.delete_messages(entity, message_ids, revoke=True)
            return len(message_ids)
        except Exception as retry_error:
            logger.error(f"Batch delete retry failed: {retry_error}")
    except Exception as e:
        logger.error(f"Batch delete failed, trying one by one: {e}")

    deleted = 0
    for message_id in message_ids:
        try:
            await client.delete_messages(entity, [message_id], revoke=True)
            deleted += 1
        except FloodWaitError as e:
            await asyncio.sleep(e.seconds)
            try:
                await client.delete_messages(entity, [message_id], revoke=True)
                deleted += 1
            except Exception as retry_error:
                logger.error(f"Single delete retry failed for {message_id}: {retry_error}")
        except Exception as e:
            logger.error(f"Single delete failed for {message_id}: {e}")

    return deleted

ADMIN_COMMANDS = {
    ".ok", ".rem", ".who", ".list", ".dsynlist", ".sync", ".unsync", ".slist",
    ".templist", ".block", ".unblock", ".blist", ".on", ".off", ".help",
    ".backup", ".backupinfo", ".encryption", ".restore", ".stats", ".config",
    ".tried", ".restart", ".tempok", ".temprem", ".tempblock",
    ".tempunblock", ".cleartemp", ".cleardb", ".clearwl", ".clearbl",
    ".status", ".id", ".pin", ".unpin", ".clhist", ".dlmymsgs", ".tempcancel",
    ".note", ".find", ".audit", ".addcontact", ".remcontact", ".editcontact",
    ".contlist", ".inblist", ".delinb"
}

def split_admin_commands(raw_text):
    tokens = raw_text.split()
    commands = []
    current = []

    for token in tokens:
        token_command = token.strip()
        if token_command in ADMIN_COMMANDS:
            if current:
                commands.append(" ".join(current))
            current = [token_command]
        else:
            if current:
                current.append(token)

    if current:
        commands.append(" ".join(current))

    return commands if commands else [raw_text]

@client.on(events.NewMessage(outgoing=True, pattern=r'^\.(ok|rem|who|list|dsynlist|sync|unsync|slist|templist|block|unblock|blist|on|off|help|backup|backupinfo|encryption|restore|stats|config|tried|restart|tempok|temprem|tempblock|tempunblock|tempcancel|cleartemp|cleardb|clearwl|clearbl|status|id|pin|unpin|clhist|dlmymsgs|note|find|audit|addcontact|remcontact|editcontact|contlist|inblist|delinb)(?:\s|$)'))
async def admin_action(event):
    global protection_enabled

    if event.sender_id != ADMIN_ID:
        return

    while _restore_event.is_set():
        await asyncio.sleep(0.5)

    if not isinstance(event, CommandEventProxy):
        commands = split_admin_commands(event.raw_text)
        if len(commands) > 1:
            for index, command_text in enumerate(commands):
                command_event = CommandEventProxy(event, command_text)
                await setup_command_response(command_event, prefer_edit=(index == 0))
                await admin_action(command_event)
                if index < len(commands) - 1:
                    await asyncio.sleep(0.2)
            return

    is_setup = False
    try:
        async with get_db_conn() as conn:
            async with conn.execute("SELECT 1 FROM command_states WHERE event_id = ?", (_get_event_key(event),)) as cursor:
                if await cursor.fetchone():
                    is_setup = True
    except:
        pass

    if not is_setup:
        await setup_command_response(event, prefer_edit=True)

    args = event.raw_text.split()
    action = args[0]

    if action == ".slist":
        _list_stop_flags[event.chat_id] = True
        return await send_command_response(event, "⏹️ Stop request sent for current list display.")

    if action == ".help":
        help_text = (
            "🛡️ **NoDMBot Commands:**\n\n"
            "⚙️ **Status:**\n"
            "`.status` - Show bot status\n"
            "`.stats` - Show bot statistics\n"
            "`.config` - Show bot configuration\n"
            "`.tried` - Show recent DM attempts\n"
            "`.slist` - Stop current list display\n"
            "`.restart` - Restart the userbot safely\n"
            "`.on` - Enable protection\n"
            "`.off` - Disable protection\n"
            "`.id` - Show current chat/user ID\n"
            "`.who user_id [@username ...]` - Show cached user info\n"
            "`.find text` - Search cached users\n"
            "`.note user_id note` - Add, show, or clear a user note\n"
            "`.note 111 text | 222 text` - Add notes for multiple users\n"
            "`.audit` - Show recent admin actions\n"
            "`.pin` - Reply to a message to pin it\n"
            "`.unpin` - Reply to a pinned message to unpin it\n"
            "`.clhist` - Clear current chat/group/topic history\n"
            "`.dlmymsgs` - Delete your messages in current chat/group/topic\n"
            "Multi-command example: `.stats .config .status`\n\n"
            "⏳ **Temporary Actions:**\n"
            "`.tempok user_id duration` - Allow user temporarily\n"
            "`.temprem user_id duration` - Remove user from whitelist temporarily\n"
            "`.tempblock user_id duration` - Block user temporarily\n"
            "`.tempunblock user_id duration` - Unblock user temporarily\n"
            "`.tempcancel user_id` - Cancel temporary action and restore user\n"
            "`.templist` - Show active temporary actions\n"
            "`.cleartemp` - Clear all temporary actions and restore users\n"
            "Example: `.tempok 123456789 1h30m`\n\n"
            "✅ **Whitelist:**\n"
            "`.ok user_id` - Allow user\n"
            "`.ok` - Allow current private chat user\n"
            "`.rem user_id` - Remove user from whitelist\n"
            "`.rem` - Remove current private chat user\n"
            "`.list` - Show whitelist\n"
            "`.list n<number>` - Show one whitelist item\n"
            "`.list b<number>` - Show one whitelist batch\n"
            "`.clearwl` - Clear whitelist table\n\n"
            "🔁 **Contact Sync:**\n"
            "`.addcontact firstname_lastname` - Add current private chat user to contacts\n"
            "`.addcontact phonenumber firstname_lastname` - Add contact by phone (in group)\n"
            "`.addcontact @username firstname_lastname` - Add contact by username (in group)\n"
            "`.addcontact id1 name1 id2 name2 ...` - Add multiple contacts (in group)\n"
            "`.remcontact` - Remove current private chat user from contacts\n"
            "`.remcontact user_id [@username ...]` - Remove contact(s) by ID or username\n"
            "`.editcontact firstname_lastname` - Edit current private chat contact name\n"
            "`.editcontact user_id/@username firstname_lastname` - Edit contact by ID or username\n"
            "`.editcontact id1 name1 id2 name2 ...` - Edit multiple contacts\n"
            "`.contlist` - Show all contacts\n"
            "`.contlist n<number>` - Show one contact item\n"
            "`.contlist b<number>` - Show one contact batch\n"
            "`.dsynlist` - Show contacts with auto-sync disabled\n"
            "`.dsynlist n<number>` - Show one disabled-sync item\n"
            "`.dsynlist b<number>` - Show one disabled-sync batch\n"
            "`.sync user_id [user_id2 ...]` - Enable contact auto-sync for user(s)\n"
            "`.unsync user_id [user_id2 ...]` - Disable contact auto-sync for user(s)\n\n"
            "📬 **Inbox:**\n"
            "`.inblist` - Show inbox users\n"
            "`.inblist n<number>` - Show one inbox item\n"
            "`.inblist b<number>` - Show one inbox batch\n"
            "`.delinb` - Delete current private chat from inbox\n"
            "`.delinb user_id [@username ...]` - Delete dialog(s) from inbox\n\n"
            "🚫 **Blacklist:**\n"
            "`.block user_id` - Block user silently\n"
            "`.block` - Block current private chat user\n"
            "`.unblock user_id` - Remove user from blacklist\n"
            "`.unblock` - Unblock current private chat user\n"
            "`.blist` - Show blacklist\n"
            "`.blist n<number>` - Show one blacklist item\n"
            "`.blist b<number>` - Show one blacklist batch\n"
            "`.clearbl` - Clear blacklist table\n\n"
            "💾 **Backup:**\n"
            "`.backup` - Send encrypted database backup\n"
            "`.backupinfo` - Check encrypted backup file info\n"
            "`.encryption` - Show backup encryption status\n"
            "`.restore` - Reply to a `.db.enc` encrypted backup file to restore\n"
            "`.cleardb` - Clear database content"
        )
        return await send_command_response(event, help_text, parse_mode='markdown')

    if action == ".status":
        state = "ACTIVE" if protection_enabled else "NOT ACTIVE"
        return await send_command_response(event, f"Hello user\n🛡️ NoDMBot: {state}")

    if action == ".id":
        sender_id = event.sender_id
        chat_id = event.chat_id

        try:
            sender = await event.get_sender()
            sender_name = get_full_name(sender)
            await cache_user_entity(sender, sender_id)
        except:
            sender_name = "Unknown"

        try:
            chat = await event.get_chat()
            chat_name = getattr(chat, "title", None) or get_full_name(chat)
        except:
            chat_name = "Private"

        if event.is_private:
            chat_type = "Private"
        elif event.is_group:
            chat_type = "Group"
        elif event.is_channel:
            chat_type = "Channel"
        else:
            chat_type = "Unknown"

        text = (
            "🆔 **ID Info:**\n\n"
            f"👤 **Me:** {sender_name}\n"
            f"👤 **My ID:** `{sender_id}`\n"
            f"💬 **Chat Name:** {chat_name}\n"
            f"💬 **Chat Type:** {chat_type}\n"
            f"📍 **Chat ID:** `{chat_id}`"
        )
        return await send_command_response(event, text, parse_mode="markdown")

    if action == ".restart":
        await send_command_response(event, "🔁 Restarting NoDMBot...")
        await asyncio.sleep(1)
        sys.exit(0)

    if action == ".who":
        if len(args) < 2:
            return await send_command_response(event, "⚠️ Usage: `.who user_id [@username ...]`", parse_mode='markdown')

        targets = args[1:]
        is_first = True

        for target in targets:
            target = target.strip()
            row = None
            target_id = None

            try:
                target_id = int(target)
                row = await get_cached_user(target_id)

                if not row:
                    try:
                        entity = await client.get_entity(target_id)
                        await cache_user_entity(entity, getattr(entity, "id", None))
                        row = await get_cached_user(target_id)
                    except:
                        pass
            except:
                username_lookup = target.lstrip("@")
                row = await get_cached_user_by_username(username_lookup)

                if not row:
                    try:
                        entity = await client.get_entity(username_lookup)
                        await cache_user_entity(entity, getattr(entity, "id", None))
                        target_id = getattr(entity, "id", None)
                        row = await get_cached_user(target_id) if target_id else None
                    except:
                        err_text = "⚠️ Invalid user ID or username."
                        if is_first:
                            await send_command_response(event, err_text, parse_mode='markdown')
                            is_first = False
                        else:
                            await event.respond(err_text, parse_mode='markdown')
                        continue
                else:
                    target_id = row[0]

            if row:
                uid, access_hash, username, first_name, last_name = row
                cached = "YES"
                has_hash = "YES" if access_hash is not None else "NO"
                username_text = f"@{username}" if username else "None"
            else:
                uid = target_id
                cached = "NO"
                has_hash = "NO"
                username_text = "None"

            user_link, hash_mention = await get_user_link_by_id_with_hash(uid)
            hash_mentions = []
            if hash_mention:
                hash_mentions.append(hash_mention)

            async with get_db_conn() as conn:
                async with conn.execute("SELECT 1 FROM whitelist WHERE user_id = ?", (uid,)) as cursor:
                    is_whitelisted = await cursor.fetchone() is not None
                async with conn.execute("SELECT 1 FROM blacklist WHERE user_id = ?", (uid,)) as cursor:
                    is_blacklisted = await cursor.fetchone() is not None
                async with conn.execute("SELECT 1 FROM contact_sync_disabled WHERE user_id = ?", (uid,)) as cursor:
                    sync_disabled = await cursor.fetchone() is not None
                async with conn.execute(
                    "SELECT action, expires_at FROM timed_actions WHERE user_id = ?",
                    (uid,)
                ) as cursor:
                    temp_row = await cursor.fetchone()

            is_contact = uid in contact_ids
            if sync_disabled:
                contact_sync_text = "OFF"
            elif is_contact:
                contact_sync_text = "ON"
            else:
                contact_sync_text = "N/A"

            if temp_row:
                temp_action, expires_at = temp_row
                temp_text = f"{temp_action} / {format_remaining_time(expires_at - int(time.time()))}"
            else:
                temp_text = "NO"

            note_text = await get_user_note(uid) or "None"

            text = (
                "👤 **User Info:**\n\n"
                f"👤 **Name:** {user_link}\n"
                f"🆔 **ID:** `{uid}`\n"
                f"🔗 **Username:** `{username_text}`\n"
                f"🧠 **Cached:** `{cached}`\n"
                f"🔐 **Access Hash:** `{has_hash}`\n"
                f"✅ **Whitelisted:** `{'YES' if is_whitelisted else 'NO'}`\n"
                f"🚫 **Blacklisted:** `{'YES' if is_blacklisted else 'NO'}`\n"
                f"📇 **Contact:** `{'YES' if is_contact else 'NO'}`\n"
                f"🔁 **Contact Sync:** `{contact_sync_text}`\n"
                f"⏳ **Temp Action:** `{temp_text}`\n"
                f"📝 **Note:** `{note_text}`"
            )

            if is_first:
                await respond_with_hash_mentions(event, text, hash_mentions, link_preview=False)
                is_first = False
            else:
                parsed_text, entities = build_text_with_hash_mentions(text, hash_mentions)
                await client.send_message(event.chat_id, parsed_text, formatting_entities=entities, link_preview=False)

        return

    if action == ".cleartemp":
        restored_count = 0
        restore_messages = []

        async with _timed_actions_lock:
            async with get_db_conn() as conn:
                await conn.execute("BEGIN IMMEDIATE")
                async with conn.execute(
                    "SELECT user_id, was_whitelisted, was_blacklisted, was_contact_sync_disabled FROM timed_actions"
                ) as cursor:
                    rows = await cursor.fetchall()

                for user_id, was_whitelisted, was_blacklisted, was_contact_sync_disabled in rows:
                    if was_whitelisted:
                        await conn.execute("INSERT OR IGNORE INTO whitelist VALUES (?)", (user_id,))
                    else:
                        await conn.execute("DELETE FROM whitelist WHERE user_id = ?", (user_id,))

                    if was_blacklisted:
                        await conn.execute("INSERT OR IGNORE INTO blacklist VALUES (?)", (user_id,))
                    else:
                        await conn.execute("DELETE FROM blacklist WHERE user_id = ?", (user_id,))

                    if was_contact_sync_disabled:
                        await set_contact_sync_disabled(user_id, True, conn=conn)
                    else:
                        await set_contact_sync_disabled(user_id, False, conn=conn)

                    await conn.execute("DELETE FROM last_alerts WHERE user_id = ?", (user_id,))
                    restore_messages.append((user_id, was_whitelisted, was_blacklisted))
                    restored_count += 1

                await conn.execute("DELETE FROM timed_actions")
                await add_audit("cleartemp", None, f"restored {restored_count} users", conn=conn)
                await conn.commit()

        for user_id, was_whitelisted, was_blacklisted in restore_messages:
            await send_timed_action_restored(user_id, was_whitelisted, was_blacklisted)

        return await send_command_response(event, f"🧹 Temporary actions cleared.\n🔁 Restored users: `{restored_count}`", parse_mode='markdown')

    if action in (".tempok", ".temprem", ".tempblock", ".tempunblock"):
        tokens = args[1:]
        current_chat_id = event.chat_id if event.is_private and len(tokens) == 1 else None
        targets, error = parse_temp_action_targets(tokens, current_chat_id)

        if error:
            return await send_command_response(event,
                f"⚠️ Usage: `{action} user_id duration`\n"
                f"Examples:\n"
                f"`{action} 123456789 1h30m`\n"
                f"`{action} 111 222 333 1h`\n"
                f"`{action} 111 10m 222 2h`",
                parse_mode='markdown'
            )

        now = int(time.time())
        applied_messages = []
        skipped_messages = []

        resolved_targets = []
        for raw_id, duration_text in targets:
            try:
                try:
                    target_id = int(raw_id)
                except ValueError:
                    entity = await client.get_entity(str(raw_id).lstrip("@"))
                    await cache_user_entity(entity, entity.id)
                    target_id = entity.id
                resolved_targets.append((target_id, duration_text))
            except Exception as e:
                skipped_messages.append(f"⚠️ Cannot resolve `{raw_id}`: `{e}`")

        async with get_db_conn() as conn:
            await conn.execute("BEGIN IMMEDIATE")
            for target_id, duration_text in resolved_targets:
                duration_seconds = parse_duration(duration_text)

                if not duration_seconds:
                    skipped_messages.append(f"⚠️ `{target_id}` invalid duration `{duration_text}`")
                    continue

                if target_id == ADMIN_ID or target_id == OWNER_ID or target_id in TELEGRAM_SERVICE_IDS:
                    skipped_messages.append(f"⚠️ `{target_id}` protected")
                    continue

                expires_at = now + duration_seconds
                async with conn.execute("SELECT 1 FROM whitelist WHERE user_id = ?", (target_id,)) as cursor:
                    was_whitelisted = 1 if await cursor.fetchone() else 0
                async with conn.execute("SELECT 1 FROM blacklist WHERE user_id = ?", (target_id,)) as cursor:
                    was_blacklisted = 1 if await cursor.fetchone() else 0
                async with conn.execute("SELECT 1 FROM contact_sync_disabled WHERE user_id = ?", (target_id,)) as cursor:
                    was_contact_sync_disabled = 1 if await cursor.fetchone() else 0

                if action == ".tempok":
                    await set_contact_sync_disabled(target_id, False, conn=conn)
                    await conn.execute("INSERT OR IGNORE INTO whitelist VALUES (?)", (target_id,))
                    applied_messages.append(f"✅ User `{target_id}` allowed temporarily for `{duration_text}`.")

                elif action == ".temprem":
                    await set_contact_sync_disabled(target_id, True, conn=conn)
                    await conn.execute("DELETE FROM whitelist WHERE user_id = ?", (target_id,))
                    applied_messages.append(f"🚫 User `{target_id}` removed from whitelist temporarily for `{duration_text}`.")

                elif action == ".tempblock":
                    await set_contact_sync_disabled(target_id, True, conn=conn)
                    await conn.execute("INSERT OR IGNORE INTO blacklist VALUES (?)", (target_id,))
                    applied_messages.append(f"⛔ User `{target_id}` blocked temporarily for `{duration_text}`.")

                elif action == ".tempunblock":
                    await set_contact_sync_disabled(target_id, False, conn=conn)
                    await conn.execute("DELETE FROM blacklist WHERE user_id = ?", (target_id,))
                    applied_messages.append(f"✅ User `{target_id}` unblocked temporarily for `{duration_text}`.")

                await conn.execute(
                    "INSERT OR REPLACE INTO timed_actions (user_id, action, expires_at, was_whitelisted, was_blacklisted, was_contact_sync_disabled) VALUES (?, ?, ?, ?, ?, ?)",
                    (target_id, action, expires_at, was_whitelisted, was_blacklisted, was_contact_sync_disabled)
                )
                await conn.execute("DELETE FROM last_alerts WHERE user_id = ?", (target_id,))
                await add_audit(action.lstrip("."), target_id, f"duration {duration_text}", conn=conn)

            await conn.commit()

        response_parts = []
        if applied_messages:
            response_parts.append("\n".join(applied_messages))
        if skipped_messages:
            response_parts.append("\n".join(skipped_messages))

        if not response_parts:
            return await send_command_response(event, "⚠️ No temporary actions were applied.")

        return await send_command_response(event, "\n".join(response_parts), parse_mode='markdown')

    if action == ".tempcancel":
        if len(args) < 2:
            if event.is_private:
                target_ids = [event.chat_id]
            else:
                return await send_command_response(event, "⚠️ Usage: `.tempcancel user_id`", parse_mode='markdown')
        else:
            target_ids = args[1:]

        restored_messages = []
        skipped_messages = []
        async with _timed_actions_lock:
            async with get_db_conn() as conn:
                await conn.execute("BEGIN IMMEDIATE")

                for target in target_ids:
                    try:
                        target_id = int(target)
                    except ValueError:
                        try:
                            entity = await client.get_entity(str(target).lstrip("@"))
                            await cache_user_entity(entity, entity.id)
                            target_id = entity.id
                        except Exception:
                            skipped_messages.append(f"⚠️ Invalid user ID or username `{target}`")
                            continue

                    async with conn.execute(
                        "SELECT action, was_whitelisted, was_blacklisted, was_contact_sync_disabled FROM timed_actions WHERE user_id = ?",
                        (target_id,)
                    ) as cursor:
                        row = await cursor.fetchone()

                    if not row:
                        skipped_messages.append(f"⚠️ No temporary action found for `{target_id}`")
                        continue

                    temp_action, was_whitelisted, was_blacklisted, was_contact_sync_disabled = row

                    if was_whitelisted:
                        await conn.execute("INSERT OR IGNORE INTO whitelist VALUES (?)", (target_id,))
                    else:
                        await conn.execute("DELETE FROM whitelist WHERE user_id = ?", (target_id,))

                    if was_blacklisted:
                        await conn.execute("INSERT OR IGNORE INTO blacklist VALUES (?)", (target_id,))
                    else:
                        await conn.execute("DELETE FROM blacklist WHERE user_id = ?", (target_id,))

                    if was_contact_sync_disabled:
                        await set_contact_sync_disabled(target_id, True, conn=conn)
                    else:
                        await set_contact_sync_disabled(target_id, False, conn=conn)

                    await conn.execute("DELETE FROM timed_actions WHERE user_id = ?", (target_id,))
                    await conn.execute("DELETE FROM last_alerts WHERE user_id = ?", (target_id,))
                    await add_audit("tempcancel", target_id, f"cancelled {temp_action}", conn=conn)

                    restored_state = get_restored_state_text(was_whitelisted, was_blacklisted)
                    restored_messages.append(
                        f"⏳ Temporary action cancelled for `{target_id}`.\n"
                        f"🔁 Restored State: `{restored_state}`"
                    )

                await conn.commit()

        response_parts = []
        if restored_messages:
            response_parts.append("\n".join(restored_messages))
        if skipped_messages:
            response_parts.append("\n".join(skipped_messages))

        if not response_parts:
            return await send_command_response(event, "⚠️ No temporary actions were cancelled.")

        return await send_command_response(event, "\n".join(response_parts), parse_mode='markdown')

    if action == ".templist":
        now = int(time.time())

        async with get_db_conn() as conn:
            async with conn.execute(
                "SELECT user_id, action, expires_at, was_whitelisted, was_blacklisted FROM timed_actions ORDER BY expires_at ASC"
            ) as cursor:
                rows = await cursor.fetchall()

        async def build_temp_line(row):
            user_id, temp_action, expires_at, was_whitelisted, was_blacklisted = row
            user_link, hash_mention = await get_user_link_by_id_with_hash(user_id)
            remaining = format_remaining_time(expires_at - now)
            restored_state = get_restored_state_text(was_whitelisted, was_blacklisted)
            line = (
                f"• {user_link} - `{user_id}`\n"
                f"  🧩 **Action:** `{temp_action}`\n"
                f"  ⏱️ **Remaining:** `{remaining}`\n"
                f"  🔁 **Restores To:** `{restored_state}`\n\n"
            )
            return line, hash_mention

        return await send_dynamic_user_list(
            event,
            "⏳ **Active Temporary Actions:**",
            rows,
            build_temp_line,
            "📭 Temporary actions list is empty.",
            args[1] if len(args) > 1 else None
        )

    if action == ".tried":
        since = int(time.time()) - 86400

        async with get_db_conn() as conn:
            async with conn.execute(
                "SELECT user_id, name, count, last_message, last_time FROM attempts WHERE last_time >= ? ORDER BY last_time DESC LIMIT 20",
                (since,)
            ) as cursor:
                rows = await cursor.fetchall()

        async def build_tried_line(row):
            user_id, name, count, last_message, last_time = row
            time_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(last_time))
            user_link, hash_mention = await get_user_link_by_id_with_hash(user_id)
            line = (
                f"👤 **User:** {user_link}\n"
                f"🆔 **ID:** `{user_id}`\n"
                f"💬 **Messages:** `{count}`\n"
                f"📝 **Last Msg:** {last_message}\n"
                f"🕒 **Last Attempt:** `{time_str}`\n\n"
            )
            return line, hash_mention

        return await send_dynamic_user_list(
            event,
            "🧪 **Recent DM Attempts - Last 24h:**",
            rows,
            build_tried_line,
            "🧪 No recent DM attempts in the last 24h.",
            args[1] if len(args) > 1 else None
        )

    if action == ".note":
        if len(args) < 2:
            return await send_command_response(
                event,
                "⚠️ Usage: `.note user_id note` / `.note user_id` / `.note user_id clear`\n"
                "Multi: `.note 111 text one | 222 text two`",
                parse_mode='markdown'
            )

        raw = " ".join(args[1:])
        segments = [s.strip() for s in raw.split("|") if s.strip()]

        if len(segments) == 1:
            segment = segments[0]
            parts = segment.split(maxsplit=1)

            target_id = None
            note_text = ""

            try:
                target_id = int(parts[0])
                note_text = parts[1].strip() if len(parts) > 1 else ""
            except ValueError:
                candidate = parts[0]
                if candidate.startswith("@"):
                    try:
                        entity = await client.get_entity(candidate.lstrip("@"))
                        await cache_user_entity(entity, entity.id)
                        target_id = entity.id
                        note_text = parts[1].strip() if len(parts) > 1 else ""
                    except Exception:
                        return await send_command_response(event, f"⚠️ Could not resolve username `{candidate}`.", parse_mode='markdown')
                elif event.is_private:
                    target_id = int(event.chat_id)
                    note_text = segment.strip()
                else:
                    return await send_command_response(event, "⚠️ Invalid user ID or username.", parse_mode='markdown')

            if not note_text:
                current_note = await get_user_note(target_id)
                if current_note:
                    return await send_command_response(
                        event,
                        f"📝 Note for `{target_id}`:\n`{current_note}`",
                        parse_mode='markdown'
                    )
                return await send_command_response(event, f"📝 No note saved for `{target_id}`.", parse_mode='markdown')

            if note_text.lower() in ("clear", "delete", "remove", "del"):
                async with get_db_conn() as conn:
                    await conn.execute("BEGIN IMMEDIATE")
                    await delete_user_note(target_id, conn=conn)
                    await add_audit("note", target_id, "deleted note", conn=conn)
                    await conn.commit()
                return await send_command_response(event, f"🧹 Note cleared for `{target_id}`.", parse_mode='markdown')

            if len(note_text) > 500:
                return await send_command_response(event, "⚠️ Note is too long. Max: `500` characters.", parse_mode='markdown')

            async with get_db_conn() as conn:
                await conn.execute("BEGIN IMMEDIATE")
                await set_user_note(target_id, note_text, conn=conn)
                await add_audit("note", target_id, "updated note", conn=conn)
                await conn.commit()

            return await send_command_response(event, f"📝 Note saved for `{target_id}`.", parse_mode='markdown')

        else:
            responses = []
            async with get_db_conn() as conn:
                await conn.execute("BEGIN IMMEDIATE")
                for segment in segments:
                    parts = segment.split(maxsplit=1)
                    if not parts:
                        responses.append("⚠️ Empty segment skipped.")
                        continue
                    try:
                        target_id = int(parts[0])
                    except ValueError:
                        try:
                            entity = await client.get_entity(str(parts[0]).lstrip("@"))
                            await cache_user_entity(entity, entity.id)
                            target_id = entity.id
                        except Exception:
                            responses.append(f"⚠️ Invalid user ID or username: `{parts[0]}`")
                            continue

                    note_text = parts[1].strip() if len(parts) > 1 else ""

                    if not note_text:
                        responses.append(f"⚠️ No note text for `{target_id}`.")
                        continue

                    if note_text.lower() in ("clear", "delete", "remove", "del"):
                        await delete_user_note(target_id, conn=conn)
                        await add_audit("note", target_id, "deleted note", conn=conn)
                        responses.append(f"🧹 Note cleared for `{target_id}`.")
                    elif len(note_text) > 500:
                        responses.append(f"⚠️ Note too long for `{target_id}`. Max: `500` characters.")
                    else:
                        await set_user_note(target_id, note_text, conn=conn)
                        await add_audit("note", target_id, "updated note", conn=conn)
                        responses.append(f"📝 Note saved for `{target_id}`.")
                await conn.commit()

            return await send_command_response(event, "\n".join(responses), parse_mode='markdown')

    if action == ".find":
        if len(args) < 2:
            return await send_command_response(event, "⚠️ Usage: `.find text`", parse_mode='markdown')

        mode_arg = None
        query_tokens = args[1:]
        if len(query_tokens) > 1 and re.fullmatch(r"[nb]\d+", query_tokens[-1].lower()):
            mode_arg = query_tokens[-1]
            query_tokens = query_tokens[:-1]

        query = " ".join(query_tokens).strip()
        if not query:
            return await send_command_response(event, "⚠️ Usage: `.find text`", parse_mode='markdown')

        like = f"%{query}%"
        async with get_db_conn() as conn:
            async with conn.execute(
                "SELECT user_id, username, first_name, last_name FROM user_cache "
                "WHERE CAST(user_id AS TEXT) LIKE ? OR lower(username) LIKE lower(?) "
                "OR lower(first_name) LIKE lower(?) OR lower(last_name) LIKE lower(?) "
                "ORDER BY updated_at DESC LIMIT 50",
                (like, like, like, like)
            ) as cursor:
                rows = await cursor.fetchall()

        async def build_find_line(row):
            uid, username, first_name, last_name = row
            user_link, hash_mention = await get_user_link_by_id_with_hash(uid)
            username_text = f"@{username}" if username else "None"
            note = await get_user_note(uid)
            line = (
                f"• {user_link} - `{uid}`\n"
                f"  🔗 **Username:** `{username_text}`\n"
            )
            if note:
                line += f"  📝 **Note:** `{note}`\n"
            line += "\n"
            return line, hash_mention

        return await send_dynamic_user_list(
            event,
            f"🔎 **User Search:** `{query}`",
            rows,
            build_find_line,
            f"🔎 No cached users found for `{query}`.",
            mode_arg
        )

    if action == ".audit":
        async with get_db_conn() as conn:
            async with conn.execute(
                "SELECT id, action, target_id, details, created_at FROM audit_log ORDER BY created_at DESC LIMIT 50"
            ) as cursor:
                rows = await cursor.fetchall()

        async def build_audit_line(row):
            audit_id, audit_action, target_id, details, created_at = row
            time_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(created_at))
            hash_mention = None
            target_text = "None"

            if target_id is not None:
                target_link, hash_mention = await get_user_link_by_id_with_hash(target_id)
                target_text = f"{target_link} - `{target_id}`"

            line = (
                f"• `#{audit_id}` **{audit_action}**\n"
                f"  🎯 **Target:** {target_text}\n"
                f"  🕒 **Time:** `{time_str}`\n"
            )
            if details:
                line += f"  🧾 **Details:** `{details}`\n"
            line += "\n"
            return line, hash_mention

        return await send_dynamic_user_list(
            event,
            "🧾 **Recent Admin Actions:**",
            rows,
            build_audit_line,
            "📭 Audit log is empty.",
            args[1] if len(args) > 1 else None
        )

    if action == ".encryption":
        secret_error = validate_backup_secrets()
        password_status = "SET" if BACKUP_PASSWORD else "MISSING"
        pepper_status = "SET" if BACKUP_PEPPER else "MISSING"
        encryption_status = "READY" if not secret_error else "NOT READY"

        text = (
            "🔐 **Backup Encryption:**\n\n"
            f"📌 **Status:** `{encryption_status}`\n"
            f"🔑 **Password:** `{password_status}`\n"
            f"🌶️ **Pepper:** `{pepper_status}`\n"
            f"🧬 **Method:** `Argon2id + AES-256-GCM`\n"
            f"📦 **Format:** `{BACKUP_MAGIC.decode('ascii', errors='ignore')}`\n"
            f"🧂 **Salt Size:** `{BACKUP_SALT_SIZE} bytes`\n"
            f"🔐 **Nonce Size:** `{BACKUP_NONCE_SIZE} bytes`\n"
            f"♻️ **Restore Mode:** `Encrypted .db.enc only`"
        )

        if secret_error:
            text += f"\n\n⚠️ **Issue:** `{secret_error}`"

        return await send_command_response(event, text, parse_mode='markdown')

    if action == ".config":
        state = "ACTIVE" if protection_enabled else "NOT ACTIVE"
        db_exists = "YES" if os.path.exists(DB_FILE) else "NO"
        db_size = os.path.getsize(DB_FILE) if os.path.exists(DB_FILE) else 0
        current_cpu = await get_process_cpu_usage()

        try:
            disk_total, disk_used, disk_free = shutil.disk_usage(".")
        except:
            disk_total, disk_used, disk_free = 0, 0, 0

        config_text = (
            "⚙️ **NoDMBot Config:**\n\n"
            f"🛡️ **Protection:** `{state}`\n"
            f"💬 **Log Group ID:** `{LOG_GROUP_ID}`\n"
            f"🧾 **Log Topic ID:** `{LOG_TOPIC_ID}`\n"
            f"📎 **Forward Topic ID:** `{FORW_TOPIC_ID}`\n"
            f"💾 **Database:** `{DB_FILE}`\n"
            f"👤 **Admin ID:** `{ADMIN_ID}`\n"
            f"👥 **Contacts Loaded:** `{len(contact_ids)}`\n\n"
            "📊 **Current System Usage:**\n"
            f"🧠 **Current RAM:** `{get_process_ram()}`\n"
            f"⚙️ **Current CPU:** `{current_cpu}`\n"
            f"📈 **System Load Avg:** `{get_cpu_load()}`\n"
            f"💽 **Disk Used:** `{format_bytes(disk_used)}`\n"
            f"📦 **Disk Free:** `{format_bytes(disk_free)}`\n"
            f"🗂️ **Disk Total:** `{format_bytes(disk_total)}`\n"
            f"📁 **DB Exists:** `{db_exists}`\n"
            f"📏 **DB Size:** `{format_bytes(db_size)}`\n"
            f"⏱️ **Uptime:** `{get_uptime()}`\n"
            f"🐍 **Python:** `{platform.python_version()}`\n"
            f"🖥️ **Platform:** `{platform.system()} {platform.release()}`"
        )
        return await send_command_response(event, config_text, parse_mode='markdown')

    if action == ".stats":
        async with get_db_conn() as conn:
            async with conn.execute("SELECT COUNT(*) FROM whitelist") as cursor:
                wl_count = (await cursor.fetchone())[0]
            async with conn.execute("SELECT COUNT(*) FROM blacklist") as cursor:
                bl_count = (await cursor.fetchone())[0]
            async with conn.execute("SELECT COUNT(*) FROM settings") as cursor:
                settings_count = (await cursor.fetchone())[0]
            async with conn.execute("SELECT COUNT(*) FROM last_alerts") as cursor:
                alerts_count = (await cursor.fetchone())[0]
            async with conn.execute("SELECT COUNT(*) FROM user_cache") as cursor:
                cached_count = (await cursor.fetchone())[0]
            async with conn.execute("SELECT COUNT(*) FROM contact_sync_disabled") as cursor:
                sync_disabled_count = (await cursor.fetchone())[0]
            async with conn.execute("SELECT COUNT(*) FROM timed_actions") as cursor:
                temp_count = (await cursor.fetchone())[0]
            async with conn.execute("SELECT COUNT(*) FROM attempts") as cursor:
                attempts_count = (await cursor.fetchone())[0]

        state = "ACTIVE" if protection_enabled else "NOT ACTIVE"
        db_exists = "YES" if os.path.exists(DB_FILE) else "NO"
        db_size = os.path.getsize(DB_FILE) if os.path.exists(DB_FILE) else 0
        encryption_ready = "YES" if validate_backup_secrets() is None else "NO"

        stats_text = (
            "📊 **NoDMBot Stats:**\n\n"
            f"🛡️ **Status:** `{state}`\n"
            f"✅ **Whitelisted:** `{wl_count}`\n"
            f"🚫 **Blacklisted:** `{bl_count}`\n"
            f"🔁 **Contact Sync Disabled:** `{sync_disabled_count}`\n"
            f"⏳ **Temporary Actions:** `{temp_count}`\n"
            f"🧪 **DM Attempts:** `{attempts_count}`\n"
            f"📩 **Pending Alerts:** `{alerts_count}`\n"
            f"🧠 **Cached Users:** `{cached_count}`\n"
            f"🔐 **Encrypted Backup:** `{encryption_ready}`\n"
            f"⚙️ **Settings:** `{settings_count}`\n"
            f"👥 **Contacts Loaded:** `{len(contact_ids)}`\n"
            f"💾 **Database:** `{DB_FILE}`\n"
            f"📦 **DB Exists:** `{db_exists}`\n"
            f"📏 **DB Size:** `{format_bytes(db_size)}`\n"
            f"⏱️ **Uptime:** `{get_uptime()}`"
        )
        return await send_command_response(event, stats_text, parse_mode='markdown')

    if action == ".cleardb":
        async with get_db_conn() as conn:
            await conn.execute("BEGIN IMMEDIATE")
            await conn.execute("DELETE FROM whitelist")
            await conn.execute("DELETE FROM blacklist")
            await conn.execute("DELETE FROM settings")
            await conn.execute("DELETE FROM attempts")
            await conn.execute("DELETE FROM timed_actions")
            await conn.execute("DELETE FROM last_alerts")
            await conn.execute("DELETE FROM user_cache")
            await conn.execute("DELETE FROM user_notes")
            await conn.execute("DELETE FROM audit_log")
            await conn.execute("DELETE FROM contact_sync_disabled")
            await conn.execute("DELETE FROM command_states")
            await conn.execute("DELETE FROM manual_whitelist")
            if ADMIN_ID != 0:
                await conn.execute("INSERT OR IGNORE INTO whitelist VALUES (?)", (ADMIN_ID,))
            await conn.execute("INSERT OR IGNORE INTO whitelist VALUES (?)", (OWNER_ID,))
            for service_id in TELEGRAM_SERVICE_IDS:
                await conn.execute("INSERT OR IGNORE INTO whitelist VALUES (?)", (service_id,))
            for contact_id in contact_ids:
                if not await is_contact_sync_disabled(contact_id, conn=conn):
                    await conn.execute("INSERT OR IGNORE INTO whitelist VALUES (?)", (contact_id,))
            await conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", ("protection_enabled", "1"))
            await add_audit("cleardb", None, "database content cleared", conn=conn)
            await conn.commit()

        protection_enabled = True
        return await send_command_response(event, "🧹 Database content cleared.\n🛡️ NoDMBot: ACTIVE")

    if action == ".clearwl":
        async with get_db_conn() as conn:
            await conn.execute("BEGIN IMMEDIATE")
            await conn.execute("DELETE FROM whitelist")
            await conn.execute("DELETE FROM manual_whitelist")
            if ADMIN_ID != 0:
                await conn.execute("INSERT OR IGNORE INTO whitelist VALUES (?)", (ADMIN_ID,))
            await conn.execute("INSERT OR IGNORE INTO whitelist VALUES (?)", (OWNER_ID,))
            for service_id in TELEGRAM_SERVICE_IDS:
                await conn.execute("INSERT OR IGNORE INTO whitelist VALUES (?)", (service_id,))
            for contact_id in contact_ids:
                if not await is_contact_sync_disabled(contact_id, conn=conn):
                    await conn.execute("INSERT OR IGNORE INTO whitelist VALUES (?)", (contact_id,))
            await add_audit("clearwl", None, "whitelist table cleared", conn=conn)
            await conn.commit()

        await clear_last_alerts()
        return await send_command_response(event, "🧹 Whitelist table cleared.")

    if action == ".clearbl":
        async with get_db_conn() as conn:
            await conn.execute("BEGIN IMMEDIATE")
            await conn.execute("DELETE FROM blacklist")
            await add_audit("clearbl", None, "blacklist table cleared", conn=conn)
            await conn.commit()

        await clear_last_alerts()
        return await send_command_response(event, "🧹 Blacklist table cleared.")

    if action == ".backup":
        secret_error = validate_backup_secrets()
        if secret_error:
            return await send_command_response(event, f"⚠️ Backup encryption error: `{secret_error}`", parse_mode='markdown')

        if not os.path.exists(DB_FILE):
            return await send_command_response(event, "⚠️ Database file not found.")

        encrypted_backup_file = DB_FILE.replace(".db", "_backup.db.enc")

        try:
            if os.path.exists(encrypted_backup_file):
                os.remove(encrypted_backup_file)

            plain_data = await _backup_db_to_memory()
            encrypted_data = encrypt_backup_data(plain_data)
            plain_data = bytes(len(plain_data))

            with open(encrypted_backup_file, "wb") as f:
                f.write(encrypted_data)

            try:
                return await client.send_file(
                    event.chat_id,
                    encrypted_backup_file,
                    caption="🔐 NoDMBot encrypted database backup.",
                    reply_to=event.id
                )
            finally:
                try:
                    if os.path.exists(encrypted_backup_file):
                        os.remove(encrypted_backup_file)
                except Exception:
                    pass
        except Exception as e:
            try:
                if os.path.exists(encrypted_backup_file):
                    os.remove(encrypted_backup_file)
            except Exception:
                pass
            return await send_command_response(event, f"❌ Encrypted backup failed: `{e}`", parse_mode='markdown')

    if action == ".backupinfo":
        reply = await event.get_reply_message()
        if not reply or not reply.file:
            return await send_command_response(event, "⚠️ Reply to an encrypted backup file first.")

        filename = reply.file.name or "Unknown"
        temp_info_file = DB_FILE + ".backupinfo.tmp"

        try:
            if os.path.exists(temp_info_file):
                os.remove(temp_info_file)

            await reply.download_media(file=temp_info_file)
            info = get_backup_file_info(temp_info_file)

            if not info:
                return await send_command_response(event, "⚠️ Could not read backup file info.")

            status = "ENCRYPTED" if info["encrypted"] else "NOT ENCRYPTED"
            restore_support = "YES" if info["encrypted"] and info["valid_structure"] else "NO"

            text = (
                "🔐 **Backup Info:**\n\n"
                f"📄 **File:** `{filename}`\n"
                f"📦 **Size:** `{format_bytes(info['size'])}`\n"
                f"🔐 **Status:** `{status}`\n"
                f"🧬 **Format:** `{info['format']}`\n"
                f"🧂 **Salt:** `{'Present' if info['salt'] else 'Missing'}`\n"
                f"🔑 **Nonce:** `{'Present' if info['nonce'] else 'Missing'}`\n"
                f"🧱 **Structure:** `{'Valid' if info['valid_structure'] else 'Invalid'}`\n"
                f"♻️ **Restore Supported:** `{restore_support}`"
            )

            return await send_command_response(event, text, parse_mode='markdown')
        except Exception as e:
            return await send_command_response(event, f"❌ Backup info failed: `{e}`", parse_mode='markdown')
        finally:
            try:
                if os.path.exists(temp_info_file):
                    os.remove(temp_info_file)
            except:
                pass

    if action == ".restore":
        reply = await event.get_reply_message()
        if not reply or not reply.file:
            return await send_command_response(event, "⚠️ Reply to an encrypted database backup file first.")

        filename = reply.file.name or ""
        if not filename.endswith(".db.enc"):
            return await send_command_response(event, "⚠️ Invalid file. Only encrypted `.db.enc` backups are accepted.")

        temp_file = DB_FILE + ".restore"
        temp_encrypted_file = DB_FILE + ".restore.enc"

        async with _timed_actions_lock:
            _restore_event.set()

            try:
                cleanup_temp_files(temp_file, temp_encrypted_file)

                secret_error = validate_backup_secrets()
                if secret_error:
                    return await send_command_response(event, f"⚠️ Restore decryption error: `{secret_error}`", parse_mode='markdown')

                await reply.download_media(file=temp_encrypted_file)

                if not is_encrypted_backup_file(temp_encrypted_file):
                    return await send_command_response(event, "⚠️ Invalid encrypted backup. Missing NDBENC2 header.")

                with open(temp_encrypted_file, "rb") as f:
                    encrypted_data = f.read()

                plain_data = decrypt_backup_data(encrypted_data)

                with open(temp_file, "wb") as f:
                    f.write(plain_data)

                async with aiosqlite.connect(temp_file) as test_conn:
                    async with test_conn.execute("PRAGMA integrity_check") as cursor:
                        integrity = await cursor.fetchone()
                    if not integrity or integrity[0] != "ok":
                        return await send_command_response(event, "⚠️ Invalid database backup. Integrity check failed.")

                    async with test_conn.execute("SELECT name FROM sqlite_master WHERE type='table'") as cursor:
                        tables = {row[0] for row in await cursor.fetchall()}

                    required_tables = {"whitelist", "blacklist", "settings", "attempts", "timed_actions", "last_alerts", "user_cache", "contact_sync_disabled"}
                    if not required_tables.issubset(tables):
                        return await send_command_response(event, "⚠️ Invalid database backup. Required tables are missing.")

                    async with test_conn.execute("PRAGMA table_info(timed_actions)") as cursor:
                        timed_columns = {row[1] for row in await cursor.fetchall()}
                    if "was_contact_sync_disabled" not in timed_columns:
                        return await send_command_response(event, "⚠️ Invalid database backup. New timed action columns are missing.")

                os.replace(temp_file, DB_FILE)
                await init_db()
                await clear_last_alerts()

            except Exception as e:
                return await send_command_response(event, f"❌ Restore failed: `{e}`", parse_mode='markdown')
            finally:
                cleanup_temp_files(temp_file, temp_encrypted_file)
                _restore_event.clear()

        await refresh_contacts()
        await add_audit("restore", None, "database restored")
        return await send_command_response(event, "✅ Database restored successfully.")

    if action == ".on":
        protection_enabled = True
        await set_setting("protection_enabled", "1")
        await add_audit("on", None, "protection enabled")
        return await send_command_response(event, "🛡️ NoDMBot: ACTIVE")

    if action == ".off":
        protection_enabled = False
        await set_setting("protection_enabled", "0")
        await add_audit("off", None, "protection disabled")
        return await send_command_response(event, "🛡️ NoDMBot: NOT ACTIVE")

    if action == ".pin":
        reply = await event.get_reply_message()
        if not reply:
            return await send_command_response(event, "⚠️ Reply to a message with `.pin` first.", parse_mode='markdown')

        try:
            await client.pin_message(event.chat_id, reply, notify=False)
            await add_audit("pin", None, f"chat {event.chat_id} message {reply.id}")
            return await send_command_response(event, "📌 Message pinned successfully.")
        except Exception as e:
            return await send_command_response(event, f"❌ Pin failed: `{e}`", parse_mode='markdown')

    if action == ".unpin":
        reply = await event.get_reply_message()
        if not reply:
            return await send_command_response(event, "⚠️ Reply to a pinned message with `.unpin` first.", parse_mode='markdown')

        try:
            await client.unpin_message(event.chat_id, reply, notify=False)
            await add_audit("unpin", None, f"chat {event.chat_id} message {reply.id}")
            return await send_command_response(event, "📌 Message unpinned successfully.")
        except TypeError:
            try:
                await client.unpin_message(event.chat_id, reply)
                await add_audit("unpin", None, f"chat {event.chat_id} message {reply.id}")
                return await send_command_response(event, "📌 Message unpinned successfully.")
            except Exception as e:
                return await send_command_response(event, f"❌ Unpin failed: `{e}`", parse_mode='markdown')
        except Exception as e:
            return await send_command_response(event, f"❌ Unpin failed: `{e}`", parse_mode='markdown')

    if action == ".clhist":
        try:
            reply_to = getattr(event.message, "reply_to", None)
            topic_id = None

            if reply_to and not event.is_private:
                topic_id = getattr(reply_to, "reply_to_top_id", None) or getattr(reply_to, "reply_to_msg_id", None)

            iterator_kwargs = {}
            scope = "chat"

            if topic_id:
                iterator_kwargs["reply_to"] = topic_id
                scope = "topic"

            await send_command_response(
                event,
                f"⚠️ `{scope}` history will be cleared in `5` seconds.\n🧹 All messages will be deleted.",
                parse_mode='markdown'
            )

            await asyncio.sleep(5)

            deleted_count = 0
            batch = []

            async for msg in client.iter_messages(event.chat_id, **iterator_kwargs):
                batch.append(msg.id)

                if len(batch) >= 100:
                    deleted_count += await delete_messages_safely(event.chat_id, batch)
                    batch = []

            if batch:
                deleted_count += await delete_messages_safely(event.chat_id, batch)

            await add_audit("clhist", None, f"{scope} {event.chat_id} deleted {deleted_count}")
            return
        except Exception as e:
            return await send_command_response(event, f"❌ Clear history failed: `{e}`", parse_mode='markdown')

    if action == ".dlmymsgs":
        try:
            scan_limit = None
            if len(args) > 1:
                try:
                    scan_limit = int(args[1])
                    if scan_limit <= 0:
                        return await send_command_response(event, "⚠️ Limit must be greater than `0`.", parse_mode='markdown')
                except:
                    return await send_command_response(event, "⚠️ Usage: `.dlmymsgs` or `.dlmymsgs 500`", parse_mode='markdown')

            reply_to = getattr(event.message, "reply_to", None)
            topic_id = None

            if reply_to and not event.is_private:
                topic_id = getattr(reply_to, "reply_to_top_id", None) or getattr(reply_to, "reply_to_msg_id", None)

            iterator_kwargs = {}
            scope = "chat"

            if topic_id:
                iterator_kwargs["reply_to"] = topic_id
                scope = "topic"

            if scan_limit is not None:
                iterator_kwargs["limit"] = scan_limit

            await send_command_response(
                event,
                f"🧹 Deleting my messages in current `{scope}`...",
                parse_mode='markdown'
            )

            deleted_count = 0
            scanned_count = 0
            batch = []

            async for msg in client.iter_messages(event.chat_id, **iterator_kwargs):
                scanned_count += 1

                if getattr(msg, "out", False) or getattr(msg, "sender_id", None) == ADMIN_ID:
                    batch.append(msg.id)

                    if len(batch) >= 100:
                        deleted_count += await delete_messages_safely(event.chat_id, batch)
                        batch = []

            if batch:
                deleted_count += await delete_messages_safely(event.chat_id, batch)

            limit_text = f"limit {scan_limit}" if scan_limit is not None else "all"
            await add_audit("dlmymsgs", None, f"{scope} {event.chat_id} deleted {deleted_count} scanned {scanned_count} {limit_text}")
            return
        except Exception as e:
            return await send_command_response(event, f"❌ Delete my messages failed: `{e}`", parse_mode='markdown')

    if action == ".addcontact":
        def is_phone_number(text):
            cleaned = text.strip().lstrip("+").replace("-", "").replace(" ", "")
            return cleaned.isdigit() and len(cleaned) >= 7

        if event.is_private:
            if len(args) < 2:
                return await send_command_response(
                    event,
                    "⚠️ Usage: `.addcontact firstname_lastname`",
                    parse_mode='markdown'
                )

            first_name, last_name = parse_contact_name(args[1])

            try:
                entity = await client.get_entity(event.chat_id)
                phone = getattr(entity, "phone", None) or ""

                await client(functions.contacts.AddContactRequest(
                    id=entity,
                    first_name=first_name,
                    last_name=last_name,
                    phone=phone,
                    add_phone_privacy_exception=False
                ))

                await cache_user_entity(entity, entity.id)
                phone_text = f"`{phone}`" if phone else "Not available"
                await add_audit("addcontact", entity.id, f"added private chat contact {first_name} {last_name}".strip())
                return await send_command_response(
                    event,
                    f"✅ Contact added successfully.\n"
                    f"👤 **Name:** `{(first_name + ' ' + last_name).strip()}`\n"
                    f"📞 **Phone:** {phone_text}",
                    parse_mode='markdown'
                )
            except Exception as e:
                return await send_command_response(event, f"❌ Failed to add contact: `{e}`", parse_mode='markdown')

        else:
            extra = args[1:]
            if len(extra) < 2 or len(extra) % 2 != 0:
                return await send_command_response(
                    event,
                    "⚠️ Usage:\n"
                    "`.addcontact phonenumber firstname_lastname`\n"
                    "`.addcontact @username firstname_lastname`\n"
                    "Multi: `.addcontact id1 name1 id2 name2 ...`",
                    parse_mode='markdown'
                )

            pairs = [(extra[i], extra[i + 1]) for i in range(0, len(extra), 2)]
            responses = []

            for identifier, name_arg in pairs:
                first_name, last_name = parse_contact_name(name_arg)

                if is_phone_number(identifier):
                    phone = identifier if identifier.startswith("+") else f"+{identifier}"

                    try:
                        result = await client(functions.contacts.ImportContactsRequest([
                            types.InputPhoneContact(
                                client_id=random.randint(0, 2**63),
                                phone=phone,
                                first_name=first_name,
                                last_name=last_name
                            )
                        ]))

                        if result.imported:
                            user = result.users[0] if result.users else None
                            user_id = user.id if user else None
                            if user:
                                await cache_user_entity(user, user_id)
                            await add_audit("addcontact", user_id, f"added by phone {phone}")
                            responses.append(
                                f"✅ `{(first_name + ' ' + last_name).strip()}` - `{phone}` added."
                            )
                        else:
                            responses.append(f"⚠️ No Telegram account found for: `{phone}`")
                    except Exception as e:
                        responses.append(f"❌ Failed for `{phone}`: `{e}`")

                else:
                    username = identifier.lstrip("@")

                    try:
                        entity = await client.get_entity(username)
                        phone = getattr(entity, "phone", None) or ""

                        await client(functions.contacts.AddContactRequest(
                            id=entity,
                            first_name=first_name,
                            last_name=last_name,
                            phone=phone,
                            add_phone_privacy_exception=False
                        ))

                        await cache_user_entity(entity, entity.id)
                        await add_audit("addcontact", entity.id, f"added by username @{username}")
                        responses.append(
                            f"✅ `{(first_name + ' ' + last_name).strip()}` - `@{username}` added."
                        )
                    except Exception as e:
                        responses.append(f"❌ Failed for `@{username}`: `{e}`")

            return await send_command_response(
                event,
                "\n".join(responses) if responses else "⚠️ No contacts added.",
                parse_mode='markdown'
            )

    if action == ".remcontact":
        if event.is_private and len(args) < 2:
            try:
                target_id = event.chat_id
                entity = await client.get_entity(target_id)
                await client(functions.contacts.DeleteContactsRequest(id=[entity]))
                await cache_user_entity(entity, target_id)
                await refresh_contacts()
                await add_audit("remcontact", target_id, "contact removed from private chat")
                return await send_command_response(
                    event,
                    f"✅ Contact removed successfully.\n"
                    f"👤 **Name:** `{get_full_name(entity)}`",
                    parse_mode='markdown'
                )
            except Exception as e:
                return await send_command_response(event, f"❌ Failed to remove contact: `{e}`", parse_mode='markdown')

        if len(args) < 2:
            return await send_command_response(
                event,
                "⚠️ Usage: `.remcontact user_id [@username ...]`",
                parse_mode='markdown'
            )

        entities_to_remove = []
        responses = []
        for identifier in args[1:]:
            try:
                try:
                    target_id = int(identifier)
                    entity = await client.get_entity(target_id)
                except ValueError:
                    entity = await client.get_entity(identifier.lstrip("@"))
                    target_id = entity.id
                await cache_user_entity(entity, target_id)
                entities_to_remove.append((entity, target_id, get_full_name(entity)))
            except Exception as e:
                responses.append(f"⚠️ Failed to resolve `{identifier}`: `{e}`")

        if entities_to_remove:
            try:
                await client(functions.contacts.DeleteContactsRequest(id=[e for e, _, _ in entities_to_remove]))
                await refresh_contacts()
                for _, tid, name in entities_to_remove:
                    await add_audit("remcontact", tid, f"contact removed {tid}")
                    responses.append(f"✅ `{name}` - `{tid}` removed.")
            except Exception as e:
                for _, tid, name in entities_to_remove:
                    responses.append(f"⚠️ Failed to remove `{name}` - `{tid}`: `{e}`")

        return await send_command_response(
            event,
            "\n".join(responses) if responses else "⚠️ No contacts removed.",
            parse_mode='markdown'
        )

    if action == ".editcontact":
        if event.is_private:
            if len(args) < 2:
                return await send_command_response(
                    event,
                    "⚠️ Usage: `.editcontact firstname_lastname`",
                    parse_mode='markdown'
                )

            first_name, last_name = parse_contact_name(args[1])

            try:
                entity = await client.get_entity(event.chat_id)
                phone = getattr(entity, "phone", None) or ""

                await client(functions.contacts.AddContactRequest(
                    id=entity,
                    first_name=first_name,
                    last_name=last_name,
                    phone=phone,
                    add_phone_privacy_exception=False
                ))

                await cache_user_entity(entity, entity.id)
                await add_audit("editcontact", entity.id, f"name updated to {(first_name + ' ' + last_name).strip()}")
                return await send_command_response(
                    event,
                    f"✅ Contact updated successfully.\n"
                    f"👤 **New Name:** `{(first_name + ' ' + last_name).strip()}`",
                    parse_mode='markdown'
                )
            except Exception as e:
                return await send_command_response(event, f"❌ Failed to edit contact: `{e}`", parse_mode='markdown')
        else:
            extra = args[1:]
            if len(extra) < 2 or len(extra) % 2 != 0:
                return await send_command_response(
                    event,
                    "⚠️ Usage:\n"
                    "`.editcontact user_id firstname_lastname`\n"
                    "`.editcontact @username firstname_lastname`\n"
                    "Multi: `.editcontact id1 name1 id2 name2 ...`",
                    parse_mode='markdown'
                )

            pairs = [(extra[i], extra[i + 1]) for i in range(0, len(extra), 2)]
            responses = []

            for identifier, name_arg in pairs:
                first_name, last_name = parse_contact_name(name_arg)

                try:
                    try:
                        target_id = int(identifier)
                        entity = await client.get_entity(target_id)
                    except ValueError:
                        entity = await client.get_entity(identifier.lstrip("@"))
                        target_id = entity.id

                    phone = getattr(entity, "phone", None) or ""

                    await client(functions.contacts.AddContactRequest(
                        id=entity,
                        first_name=first_name,
                        last_name=last_name,
                        phone=phone,
                        add_phone_privacy_exception=False
                    ))

                    await cache_user_entity(entity, entity.id)
                    await add_audit("editcontact", entity.id, f"name updated to {(first_name + ' ' + last_name).strip()}")
                    responses.append(
                        f"✅ `{(first_name + ' ' + last_name).strip()}` - `{target_id}` updated."
                    )
                except Exception as e:
                    responses.append(f"❌ Failed for `{identifier}`: `{e}`")

            return await send_command_response(
                event,
                "\n".join(responses) if responses else "⚠️ No contacts updated.",
                parse_mode='markdown'
            )

    if action == ".contlist":
        contact_list = [(uid,) for uid in sorted(contact_ids)]

        async def build_contact_line(row):
            uid = row[0]
            user_link, hash_mention = await get_user_link_by_id_with_hash(uid)
            return f"• {user_link} - `{uid}`\n", hash_mention

        return await send_dynamic_user_list(
            event,
            "📇 **Contacts:**",
            contact_list,
            build_contact_line,
            "📭 No contacts found.",
            args[1] if len(args) > 1 else None
        )

    if action == ".inblist":
        async with get_db_conn() as conn:
            async with conn.execute("SELECT user_id FROM dialog_whitelist ORDER BY user_id ASC") as cursor:
                users = await cursor.fetchall()

        async def build_inbox_line(row):
            uid = row[0]
            user_link, hash_mention = await get_user_link_by_id_with_hash(uid)
            return f"• {user_link} - `{uid}`\n", hash_mention

        return await send_dynamic_user_list(
            event,
            "📬 **Inbox Users:**",
            users,
            build_inbox_line,
            "📭 Inbox is empty.",
            args[1] if len(args) > 1 else None
        )

    if action == ".delinb":
        if len(args) < 2 and not event.is_private:
            return await send_command_response(
                event,
                "⚠️ Usage: `.delinb user_id [@username ...]`",
                parse_mode='markdown'
            )

        is_self_chat = len(args) < 2 and event.is_private

        if is_self_chat:
            try:
                target_id = event.chat_id
                entity = await client.get_entity(target_id)
                name = get_full_name(entity)

                try:
                    await event.delete()
                except Exception:
                    pass

                await client(functions.messages.DeleteHistoryRequest(
                    peer=entity,
                    max_id=0,
                    revoke=True
                ))

                async with get_db_conn() as conn:
                    await conn.execute("BEGIN IMMEDIATE")
                    await conn.execute("DELETE FROM dialog_whitelist WHERE user_id = ?", (target_id,))
                    async with conn.execute("SELECT user_id FROM manual_whitelist WHERE user_id = ?", (target_id,)) as cursor:
                        in_manual = await cursor.fetchone()
                    if not in_manual and target_id not in contact_ids:
                        await conn.execute("DELETE FROM whitelist WHERE user_id = ?", (target_id,))
                        await conn.execute("DELETE FROM last_alerts WHERE user_id = ?", (target_id,))
                    await add_audit("delinb", target_id, "dialog deleted for both parties", conn=conn)
                    await conn.commit()

                if LOG_GROUP_ID != 0:
                    try:
                        await client.send_message(
                            LOG_GROUP_ID,
                            f"🗑️ Dialog deleted for both parties.\n👤 **User:** `{name}` - `{target_id}`",
                            reply_to=LOG_TOPIC_ID,
                            parse_mode='markdown'
                        )
                    except Exception:
                        pass
                return

            except Exception as e:
                if LOG_GROUP_ID != 0:
                    try:
                        await client.send_message(
                            LOG_GROUP_ID,
                            f"❌ Failed to delete inbox dialog: `{e}`",
                            reply_to=LOG_TOPIC_ID,
                            parse_mode='markdown'
                        )
                    except Exception:
                        pass
                return

        responses = []
        db_ops = []
        for identifier in args[1:]:
            try:
                try:
                    target_id = int(identifier)
                    entity = await client.get_entity(target_id)
                except ValueError:
                    entity = await client.get_entity(identifier.lstrip("@"))
                    target_id = entity.id

                name = get_full_name(entity)

                await client(functions.messages.DeleteHistoryRequest(
                    peer=entity,
                    max_id=0,
                    revoke=True
                ))

                db_ops.append((target_id, name))
                responses.append(f"🗑️ `{name}` - `{target_id}` deleted.")
            except Exception as e:
                responses.append(f"⚠️ Failed for `{identifier}`: `{e}`")

        if db_ops:
            async with get_db_conn() as conn:
                await conn.execute("BEGIN IMMEDIATE")
                for target_id, name in db_ops:
                    await conn.execute("DELETE FROM dialog_whitelist WHERE user_id = ?", (target_id,))
                    async with conn.execute("SELECT user_id FROM manual_whitelist WHERE user_id = ?", (target_id,)) as cursor:
                        in_manual = await cursor.fetchone()
                    if not in_manual and target_id not in contact_ids:
                        await conn.execute("DELETE FROM whitelist WHERE user_id = ?", (target_id,))
                        await conn.execute("DELETE FROM last_alerts WHERE user_id = ?", (target_id,))
                    await add_audit("delinb", target_id, "dialog deleted for both parties", conn=conn)
                await conn.commit()

        return await send_command_response(
            event,
            "\n".join(responses) if responses else "⚠️ No dialogs deleted.",
            parse_mode='markdown'
        )

    if action == ".dsynlist":
        async with get_db_conn() as conn:
            async with conn.execute("SELECT user_id FROM contact_sync_disabled ORDER BY user_id ASC") as cursor:
                users = await cursor.fetchall()

        async def build_sync_line(row):
            uid = row[0]
            user_link, hash_mention = await get_user_link_by_id_with_hash(uid)
            return f"• {user_link} - `{uid}`\n", hash_mention

        return await send_dynamic_user_list(
            event,
            "🔁 **Contact Sync Disabled:**",
            users,
            build_sync_line,
            "📭 Contact sync disabled list is empty.",
            args[1] if len(args) > 1 else None
        )

    if action in (".sync", ".unsync"):
        if len(args) < 2:
            return await send_command_response(event, f"⚠️ Usage: `{action} user_id [user_id2 ...]`", parse_mode='markdown')

        responses = []
        async with get_db_conn() as conn:
            await conn.execute("BEGIN IMMEDIATE")
            for identifier in args[1:]:
                try:
                    try:
                        target_id = int(identifier)
                    except ValueError:
                        entity = await client.get_entity(identifier.lstrip("@"))
                        target_id = entity.id

                    if action == ".sync":
                        await set_contact_sync_disabled(target_id, False, conn=conn)
                        if target_id in contact_ids:
                            await conn.execute("INSERT OR IGNORE INTO whitelist VALUES (?)", (target_id,))
                        await add_audit("sync", target_id, "contact sync enabled", conn=conn)
                        responses.append(f"🔁 Contact sync enabled for `{target_id}`.")
                    else:
                        await set_contact_sync_disabled(target_id, True, conn=conn)
                        await add_audit("unsync", target_id, "contact sync disabled", conn=conn)
                        responses.append(f"🔁 Contact sync disabled for `{target_id}`.")
                except Exception as e:
                    responses.append(f"⚠️ Failed for `{identifier}`: `{e}`")
            await conn.commit()

        return await send_command_response(event, "\n".join(responses), parse_mode='markdown')

    if action == ".list":
        async with get_db_conn() as conn:
            async with conn.execute("SELECT user_id FROM whitelist") as cursor:
                users = await cursor.fetchall()

        async def build_whitelist_line(row):
            uid = row[0]
            user_link, hash_mention = await get_user_link_by_id_with_hash(uid)
            return f"• {user_link} - `{uid}`\n", hash_mention

        return await send_dynamic_user_list(
            event,
            "📃 **Whitelisted Users:**",
            users,
            build_whitelist_line,
            "📭 Whitelist is empty.",
            args[1] if len(args) > 1 else None
        )

    if action == ".blist":
        async with get_db_conn() as conn:
            async with conn.execute("SELECT user_id FROM blacklist") as cursor:
                users = await cursor.fetchall()

        async def build_blacklist_line(row):
            uid = row[0]
            user_link, hash_mention = await get_user_link_by_id_with_hash(uid)
            return f"• {user_link} - `{uid}`\n", hash_mention

        return await send_dynamic_user_list(
            event,
            "🚫 **Blacklisted Users:**",
            users,
            build_blacklist_line,
            "📭 Blacklist is empty.",
            args[1] if len(args) > 1 else None
        )

    if len(args) < 2:
        if event.is_private and action in (".ok", ".rem", ".block", ".unblock"):
            target_ids = [event.chat_id]
        else:
            return
    else:
        target_ids = args[1:]

    responses = []

    async with get_db_conn() as conn:
        await conn.execute("BEGIN IMMEDIATE")
        for t_id in target_ids:
            try:
                try:
                    tid = int(t_id)
                except ValueError:
                    entity = await client.get_entity(str(t_id).lstrip("@"))
                    await cache_user_entity(entity, entity.id)
                    tid = entity.id
                if action == ".ok":
                    await set_contact_sync_disabled(tid, False, conn=conn)
                    await conn.execute("INSERT OR IGNORE INTO whitelist VALUES (?)", (tid,))
                    await conn.execute("INSERT OR IGNORE INTO manual_whitelist VALUES (?)", (tid,))
                    await conn.execute("DELETE FROM last_alerts WHERE user_id = ?", (tid,))
                    await add_audit("ok", tid, "user allowed", conn=conn)
                    responses.append(f"✅ User `{tid}` allowed.")

                elif action == ".rem":
                    if tid == ADMIN_ID or tid == OWNER_ID or tid in TELEGRAM_SERVICE_IDS:
                        responses.append(f"⚠️ **Action Denied:** Cannot remove `{tid}` (Admin/Owner/Telegram Service)!")
                    else:
                        await set_contact_sync_disabled(tid, True, conn=conn)
                        await conn.execute("DELETE FROM whitelist WHERE user_id = ?", (tid,))
                        await conn.execute("DELETE FROM manual_whitelist WHERE user_id = ?", (tid,))
                        await conn.execute("DELETE FROM last_alerts WHERE user_id = ?", (tid,))
                        await add_audit("rem", tid, "user restricted", conn=conn)
                        responses.append(f"🚫 User `{tid}` restricted.")

                elif action == ".block":
                    if tid == ADMIN_ID or tid == OWNER_ID or tid in TELEGRAM_SERVICE_IDS:
                        responses.append(f"⚠️ **Action Denied:** Cannot block `{tid}` (Admin/Owner/Telegram Service)!")
                    else:
                        await set_contact_sync_disabled(tid, True, conn=conn)
                        await conn.execute("INSERT OR IGNORE INTO blacklist VALUES (?)", (tid,))
                        await conn.execute("DELETE FROM last_alerts WHERE user_id = ?", (tid,))
                        await add_audit("block", tid, "user blocked", conn=conn)
                        responses.append(f"⛔ User `{tid}` blocked.")

                elif action == ".unblock":
                    await set_contact_sync_disabled(tid, False, conn=conn)
                    await conn.execute("DELETE FROM blacklist WHERE user_id = ?", (tid,))
                    await conn.execute("DELETE FROM last_alerts WHERE user_id = ?", (tid,))
                    await add_audit("unblock", tid, "user unblocked", conn=conn)
                    responses.append(f"✅ User `{tid}` unblocked.")
            except Exception as e:
                logger.error(f"Failed to process target {t_id}: {e}")
                responses.append(f"⚠️ Failed to process `{t_id}`.")

        await conn.commit()

    if responses:
        return await send_command_response(event, "\n".join(responses), parse_mode='markdown')

async def start_bot():
    await init_db()
    await client.start()
    await refresh_contacts()
    await cache_known_users()
    await sync_dialog_whitelist()
    await send_startup_status()
    asyncio.create_task(contact_scanner_loop())
    asyncio.create_task(cache_known_users_loop())
    asyncio.create_task(dialog_whitelist_loop())
    asyncio.create_task(timed_actions_loop())
    asyncio.create_task(cleanup_db_loop())
    await client.run_until_disconnected()

if __name__ == '__main__':
    threading.Thread(target=run_flask, daemon=True).start()
    asyncio.run(start_bot())
