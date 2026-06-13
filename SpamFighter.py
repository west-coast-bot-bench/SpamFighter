
from __future__ import annotations

import asyncio
import argparse
import concurrent.futures
import contextlib
import csv
import hashlib
import ipaddress
import json
import logging
import os
import errno
import uuid
import time
import re
import signal
import socket
import sys
import unicodedata
import urllib.error
import urllib.request
from collections import OrderedDict, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Collection, Dict, Iterable, List, Optional, Sequence, Set, Tuple
from urllib.parse import urlsplit

import aiosqlite
import aiohttp
import discord
import regex as safe_regex
from discord import app_commands
from discord.ext import commands
try:
    import psycopg
except ModuleNotFoundError:  # pragma: no cover
    psycopg = None  # type: ignore

MessageHistoryChannel = discord.TextChannel | discord.VoiceChannel
MESSAGE_HISTORY_CHANNEL_TYPES = (discord.TextChannel, discord.VoiceChannel)


# ============================================================
# Logging
# ============================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger("spamfighter")


# ============================================================
# TOML helpers
# ============================================================

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib  # type: ignore

try:
    import tomli_w
except ModuleNotFoundError:  # pragma: no cover
    tomli_w = None


# ============================================================
# Environment helpers
# ============================================================

APP_DIR = Path(__file__).resolve().parent
CLI_REGRESSION_MODE = "--regression" in sys.argv


def _resolve_runtime_path(env_name: str, default_path: Path) -> Path:
    raw_value = os.environ.get(env_name)
    if not raw_value:
        return default_path
    candidate = Path(raw_value).expanduser()
    if not candidate.is_absolute():
        candidate = (APP_DIR / candidate).resolve()
    return candidate


DATA_DIR = _resolve_runtime_path("SPAMFIGHTER_DATA_DIR", APP_DIR)
CONFIG_PATH = _resolve_runtime_path("SPAMFIGHTER_CONFIG_PATH", DATA_DIR / "config.toml")
SPAM_RULES_PATH = _resolve_runtime_path("SPAMFIGHTER_SPAM_RULES_PATH", DATA_DIR / "spam_rules.toml")
SPAM_RULES_HISTORY_DIR = _resolve_runtime_path("SPAMFIGHTER_SPAM_RULES_HISTORY_DIR", DATA_DIR / "spam_rules_history")
RULE_REPORTS_PATH = _resolve_runtime_path("SPAMFIGHTER_RULE_REPORTS_PATH", DATA_DIR / "rule_review_reports.json")
AI_USAGE_PATH = _resolve_runtime_path("SPAMFIGHTER_AI_USAGE_PATH", DATA_DIR / "ai_review_usage.json")
STATE_DB_PATH = _resolve_runtime_path("SPAMFIGHTER_STATE_DB_PATH", DATA_DIR / "spamfighter_state.sqlite3")
DOMAIN_BLOCKLISTS_DIR = _resolve_runtime_path("SPAMFIGHTER_DOMAIN_BLOCKLISTS_DIR", DATA_DIR / "domain_blocklists")
PORN_DOMAIN_BLOCKLIST_PATH = _resolve_runtime_path(
    "SPAMFIGHTER_PORN_BLOCKLIST_PATH",
    DOMAIN_BLOCKLISTS_DIR / "porn_sites.txt",
)
MALICIOUS_DOMAIN_BLOCKLIST_PATH = _resolve_runtime_path(
    "SPAMFIGHTER_MALICIOUS_BLOCKLIST_PATH",
    DOMAIN_BLOCKLISTS_DIR / "malicious_sites.txt",
)
CUSTOM_DOMAIN_BLOCKLIST_PATH = _resolve_runtime_path(
    "SPAMFIGHTER_CUSTOM_BLOCKLIST_PATH",
    DOMAIN_BLOCKLISTS_DIR / "custom_sites.txt",
)
SPAM_RULES_BACKUP_LIMIT = 3


def env_str(name: str, default: Optional[str] = None) -> Optional[str]:
    value = os.environ.get(name)
    return value if value not in (None, "") else default


def env_secret_str(name: str, default: Optional[str] = None) -> Optional[str]:
    value = env_str(name)
    if value is not None:
        return value

    secret_file = env_str(f"{name}_FILE")
    if not secret_file:
        return default

    secret_path = Path(secret_file).expanduser()
    if not secret_path.is_absolute():
        secret_path = (APP_DIR / secret_path).resolve()

    try:
        secret_value = secret_path.read_text(encoding="utf-8").strip()
    except FileNotFoundError as exc:
        raise RuntimeError(f"Secret file configured via {name}_FILE was not found: {secret_path}") from exc
    except OSError as exc:
        raise RuntimeError(f"Could not read secret file configured via {name}_FILE: {secret_path}") from exc

    if not secret_value:
        raise RuntimeError(f"Secret file configured via {name}_FILE is empty: {secret_path}")
    return secret_value


def load_raw_config_dict(path: Path = CONFIG_PATH) -> dict:
    config_path = Path(path)
    if not config_path.exists():
        raise FileNotFoundError(f"Missing config file: {config_path}")
    with config_path.open("rb") as handle:
        return tomllib.load(handle)


def save_raw_config_dict(raw: dict, path: Path = CONFIG_PATH) -> None:
    if tomli_w is None:
        raise RuntimeError("tomli-w is not installed. Run: pip install tomli-w")

    config_path = Path(path)
    config_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = config_path.with_name(f"{config_path.name}.{uuid.uuid4().hex}.tmp")
    try:
        with tmp_path.open("wb") as handle:
            tomli_w.dump(raw, handle)
            handle.flush()
            os.fsync(handle.fileno())

        last_exc: Optional[OSError] = None
        for attempt in range(8):
            try:
                os.replace(tmp_path, config_path)
                last_exc = None
                break
            except OSError as exc:
                last_exc = exc
                if exc.errno not in (errno.EBUSY, errno.EACCES, errno.EPERM):
                    raise
                time.sleep(0.05 * (attempt + 1))
        if last_exc is not None:
            raise last_exc
    finally:
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass


# ============================================================
# Configuration models
# ============================================================

@dataclass(frozen=True)
class AppConfig:
    env: str
    use_guild_sync_for_dev: bool
    dev_guild_id: Optional[int]
    stale_command_cleanup_guild_ids: Set[int]


@dataclass(frozen=True)
class BotConfig:
    spam_dry_run: bool
    ignore_bots: bool
    ignore_guild_admins: bool
    max_audit_content_len: int


@dataclass(frozen=True)
class ControlConfig:
    admin_user_ids: Set[int]
    super_user_ids: Set[int]
    rule_deployer_user_ids: Set[int]
    rule_deployer_role_ids: Set[int]
    require_second_approver_for_ai: bool


@dataclass(frozen=True)
class GuildConfig:
    allowlist_enabled: bool
    allowed_guild_ids: Set[int]


@dataclass(frozen=True)
class AllowlistConfig:
    user_ids: Set[int]
    role_ids: Set[int]
    channel_ids: Set[int]


@dataclass(frozen=True)
class AuditConfig:
    default_channel_id: Optional[int]
    channel_map: Dict[int, int]


@dataclass(frozen=True)
class EnforcementConfig:
    default_channel_id: Optional[int]
    channel_map: Dict[int, int]


@dataclass(frozen=True)
class ReportsConfig:
    review_channel_id: Optional[int]
    false_positive_channel_ids: Set[int]
    validation_months: int
    validation_master_guild_id: Optional[int]


@dataclass(frozen=True)
class FeaturesConfig:
    disabled_commands_by_guild: Dict[int, Set[str]]


@dataclass(frozen=True)
class ModerationSettings:
    enable_deletion: bool
    enable_escalation: bool
    warn_threshold: int
    timeout_threshold: int
    kick_threshold: int
    ban_threshold: int
    timeout_minutes: int = 60


@dataclass(frozen=True)
class ModerationOverride:
    enable_deletion: Optional[bool] = None
    enable_escalation: Optional[bool] = None
    warn_threshold: Optional[int] = None
    timeout_threshold: Optional[int] = None
    kick_threshold: Optional[int] = None
    ban_threshold: Optional[int] = None
    timeout_minutes: Optional[int] = None


@dataclass(frozen=True)
class ModerationConfig:
    defaults: ModerationSettings
    guild_overrides: Dict[int, ModerationOverride]


@dataclass(frozen=True)
class Config:
    app: AppConfig
    bot: BotConfig
    control: ControlConfig
    guilds: GuildConfig
    allowlists: AllowlistConfig
    audit: AuditConfig
    enforcement: EnforcementConfig
    reports: ReportsConfig
    features: FeaturesConfig
    moderation: ModerationConfig


def _to_int_set(values: Optional[Iterable]) -> Set[int]:
    if not values:
        return set()
    return {int(value) for value in values}


def _to_int_dict(mapping: Optional[dict]) -> Dict[int, int]:
    if not mapping:
        return {}
    return {int(key): int(value) for key, value in mapping.items()}


def _to_str_set(values: Optional[Iterable]) -> Set[str]:
    if not values:
        return set()
    return {str(value).strip().lower() for value in values if str(value).strip()}


def _to_nested_command_map(mapping: Optional[dict]) -> Dict[int, Set[str]]:
    if not mapping:
        return {}
    result: Dict[int, Set[str]] = {}
    for key, values in mapping.items():
        command_names = _to_str_set(values)
        if command_names:
            result[int(key)] = command_names
    return result


def _optional_int(value: Optional[object]) -> Optional[int]:
    if value in (None, ""):
        return None
    return int(value)


def _optional_bool(value: Optional[object]) -> Optional[bool]:
    if value is None:
        return None
    return bool(value)


def parse_config_dict(raw: dict) -> Config:
    app_raw = raw.get("app", {})
    bot_raw = raw.get("bot", {})
    control_raw = raw.get("control", {})
    guilds_raw = raw.get("guilds", {})
    allowlists_raw = raw.get("allowlists", {})
    audit_raw = raw.get("audit", {})
    enforcement_raw = raw.get("enforcement", {})
    reports_raw = raw.get("reports", {})
    features_raw = raw.get("features", {})
    moderation_raw = raw.get("moderation", {})

    defaults_raw = moderation_raw.get("defaults", moderation_raw)
    guild_overrides_raw = moderation_raw.get("guild_overrides", {})

    allowed_guild_ids = _to_int_set(guilds_raw.get("allowed_guild_ids", []))
    allowlist_enabled = bool(guilds_raw.get("allowlist_enabled", bool(allowed_guild_ids)))

    moderation_defaults = ModerationSettings(
        enable_deletion=bool(defaults_raw.get("enable_deletion", True)),
        enable_escalation=bool(defaults_raw.get("enable_escalation", False)),
        warn_threshold=int(defaults_raw.get("warn_threshold", 1)),
        timeout_threshold=int(defaults_raw.get("timeout_threshold", 2)),
        kick_threshold=int(defaults_raw.get("kick_threshold", 3)),
        ban_threshold=int(defaults_raw.get("ban_threshold", 4)),
        timeout_minutes=int(defaults_raw.get("timeout_minutes", 60)),
    )

    moderation_overrides: Dict[int, ModerationOverride] = {}
    for guild_id, override_raw in guild_overrides_raw.items():
        moderation_overrides[int(guild_id)] = ModerationOverride(
            enable_deletion=_optional_bool(override_raw.get("enable_deletion")),
            enable_escalation=_optional_bool(override_raw.get("enable_escalation")),
            warn_threshold=_optional_int(override_raw.get("warn_threshold")),
            timeout_threshold=_optional_int(override_raw.get("timeout_threshold")),
            kick_threshold=_optional_int(override_raw.get("kick_threshold")),
            ban_threshold=_optional_int(override_raw.get("ban_threshold")),
            timeout_minutes=_optional_int(override_raw.get("timeout_minutes")),
        )

    return Config(
        app=AppConfig(
            env=str(app_raw.get("env", "production")).lower(),
            use_guild_sync_for_dev=bool(app_raw.get("use_guild_sync_for_dev", False)),
            dev_guild_id=int(app_raw["dev_guild_id"]) if app_raw.get("dev_guild_id") else None,
            stale_command_cleanup_guild_ids=_to_int_set(app_raw.get("stale_command_cleanup_guild_ids", [])),
        ),
        bot=BotConfig(
            spam_dry_run=bool(bot_raw.get("spam_dry_run", False)),
            ignore_bots=bool(bot_raw.get("ignore_bots", True)),
            ignore_guild_admins=bool(bot_raw.get("ignore_guild_admins", True)),
            max_audit_content_len=int(bot_raw.get("max_audit_content_len", 1800)),
        ),
        control=ControlConfig(
            admin_user_ids=_to_int_set(control_raw.get("admin_user_ids", [])),
            super_user_ids=_to_int_set(control_raw.get("super_user_ids", [])),
            rule_deployer_user_ids=_to_int_set(control_raw.get("rule_deployer_user_ids", [])),
            rule_deployer_role_ids=_to_int_set(control_raw.get("rule_deployer_role_ids", [])),
            require_second_approver_for_ai=bool(control_raw.get("require_second_approver_for_ai", True)),
        ),
        guilds=GuildConfig(
            allowlist_enabled=allowlist_enabled,
            allowed_guild_ids=allowed_guild_ids,
        ),
        allowlists=AllowlistConfig(
            user_ids=_to_int_set(allowlists_raw.get("user_ids", [])),
            role_ids=_to_int_set(allowlists_raw.get("role_ids", [])),
            channel_ids=_to_int_set(allowlists_raw.get("channel_ids", [])),
        ),
        audit=AuditConfig(
            default_channel_id=int(audit_raw["default_channel_id"]) if audit_raw.get("default_channel_id") else None,
            channel_map=_to_int_dict(audit_raw.get("channel_map", {})),
        ),
        enforcement=EnforcementConfig(
            default_channel_id=int(enforcement_raw["default_channel_id"]) if enforcement_raw.get("default_channel_id") else None,
            channel_map=_to_int_dict(enforcement_raw.get("channel_map", {})),
        ),
        reports=ReportsConfig(
            review_channel_id=int(reports_raw["review_channel_id"]) if reports_raw.get("review_channel_id") else None,
            false_positive_channel_ids=_to_int_set(reports_raw.get("false_positive_channel_ids", [])),
            validation_months=int(reports_raw.get("validation_months", 3)),
            validation_master_guild_id=int(reports_raw["validation_master_guild_id"]) if reports_raw.get("validation_master_guild_id") else None,
        ),
        features=FeaturesConfig(
            disabled_commands_by_guild=_to_nested_command_map(features_raw.get("disabled_commands_by_guild", {})),
        ),
        moderation=ModerationConfig(
            defaults=moderation_defaults,
            guild_overrides=moderation_overrides,
        ),
    )


def load_config(path: Path = CONFIG_PATH) -> Config:
    return parse_config_dict(load_raw_config_dict(path))


def validate_thresholds(settings: ModerationSettings, *, where: str) -> None:
    values = [
        settings.warn_threshold,
        settings.timeout_threshold,
        settings.kick_threshold,
        settings.ban_threshold,
    ]
    if any(value <= 0 for value in values):
        raise ValueError(f"{where}: moderation thresholds must be positive")
    if not (
        settings.warn_threshold
        <= settings.timeout_threshold
        <= settings.kick_threshold
        <= settings.ban_threshold
    ):
        raise ValueError(f"{where}: thresholds must satisfy warn <= timeout <= kick <= ban")
    if settings.timeout_minutes <= 0:
        raise ValueError(f"{where}: timeout_minutes must be positive")


def resolve_moderation_settings(guild_id: int, *, config: Optional[Config] = None) -> ModerationSettings:
    source_config = CONFIG if config is None else config
    defaults = source_config.moderation.defaults
    override = source_config.moderation.guild_overrides.get(guild_id)

    if override is None:
        return defaults

    return ModerationSettings(
        enable_deletion=defaults.enable_deletion if override.enable_deletion is None else override.enable_deletion,
        enable_escalation=defaults.enable_escalation if override.enable_escalation is None else override.enable_escalation,
        warn_threshold=defaults.warn_threshold if override.warn_threshold is None else override.warn_threshold,
        timeout_threshold=defaults.timeout_threshold if override.timeout_threshold is None else override.timeout_threshold,
        kick_threshold=defaults.kick_threshold if override.kick_threshold is None else override.kick_threshold,
        ban_threshold=defaults.ban_threshold if override.ban_threshold is None else override.ban_threshold,
        timeout_minutes=defaults.timeout_minutes if override.timeout_minutes is None else override.timeout_minutes,
    )


def validate_config(config: Config) -> None:
    if config.app.use_guild_sync_for_dev and not config.app.dev_guild_id:
        raise ValueError("use_guild_sync_for_dev=true but dev_guild_id is missing")

    if config.bot.max_audit_content_len < 200:
        raise ValueError("max_audit_content_len must be at least 200")

    if config.bot.max_audit_content_len > 8000:
        raise ValueError("max_audit_content_len must be <= 8000")

    if config.audit.default_channel_id is not None and config.audit.default_channel_id <= 0:
        raise ValueError("audit.default_channel_id must be positive")

    if config.enforcement.default_channel_id is not None and config.enforcement.default_channel_id <= 0:
        raise ValueError("enforcement.default_channel_id must be positive")

    if config.reports.review_channel_id is not None and config.reports.review_channel_id <= 0:
        raise ValueError("reports.review_channel_id must be positive")
    if config.reports.validation_months <= 0 or config.reports.validation_months > 12:
        raise ValueError("reports.validation_months must be between 1 and 12")
    if config.reports.validation_master_guild_id is not None and config.reports.validation_master_guild_id <= 0:
        raise ValueError("reports.validation_master_guild_id must be positive")
    for channel_id in config.reports.false_positive_channel_ids:
        if channel_id <= 0:
            raise ValueError("reports.false_positive_channel_ids contains a non-positive ID")
    for user_id in config.control.rule_deployer_user_ids:
        if user_id <= 0:
            raise ValueError("control.rule_deployer_user_ids contains a non-positive ID")
    for role_id in config.control.rule_deployer_role_ids:
        if role_id <= 0:
            raise ValueError("control.rule_deployer_role_ids contains a non-positive ID")
    for guild_id, command_names in config.features.disabled_commands_by_guild.items():
        if guild_id <= 0:
            raise ValueError("features.disabled_commands_by_guild contains a non-positive guild ID")
        for command_name in command_names:
            if not command_name.strip():
                raise ValueError("features.disabled_commands_by_guild contains a blank command name")

    for label, channel_map in (
        ("audit.channel_map", config.audit.channel_map),
        ("enforcement.channel_map", config.enforcement.channel_map),
    ):
        for guild_id, channel_id in channel_map.items():
            if guild_id <= 0 or channel_id <= 0:
                raise ValueError(f"{label} contains a non-positive ID")

    validate_thresholds(config.moderation.defaults, where="moderation.defaults")
    for guild_id in config.moderation.guild_overrides:
        validate_thresholds(
            resolve_moderation_settings(guild_id, config=config),
            where=f"moderation.guild_overrides.{guild_id}",
        )


# ============================================================
# Config bootstrap
# ============================================================

try:
    CONFIG = load_config(CONFIG_PATH)
    validate_config(CONFIG)
except FileNotFoundError as exc:
    raise RuntimeError(
        f"Missing config file at {CONFIG_PATH}. Mount it into the container or set SPAMFIGHTER_CONFIG_PATH."
    ) from exc
except tomllib.TOMLDecodeError as exc:
    raise RuntimeError(f"Config file at {CONFIG_PATH} is not valid TOML: {exc}") from exc
except ValueError as exc:
    raise RuntimeError(f"Config file at {CONFIG_PATH} failed validation: {exc}") from exc

CONFIG_LOCK = asyncio.Lock()
COMMAND_SYNC_LOCK = asyncio.Lock()

BOT_TOKEN = env_secret_str("SPAMFIGHTER_BOT_TOKEN")
if not BOT_TOKEN and not CLI_REGRESSION_MODE:
    raise RuntimeError(
        "Missing SPAMFIGHTER_BOT_TOKEN. Set the environment variable or mount a secret file via SPAMFIGHTER_BOT_TOKEN_FILE."
    )
SPAM_RULES_DATABASE_URL = env_secret_str("SPAMFIGHTER_SPAM_RULES_DATABASE_URL")


def apply_config(config: Config) -> None:
    global CONFIG
    global APP_ENV, USE_GUILD_SYNC_FOR_DEV, DEV_GUILD_ID, STALE_COMMAND_CLEANUP_GUILD_IDS
    global SPAM_DRY_RUN, IGNORE_BOTS, IGNORE_GUILD_ADMINS, MAX_AUDIT_CONTENT_LEN
    global CONTROL_ADMIN_USER_IDS, CONTROL_SUPER_USER_IDS
    global RULE_DEPLOYER_USER_IDS, RULE_DEPLOYER_ROLE_IDS, REQUIRE_SECOND_APPROVER_FOR_AI
    global GUILD_ALLOWLIST_ENABLED, ALLOWED_GUILD_IDS
    global ALLOWLIST_USER_IDS, ALLOWLIST_ROLE_IDS, ALLOWLIST_CHANNEL_IDS
    global AUDIT_LOG_CHANNEL_MAP, DEFAULT_AUDIT_LOG_CHANNEL_ID
    global ENFORCEMENT_LOG_CHANNEL_MAP, DEFAULT_ENFORCEMENT_LOG_CHANNEL_ID
    global REPORT_REVIEW_CHANNEL_ID, REPORT_FP_CHANNEL_IDS, REPORT_VALIDATION_MONTHS, REPORT_VALIDATION_MASTER_GUILD_ID
    global CONFIG_DISABLED_COMMANDS_BY_GUILD

    CONFIG = config

    APP_ENV = config.app.env
    USE_GUILD_SYNC_FOR_DEV = config.app.use_guild_sync_for_dev
    DEV_GUILD_ID = config.app.dev_guild_id
    STALE_COMMAND_CLEANUP_GUILD_IDS = config.app.stale_command_cleanup_guild_ids

    SPAM_DRY_RUN = config.bot.spam_dry_run
    IGNORE_BOTS = config.bot.ignore_bots
    IGNORE_GUILD_ADMINS = config.bot.ignore_guild_admins
    MAX_AUDIT_CONTENT_LEN = config.bot.max_audit_content_len

    CONTROL_ADMIN_USER_IDS = config.control.admin_user_ids
    CONTROL_SUPER_USER_IDS = config.control.super_user_ids
    RULE_DEPLOYER_USER_IDS = config.control.rule_deployer_user_ids
    RULE_DEPLOYER_ROLE_IDS = config.control.rule_deployer_role_ids
    REQUIRE_SECOND_APPROVER_FOR_AI = config.control.require_second_approver_for_ai

    GUILD_ALLOWLIST_ENABLED = config.guilds.allowlist_enabled
    ALLOWED_GUILD_IDS = config.guilds.allowed_guild_ids

    ALLOWLIST_USER_IDS = config.allowlists.user_ids
    ALLOWLIST_ROLE_IDS = config.allowlists.role_ids
    ALLOWLIST_CHANNEL_IDS = config.allowlists.channel_ids

    AUDIT_LOG_CHANNEL_MAP = config.audit.channel_map
    DEFAULT_AUDIT_LOG_CHANNEL_ID = config.audit.default_channel_id

    ENFORCEMENT_LOG_CHANNEL_MAP = config.enforcement.channel_map
    DEFAULT_ENFORCEMENT_LOG_CHANNEL_ID = config.enforcement.default_channel_id

    REPORT_REVIEW_CHANNEL_ID = config.reports.review_channel_id
    REPORT_FP_CHANNEL_IDS = config.reports.false_positive_channel_ids
    REPORT_VALIDATION_MONTHS = config.reports.validation_months
    REPORT_VALIDATION_MASTER_GUILD_ID = config.reports.validation_master_guild_id
    CONFIG_DISABLED_COMMANDS_BY_GUILD = {
        guild_id: set(command_names)
        for guild_id, command_names in config.features.disabled_commands_by_guild.items()
    }


apply_config(CONFIG)
OPENAI_API_KEY = env_secret_str("SPAMFIGHTER_OPENAI_API_KEY") or env_secret_str("OPENAI_API_KEY")
OPENAI_RULE_MODEL = env_str("SPAMFIGHTER_OPENAI_MODEL", "gpt-5.4-mini") or "gpt-5.4-mini"
OPENAI_API_TIMEOUT_SECONDS = int(env_str("SPAMFIGHTER_OPENAI_TIMEOUT_SECONDS", "60") or "60")
AI_REVIEW_REDACT_SENSITIVE = (env_str("SPAMFIGHTER_AI_REDACT_SENSITIVE", "true") or "true").lower() not in {"0", "false", "no", "off"}
AI_REVIEW_MAX_INPUT_CHARS = int(env_str("SPAMFIGHTER_AI_MAX_INPUT_CHARS", "7000") or "7000")
AI_REVIEW_WARN_INPUT_CHARS = int(env_str("SPAMFIGHTER_AI_WARN_INPUT_CHARS", "6000") or "6000")
AI_REVIEW_MAX_COMPLETION_TOKENS = int(env_str("SPAMFIGHTER_AI_MAX_OUTPUT_TOKENS", "750") or "750")
AI_REVIEW_DAILY_REQUEST_LIMIT = int(env_str("SPAMFIGHTER_AI_DAILY_REQUEST_LIMIT", "100") or "100")
AI_REVIEW_MONTHLY_REQUEST_LIMIT = int(env_str("SPAMFIGHTER_AI_MONTHLY_REQUEST_LIMIT", "2000") or "2000")
AI_REVIEW_DAILY_INPUT_TOKEN_LIMIT = int(env_str("SPAMFIGHTER_AI_DAILY_INPUT_TOKEN_LIMIT", "1750000") or "1750000")
AI_REVIEW_MONTHLY_INPUT_TOKEN_LIMIT = int(env_str("SPAMFIGHTER_AI_MONTHLY_INPUT_TOKEN_LIMIT", "52500000") or "52500000")
AI_REVIEW_DAILY_OUTPUT_TOKEN_LIMIT = int(env_str("SPAMFIGHTER_AI_DAILY_OUTPUT_TOKEN_LIMIT", "750000") or "750000")
AI_REVIEW_MONTHLY_OUTPUT_TOKEN_LIMIT = int(env_str("SPAMFIGHTER_AI_MONTHLY_OUTPUT_TOKEN_LIMIT", "22500000") or "22500000")
KNOWN_IMAGE_HASH_MAX_BYTES = int(env_str("SPAMFIGHTER_IMAGE_HASH_MAX_BYTES", str(8 * 1024 * 1024)) or str(8 * 1024 * 1024))
KNOWN_IMAGE_HASH_EXTENSIONS = {".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp"}
LIVE_IMAGE_HASH_MODE = (env_str("SPAMFIGHTER_LIVE_IMAGE_HASH_MODE", "suspicious") or "suspicious").strip().lower()
LIVE_IMAGE_HASH_SUSPICIOUS_TEXT_MAX_CHARS = int(
    env_str("SPAMFIGHTER_LIVE_IMAGE_HASH_SUSPICIOUS_TEXT_MAX_CHARS", "48") or "48"
)
REPORTER_DENIAL_COOLDOWN_HOURS = int(env_str("SPAMFIGHTER_REPORT_DENIAL_COOLDOWN_HOURS", "2") or "2")
REPORTER_DENIAL_LIMIT_PER_DAY = int(env_str("SPAMFIGHTER_REPORT_DENIAL_LIMIT_PER_DAY", "2") or "2")
INSTANCE_ROLE = (env_str("SPAMFIGHTER_INSTANCE_ROLE", "auto") or "auto").strip().lower()
INSTANCE_ID = (
    env_str("SPAMFIGHTER_INSTANCE_ID")
    or f"{socket.gethostname()}-{os.getpid()}-{uuid.uuid4().hex[:8]}"
)
INSTANCE_LEASE_KEY = env_str("SPAMFIGHTER_INSTANCE_LEASE_KEY", "spamfighter:leader") or "spamfighter:leader"
INSTANCE_LEASE_SECONDS = int(env_str("SPAMFIGHTER_INSTANCE_LEASE_SECONDS", "60") or "60")
INSTANCE_ROLE_REFRESH_SECONDS = int(env_str("SPAMFIGHTER_INSTANCE_ROLE_REFRESH_SECONDS", "15") or "15")
STATE_REFRESH_INTERVAL_SECONDS = int(env_str("SPAMFIGHTER_STATE_REFRESH_INTERVAL_SECONDS", "20") or "20")
STATE_RETENTION_INTERVAL_SECONDS = int(env_str("SPAMFIGHTER_STATE_RETENTION_INTERVAL_SECONDS", "900") or "900")
RULE_REPORT_RETENTION_DAYS = int(env_str("SPAMFIGHTER_RULE_REPORT_RETENTION_DAYS", "30") or "30")
REPORTER_EVENT_RETENTION_DAYS = int(env_str("SPAMFIGHTER_REPORTER_EVENT_RETENTION_DAYS", "90") or "90")
ATTACHMENT_HASH_CACHE_LIMIT = int(env_str("SPAMFIGHTER_ATTACHMENT_HASH_CACHE_LIMIT", "4096") or "4096")
ATTACHMENT_HASH_CACHE_TTL_SECONDS = int(env_str("SPAMFIGHTER_ATTACHMENT_HASH_CACHE_TTL_SECONDS", "21600") or "21600")
KNOWN_USER_CACHE_TTL_SECONDS = int(env_str("SPAMFIGHTER_KNOWN_USER_CACHE_TTL_SECONDS", "86400") or "86400")
KNOWN_USER_CACHE_MAX_USERS_PER_GUILD = int(
    env_str("SPAMFIGHTER_KNOWN_USER_CACHE_MAX_USERS_PER_GUILD", "5000") or "5000"
)
MODERATION_LOG_QUEUE_LIMIT = int(env_str("SPAMFIGHTER_MODERATION_LOG_QUEUE_LIMIT", "1000") or "1000")
CPU_WORKER_THREADS = max(
    2,
    int(
        env_str(
            "SPAMFIGHTER_CPU_WORKER_THREADS",
            str(max(2, min(32, (os.cpu_count() or 2) * 2))),
        )
        or str(max(2, min(32, (os.cpu_count() or 2) * 2)))
    ),
)
STARTUP_COMMAND_SYNC_ENABLED = (env_str("SPAMFIGHTER_STARTUP_COMMAND_SYNC", "true") or "true").lower() not in {"0", "false", "no", "off"}
HEALTHCHECK_HOST = env_str("SPAMFIGHTER_HEALTHCHECK_HOST", "0.0.0.0") or "0.0.0.0"
HEALTHCHECK_PORT = int(env_str("SPAMFIGHTER_HEALTHCHECK_PORT", "8080") or "8080")
HEALTHCHECK_STALE_SECONDS = int(env_str("SPAMFIGHTER_HEALTHCHECK_STALE_SECONDS", "180") or "180")
HEALTHCHECK_STARTUP_GRACE_SECONDS = int(env_str("SPAMFIGHTER_HEALTHCHECK_STARTUP_GRACE_SECONDS", "180") or "180")
WATCHDOG_INTERVAL_SECONDS = int(env_str("SPAMFIGHTER_WATCHDOG_INTERVAL_SECONDS", "30") or "30")
WATCHDOG_ENABLED = (env_str("SPAMFIGHTER_WATCHDOG_ENABLED", "true") or "true").lower() not in {"0", "false", "no", "off"}
GATEWAY_RESUME_LOG_MIN_SECONDS = float(
    env_str("SPAMFIGHTER_GATEWAY_RESUME_LOG_MIN_SECONDS", "30") or "30"
)
DISCORD_CONNECT_RETRY_BASE_SECONDS = float(
    env_str("SPAMFIGHTER_CONNECT_RETRY_BASE_SECONDS", "5") or "5"
)
DISCORD_CONNECT_RETRY_MAX_SECONDS = float(
    env_str("SPAMFIGHTER_CONNECT_RETRY_MAX_SECONDS", "60") or "60"
)
SAFE_REGEX_TIMEOUT_SECONDS = float(env_str("SPAMFIGHTER_SAFE_REGEX_TIMEOUT_SECONDS", "0.05") or "0.05")
MAX_DYNAMIC_REGEX_PATTERN_LEN = int(env_str("SPAMFIGHTER_MAX_DYNAMIC_REGEX_PATTERN_LEN", "240") or "240")
RETRO_SCAN_LEASE_KEY = env_str("SPAMFIGHTER_RETRO_SCAN_LEASE_KEY", "spamfighter:retro-scan") or "spamfighter:retro-scan"
RETRO_SCAN_LEASE_SECONDS = int(env_str("SPAMFIGHTER_RETRO_SCAN_LEASE_SECONDS", "300") or "300")

MODEL_PRICING_PER_MILLION: Dict[str, Dict[str, float]] = {
    "gpt-5.4": {"input": 2.50, "output": 15.00},
    "gpt-5.4-mini": {"input": 0.25, "output": 2.00},
    "gpt-5-mini": {"input": 0.25, "output": 2.00},
}

AUDIT_DETAIL_CACHE_LIMIT = 500

MANAGED_RULE_HOOK_NAMES = (
    "ticket_words",
    "ticket_context",
    "ticket_contact",
    "anti_ticket",
    "giveaway_intent",
    "giveaway_item",
    "giveaway_contact",
    "anti_giveaway",
    "job_role",
    "job_remote",
    "job_pay",
    "job_tasks",
    "job_response",
    "academic_intent",
    "academic_contact",
)
MANAGED_RULE_REASONS = {
    "ticket_resale",
    "giveaway_spam",
    "job_spam",
    "academic_spam",
    "known_spam_artifact",
}
DOMAIN_BLOCKLIST_KEYS = ("porn", "malicious", "custom")
DOMAIN_BLOCKLIST_DISPLAY_NAMES = {
    "porn": "Porn Sites",
    "malicious": "Malicious Sites",
    "custom": "Custom Sites",
}
DOMAIN_BLOCKLIST_REASON_MAP = {
    "porn": "blocked_porn_domain",
    "malicious": "blocked_malicious_domain",
    "custom": "blocked_custom_domain",
}
DOMAIN_BLOCKLIST_PATHS = {
    "porn": PORN_DOMAIN_BLOCKLIST_PATH,
    "malicious": MALICIOUS_DOMAIN_BLOCKLIST_PATH,
    "custom": CUSTOM_DOMAIN_BLOCKLIST_PATH,
}

DEFAULT_RULE_SUGGESTION_PROMPT = (
    "You are maintaining SpamFighter's regex-based Discord spam rules. "
    "Analyze the reported message and propose the smallest safe change that catches the report "
    "while preserving the current detector behavior. If the current detector already matched and the message appears "
    "to be robustly covered by multiple independent signals, prefer ignore unless you can identify a concrete uncovered "
    "syntax or evasion that should be captured explicitly. Prefer exact artifact values for image-only spam, "
    "prefer extending an existing hook before inventing a brand new custom rule, and never broaden a rule "
    "without explaining likely false-positive risks."
)
OPENAI_RULE_SYSTEM_PROMPT = (
    "You are a security-focused coding assistant helping maintain regex-based Discord spam rules. "
    "Return JSON only and prefer the smallest safe rule addition."
)
OPENAI_RULE_RESPONSE_SCHEMA = {
    "name": "spamfighter_rule_suggestion",
    "strict": True,
    "schema": {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "decision": {"type": "string", "enum": ["ignore", "propose"]},
            "target_type": {"type": "string", "enum": ["", "artifact", "hook", "custom_rule"]},
            "target_name": {"type": "string"},
            "reason": {"type": "string"},
            "pattern": {"type": "string"},
            "exact_values": {
                "type": "array",
                "items": {"type": "string"},
            },
            "custom_rule_id": {"type": "string"},
            "description": {"type": "string"},
            "rationale": {"type": "string"},
            "confidence": {"type": "string", "enum": ["", "low", "medium", "high"]},
            "tests": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "text": {"type": "string"},
                        "should_match": {"type": "boolean"},
                        "note": {"type": "string"},
                    },
                    "required": ["text", "should_match", "note"],
                },
            },
            "enhancement_prompt": {"type": "string"},
        },
        "required": [
            "decision",
            "target_type",
            "target_name",
            "reason",
            "pattern",
            "exact_values",
            "custom_rule_id",
            "description",
            "rationale",
            "confidence",
            "tests",
            "enhancement_prompt",
        ],
    },
}


async def mutate_config(mutator: Callable[[dict], None]) -> Config:
    async with CONFIG_LOCK:
        raw = load_raw_config_dict(str(CONFIG_PATH))
        mutator(raw)
        new_config = parse_config_dict(raw)
        validate_config(new_config)
        save_raw_config_dict(raw, str(CONFIG_PATH))
        apply_config(new_config)
        return new_config


# ============================================================
# Managed spam rules
# ============================================================

@dataclass(frozen=True)
class ManagedCustomRule:
    rule_id: str
    reason: str
    pattern: str
    enabled: bool = True
    description: str = ""
    source: str = "manual"
    created_at: str = ""
    approved_by: str = ""
    report_id: str = ""


@dataclass(frozen=True)
class SpamRulesConfig:
    schema_version: int
    artifact_values: Tuple[str, ...]
    image_hashes: Tuple[str, ...]
    hooks: Dict[str, Tuple[str, ...]]
    custom_rules: Tuple[ManagedCustomRule, ...]


def default_spam_rules_raw() -> dict:
    return {
        "custom_rules": [],
        "meta": {
            "schema_version": 1,
        },
        "artifacts": {
            "values": [],
        },
        "image_hashes": {
            "sha256": [],
        },
        "hooks": {name: [] for name in MANAGED_RULE_HOOK_NAMES},
    }


def parse_spam_rules_from_raw(raw: dict) -> SpamRulesConfig:
    meta_raw = raw.get("meta", {})
    artifacts_raw = raw.get("artifacts", {})
    image_hashes_raw = raw.get("image_hashes", {})
    hooks_raw = raw.get("hooks", {})
    custom_rules_raw = raw.get("custom_rules", artifacts_raw.get("custom_rules", []))

    hooks: Dict[str, Tuple[str, ...]] = {}
    for hook_name in MANAGED_RULE_HOOK_NAMES:
        values = hooks_raw.get(hook_name, [])
        if values is None:
            values = []
        hooks[hook_name] = tuple(str(value) for value in values if str(value).strip())

    custom_rules: List[ManagedCustomRule] = []
    for item in custom_rules_raw:
        if not isinstance(item, dict):
            continue
        custom_rules.append(
            ManagedCustomRule(
                rule_id=str(item.get("id", "")).strip(),
                reason=str(item.get("reason", "")).strip(),
                pattern=str(item.get("pattern", "")).strip(),
                enabled=bool(item.get("enabled", True)),
                description=str(item.get("description", "")).strip(),
                source=str(item.get("source", "manual")).strip(),
                created_at=str(item.get("created_at", "")).strip(),
                approved_by=str(item.get("approved_by", "")).strip(),
                report_id=str(item.get("report_id", "")).strip(),
            )
        )

    return SpamRulesConfig(
        schema_version=int(meta_raw.get("schema_version", 1) or 1),
        artifact_values=tuple(str(value) for value in artifacts_raw.get("values", []) if str(value).strip()),
        image_hashes=tuple(
            str(value).split(":", 1)[1].strip().lower() if str(value).lower().startswith("sha256:") else str(value).strip().lower()
            for value in image_hashes_raw.get("sha256", [])
            if str(value).strip()
        ),
        hooks=hooks,
        custom_rules=tuple(custom_rules),
    )


def is_spam_rules_postgres_enabled() -> bool:
    return bool(SPAM_RULES_DATABASE_URL)


def _load_spam_rules_raw_from_postgres_sync() -> dict:
    if not SPAM_RULES_DATABASE_URL:
        raise RuntimeError("Postgres rules backend is not configured.")
    if psycopg is None:
        raise RuntimeError("psycopg is not installed. Install psycopg to use SPAMFIGHTER_SPAM_RULES_DATABASE_URL.")

    with psycopg.connect(SPAM_RULES_DATABASE_URL) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS spamfighter_managed_rules (
                    id SMALLINT PRIMARY KEY CHECK (id = 1),
                    payload JSONB NOT NULL,
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
                """
            )
            cur.execute("SELECT payload FROM spamfighter_managed_rules WHERE id = 1")
            row = cur.fetchone()
            if row is None:
                raw = normalize_spam_rules_raw(default_spam_rules_raw())
                cur.execute(
                    """
                    INSERT INTO spamfighter_managed_rules (id, payload, updated_at)
                    VALUES (1, %s, NOW())
                    """,
                    (json.dumps(raw),),
                )
                conn.commit()
                return raw
            payload = row[0]
            if isinstance(payload, str):
                raw = json.loads(payload)
            else:
                raw = dict(payload)
            return normalize_spam_rules_raw(raw)


def _save_spam_rules_raw_to_postgres_sync(raw: dict) -> None:
    if not SPAM_RULES_DATABASE_URL:
        raise RuntimeError("Postgres rules backend is not configured.")
    if psycopg is None:
        raise RuntimeError("psycopg is not installed. Install psycopg to use SPAMFIGHTER_SPAM_RULES_DATABASE_URL.")

    normalized = normalize_spam_rules_raw(raw)
    with psycopg.connect(SPAM_RULES_DATABASE_URL) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS spamfighter_managed_rules (
                    id SMALLINT PRIMARY KEY CHECK (id = 1),
                    payload JSONB NOT NULL,
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
                """
            )
            cur.execute(
                """
                INSERT INTO spamfighter_managed_rules (id, payload, updated_at)
                VALUES (1, %s, NOW())
                ON CONFLICT (id) DO UPDATE
                SET payload = EXCLUDED.payload, updated_at = NOW()
                """,
                (json.dumps(normalized),),
            )
            conn.commit()


async def load_spam_rules_raw_from_postgres() -> dict:
    return await asyncio.to_thread(_load_spam_rules_raw_from_postgres_sync)


async def save_spam_rules_raw_to_postgres(raw: dict) -> None:
    await asyncio.to_thread(_save_spam_rules_raw_to_postgres_sync, raw)


def ensure_spam_rules_file(path: Path = SPAM_RULES_PATH) -> None:
    if path.exists():
        return
    lines = [
        "custom_rules = []",
        "",
        "[meta]",
        "schema_version = 1",
        "",
        "[artifacts]",
        "values = []",
        "",
        "[image_hashes]",
        "sha256 = []",
        "",
        "[hooks]",
    ]
    for hook_name in MANAGED_RULE_HOOK_NAMES:
        lines.append(f"{hook_name} = []")
    lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


def normalize_spam_rules_raw(raw: dict) -> dict:
    meta = raw.setdefault("meta", {})
    meta["schema_version"] = int(meta.get("schema_version", 1) or 1)

    artifacts = raw.setdefault("artifacts", {})
    artifacts.setdefault("values", [])

    if "custom_rules" not in raw:
        if isinstance(meta.get("custom_rules"), list):
            raw["custom_rules"] = meta.pop("custom_rules")
        elif isinstance(artifacts.get("custom_rules"), list):
            raw["custom_rules"] = artifacts.pop("custom_rules")
        else:
            raw["custom_rules"] = []
    else:
        raw.setdefault("custom_rules", [])

    image_hashes = raw.setdefault("image_hashes", {})
    image_hashes.setdefault("sha256", [])

    hooks = raw.setdefault("hooks", {})
    for hook_name in MANAGED_RULE_HOOK_NAMES:
        hooks.setdefault(hook_name, [])

    return raw


def load_spam_rules(path: Path = SPAM_RULES_PATH) -> SpamRulesConfig:
    if is_spam_rules_postgres_enabled():
        raw = _load_spam_rules_raw_from_postgres_sync()
        config = parse_spam_rules_from_raw(raw)
        validate_spam_rules(config)
        return config

    ensure_spam_rules_file(path)

    with path.open("rb") as handle:
        raw = tomllib.load(handle)

    needs_schema_rewrite = (
        "custom_rules" not in raw
        and (
            isinstance(raw.get("meta", {}).get("custom_rules"), list)
            or isinstance(raw.get("artifacts", {}).get("custom_rules"), list)
        )
    )
    raw = normalize_spam_rules_raw(raw)
    if needs_schema_rewrite and tomli_w is not None:
        try:
            save_raw_config_dict(raw, str(path))
        except OSError:
            pass

    config = parse_spam_rules_from_raw(raw)
    validate_spam_rules(config)
    return config


def assess_dynamic_regex_safety(pattern: str) -> Tuple[bool, str]:
    normalized = pattern.strip()
    if not normalized:
        return False, "Pattern cannot be blank."
    if len(normalized) > MAX_DYNAMIC_REGEX_PATTERN_LEN:
        return False, f"Pattern is too long ({len(normalized)} chars). Keep dynamic rules at or below {MAX_DYNAMIC_REGEX_PATTERN_LEN} chars."
    if re.search(r"\\[1-9]", normalized):
        return False, "Backreferences are not allowed in dynamic SpamFighter rules."
    if re.search(r"\((?:[^()\\]|\\.)*[+*](?:[^()\\]|\\.)*\)[+*{]", normalized):
        return False, "Nested quantifiers are not allowed in dynamic SpamFighter rules."
    if normalized.count("|") > 20:
        return False, "Dynamic SpamFighter rules cannot use more than 20 alternations."
    return True, "ok"


def compile_dynamic_regex(pattern: str, *, where: str) -> safe_regex.Pattern[str]:
    allowed, reason = assess_dynamic_regex_safety(pattern)
    if not allowed:
        raise ValueError(f"{where} failed regex safety review: {reason}")
    try:
        compiled = safe_regex.compile(pattern)
    except safe_regex.error as exc:
        raise ValueError(f"{where} has invalid regex: {exc}") from exc

    try:
        compiled.search("discord student chat " * 200, timeout=SAFE_REGEX_TIMEOUT_SECONDS)
    except TimeoutError as exc:
        raise ValueError(f"{where} timed out during regex safety validation") from exc
    return compiled


def safe_dynamic_regex_search(compiled: safe_regex.Pattern[str], text: str) -> bool:
    try:
        return bool(compiled.search(text, timeout=SAFE_REGEX_TIMEOUT_SECONDS))
    except TimeoutError:
        log.warning("Timed out while evaluating a managed SpamFighter regex pattern.")
        return False
    except safe_regex.error:
        return False


def validate_spam_rules(config: SpamRulesConfig) -> None:
    if config.schema_version <= 0:
        raise ValueError("spam_rules.meta.schema_version must be positive")

    for hash_value in config.image_hashes:
        if not re.fullmatch(r"[a-f0-9]{64}", hash_value):
            raise ValueError(f"spam_rules.image_hashes contains an invalid sha256 value: {hash_value!r}")

    for hook_name, patterns in config.hooks.items():
        if hook_name not in MANAGED_RULE_HOOK_NAMES:
            raise ValueError(f"spam_rules.hooks.{hook_name} is not a supported managed hook")
        for index, pattern in enumerate(patterns, start=1):
            compile_dynamic_regex(pattern, where=f"spam_rules.hooks.{hook_name}[{index}]")

    for rule in config.custom_rules:
        if not rule.rule_id:
            raise ValueError("spam_rules.custom_rules contains an entry with a blank id")
        if rule.reason not in MANAGED_RULE_REASONS:
            raise ValueError(f"spam_rules.custom_rules.{rule.rule_id} uses unsupported reason {rule.reason!r}")
        if not rule.pattern:
            raise ValueError(f"spam_rules.custom_rules.{rule.rule_id} has a blank pattern")
        compile_dynamic_regex(rule.pattern, where=f"spam_rules.custom_rules.{rule.rule_id}")


SPAM_RULES_LOCK = asyncio.Lock()
SPAM_RULES = SpamRulesConfig(schema_version=1, artifact_values=tuple(), image_hashes=tuple(), hooks={name: tuple() for name in MANAGED_RULE_HOOK_NAMES}, custom_rules=tuple())
MANAGED_KNOWN_SPAM_ARTIFACTS: Tuple[str, ...] = tuple()
MANAGED_KNOWN_IMAGE_HASHES: Set[str] = set()
MANAGED_HOOK_PATTERNS: Dict[str, Tuple[safe_regex.Pattern[str], ...]] = {name: tuple() for name in MANAGED_RULE_HOOK_NAMES}
MANAGED_CUSTOM_RULES: Tuple[ManagedCustomRule, ...] = tuple()
MANAGED_CUSTOM_RULE_PATTERNS: Dict[str, safe_regex.Pattern[str]] = {}


def apply_spam_rules(config: SpamRulesConfig) -> None:
    global SPAM_RULES, MANAGED_KNOWN_SPAM_ARTIFACTS, MANAGED_HOOK_PATTERNS
    global MANAGED_CUSTOM_RULES, MANAGED_CUSTOM_RULE_PATTERNS, MANAGED_KNOWN_IMAGE_HASHES

    SPAM_RULES = config
    MANAGED_KNOWN_SPAM_ARTIFACTS = tuple(normalize_for_scan(value) for value in config.artifact_values if value)
    MANAGED_KNOWN_IMAGE_HASHES = {value.lower() for value in config.image_hashes}
    MANAGED_HOOK_PATTERNS = {
        hook_name: tuple(
            compile_dynamic_regex(pattern, where=f"spam_rules.hooks.{hook_name}")
            for pattern in config.hooks.get(hook_name, tuple())
        )
        for hook_name in MANAGED_RULE_HOOK_NAMES
    }
    MANAGED_CUSTOM_RULES = tuple(rule for rule in config.custom_rules if rule.enabled)
    MANAGED_CUSTOM_RULE_PATTERNS = {
        rule.rule_id: compile_dynamic_regex(rule.pattern, where=f"spam_rules.custom_rules.{rule.rule_id}")
        for rule in MANAGED_CUSTOM_RULES
    }


def rotate_spam_rule_backups(directory: Path = SPAM_RULES_HISTORY_DIR, keep: int = SPAM_RULES_BACKUP_LIMIT) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    backups = sorted(directory.glob("spam_rules-*.toml"), key=lambda item: item.stat().st_mtime, reverse=True)
    for backup in backups[keep:]:
        try:
            backup.unlink()
        except OSError:
            pass


def write_spam_rules_backup(path: Path = SPAM_RULES_PATH, directory: Path = SPAM_RULES_HISTORY_DIR) -> None:
    if not path.exists():
        return
    directory.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-%f")
    backup_path = directory / f"spam_rules-{stamp}.toml"
    backup_path.write_bytes(path.read_bytes())
    rotate_spam_rule_backups(directory)


async def mutate_spam_rules(mutator: Callable[[dict], None]) -> SpamRulesConfig:
    async with SPAM_RULES_LOCK:
        if is_spam_rules_postgres_enabled():
            raw = normalize_spam_rules_raw(await load_spam_rules_raw_from_postgres())
            mutator(raw)
            await save_spam_rules_raw_to_postgres(raw)
            new_rules = load_spam_rules(SPAM_RULES_PATH)
            apply_spam_rules(new_rules)
            return new_rules

        ensure_spam_rules_file(SPAM_RULES_PATH)
        raw = normalize_spam_rules_raw(load_raw_config_dict(str(SPAM_RULES_PATH)))
        write_spam_rules_backup(SPAM_RULES_PATH)
        mutator(raw)
        save_raw_config_dict(raw, str(SPAM_RULES_PATH))
        new_rules = load_spam_rules(SPAM_RULES_PATH)
        apply_spam_rules(new_rules)
        return new_rules


def list_spam_rule_backups(directory: Path = SPAM_RULES_HISTORY_DIR) -> List[Path]:
    if not directory.exists():
        return []
    return sorted(directory.glob("spam_rules-*.toml"), key=lambda item: item.stat().st_mtime, reverse=True)


async def restore_spam_rules_backup(backup_name: str) -> SpamRulesConfig:
    if is_spam_rules_postgres_enabled():
        raise RuntimeError("Backup rollback is unavailable while Postgres rules backend is enabled.")
    backups = {path.name: path for path in list_spam_rule_backups()}
    backup_path = backups.get(backup_name)
    if backup_path is None:
        raise FileNotFoundError("That backup file was not found in spam_rules_history.")

    async with SPAM_RULES_LOCK:
        ensure_spam_rules_file(SPAM_RULES_PATH)
        write_spam_rules_backup(SPAM_RULES_PATH)
        SPAM_RULES_PATH.write_bytes(backup_path.read_bytes())
        raw = normalize_spam_rules_raw(load_raw_config_dict(str(SPAM_RULES_PATH)))
        save_raw_config_dict(raw, str(SPAM_RULES_PATH))
        new_rules = load_spam_rules(SPAM_RULES_PATH)
        apply_spam_rules(new_rules)
        return new_rules


# ============================================================
# Domain blocklists
# ============================================================

DOMAIN_HOST_RE = re.compile(r"a\A")
URL_CANDIDATE_RE = re.compile(r"a\A")
PLAIN_DOMAIN_CANDIDATE_RE = re.compile(r"a\A")
URL_TRAILING_PUNCTUATION = ".,;:!?)]}\"'>"


def normalize_domain_blocklist_key(value: str) -> str:
    normalized = str(value or "").strip().lower()
    if normalized not in DOMAIN_BLOCKLIST_KEYS:
        raise ValueError("Unsupported blocklist. Choose porn, malicious, or custom.")
    return normalized


def ensure_domain_blocklist_files() -> None:
    DOMAIN_BLOCKLISTS_DIR.mkdir(parents=True, exist_ok=True)
    for path in DOMAIN_BLOCKLIST_PATHS.values():
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            path.touch()


def is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def normalize_domain_candidate(value: str) -> Optional[str]:
    cleaned = str(value or "").strip()
    if not cleaned:
        return None

    cleaned = cleaned.strip(" <>[](){}\"'`")
    if not cleaned:
        return None
    if cleaned.startswith(("!", "#", ";", "//", "@@")):
        return None

    cleaned = cleaned.split("$", 1)[0].strip()
    cleaned = cleaned.lstrip("|")
    if cleaned.startswith("*."):
        cleaned = cleaned[2:]
    cleaned = cleaned.lstrip(".")
    if not cleaned:
        return None

    host: Optional[str]
    if "://" in cleaned:
        host = urlsplit(cleaned).hostname
    else:
        if "/" in cleaned:
            cleaned = cleaned.split("/", 1)[0].strip()
        if cleaned.startswith("[") and "]" in cleaned:
            cleaned = cleaned[1:cleaned.index("]")]
        elif cleaned.count(":") == 1:
            possible_host, possible_port = cleaned.rsplit(":", 1)
            if possible_port.isdigit():
                cleaned = possible_host
        host = cleaned

    if not host:
        return None

    normalized_host = host.strip().strip(".").lower()
    if not normalized_host or normalized_host == "localhost":
        return None

    try:
        normalized_host = normalized_host.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None

    normalized_host = normalized_host.rstrip(".")
    if not normalized_host:
        return None
    if is_ip_address(normalized_host):
        return normalized_host
    if len(normalized_host) > 253:
        return None
    if DOMAIN_HOST_RE.fullmatch(normalized_host) is None:
        return None
    return normalized_host


def extract_domains_from_blocklist_line(line: str) -> List[str]:
    stripped = str(line or "").strip()
    if not stripped:
        return []
    if stripped.startswith(("!", "#", ";", "//")):
        return []

    parts = stripped.split()
    if not parts:
        return []

    tokens = parts
    if len(parts) >= 2 and is_ip_address(parts[0]):
        tokens = parts[1:]

    domains: List[str] = []
    seen: Set[str] = set()
    for token in tokens:
        normalized = normalize_domain_candidate(token)
        if normalized and normalized not in seen:
            seen.add(normalized)
            domains.append(normalized)
    return domains


def _load_domain_blocklist_file(path: Path) -> frozenset[str]:
    domains: Set[str] = set()
    if not path.exists():
        return frozenset()

    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            domains.update(extract_domains_from_blocklist_line(line))

    return frozenset(domains)


def _current_domain_blocklist_mtime(path: Path) -> int:
    if not path.exists():
        return -1
    return int(path.stat().st_mtime_ns)


def _append_domain_to_blocklist_file(path: Path, domain: str) -> bool:
    ensure_domain_blocklist_files()

    existing = _load_domain_blocklist_file(path)
    if domain in existing:
        return False

    needs_leading_newline = False
    if path.exists() and path.stat().st_size > 0:
        with path.open("rb") as handle:
            handle.seek(-1, os.SEEK_END)
            needs_leading_newline = handle.read(1) not in {b"\n", b"\r"}

    with path.open("a", encoding="utf-8", newline="\n") as handle:
        if needs_leading_newline:
            handle.write("\n")
        handle.write(domain + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    return True


async def refresh_domain_blocklists(*, force: bool = False) -> Dict[str, int]:
    async with DOMAIN_BLOCKLISTS_LOCK:
        await asyncio.to_thread(ensure_domain_blocklist_files)

        keys_to_reload: List[str] = []
        for key, path in DOMAIN_BLOCKLIST_PATHS.items():
            current_mtime = await asyncio.to_thread(_current_domain_blocklist_mtime, path)
            previous_mtime = DOMAIN_BLOCKLIST_SOURCE_MTIMES.get(key)
            if force or previous_mtime is None or previous_mtime != current_mtime:
                keys_to_reload.append(key)

        if not keys_to_reload and LOADED_DOMAIN_BLOCKLISTS:
            return {key: len(LOADED_DOMAIN_BLOCKLISTS.get(key, frozenset())) for key in DOMAIN_BLOCKLIST_KEYS}

        loaded_at = utcnow()
        for key in keys_to_reload or DOMAIN_BLOCKLIST_KEYS:
            path = DOMAIN_BLOCKLIST_PATHS[key]
            domains = await asyncio.to_thread(_load_domain_blocklist_file, path)
            LOADED_DOMAIN_BLOCKLISTS[key] = domains
            DOMAIN_BLOCKLIST_SOURCE_MTIMES[key] = await asyncio.to_thread(_current_domain_blocklist_mtime, path)
            DOMAIN_BLOCKLIST_LAST_LOADED_AT[key] = loaded_at

        for key in DOMAIN_BLOCKLIST_KEYS:
            LOADED_DOMAIN_BLOCKLISTS.setdefault(key, frozenset())

        return {key: len(LOADED_DOMAIN_BLOCKLISTS.get(key, frozenset())) for key in DOMAIN_BLOCKLIST_KEYS}


async def load_guild_domain_blocklist_settings() -> None:
    GUILD_DOMAIN_BLOCKLIST_SETTINGS.clear()
    async with STATE_DB_LOCK:
        connection = await get_state_db_connection()
        rows = await (
            await connection.execute(
                """
                SELECT guild_id, blocklist_key
                FROM guild_domain_blocklists
                ORDER BY guild_id, blocklist_key
                """
            )
        ).fetchall()

    for row in rows:
        guild_id = int(row["guild_id"] or 0)
        blocklist_key = str(row["blocklist_key"] or "").strip().lower()
        if guild_id > 0 and blocklist_key in DOMAIN_BLOCKLIST_KEYS:
            GUILD_DOMAIN_BLOCKLIST_SETTINGS[guild_id].add(blocklist_key)


async def set_guild_domain_blocklist_enabled(guild_id: int, blocklist_key: str, *, enabled: bool) -> None:
    normalized_key = normalize_domain_blocklist_key(blocklist_key)

    async with STATE_DB_LOCK:
        connection = await get_state_db_connection()
        if enabled:
            await connection.execute(
                """
                INSERT INTO guild_domain_blocklists (guild_id, blocklist_key, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(guild_id, blocklist_key) DO UPDATE SET
                    updated_at = excluded.updated_at
                """,
                (guild_id, normalized_key, utcnow().isoformat()),
            )
        else:
            await connection.execute(
                "DELETE FROM guild_domain_blocklists WHERE guild_id = ? AND blocklist_key = ?",
                (guild_id, normalized_key),
            )
        await connection.commit()

    if enabled:
        GUILD_DOMAIN_BLOCKLIST_SETTINGS[guild_id].add(normalized_key)
    else:
        GUILD_DOMAIN_BLOCKLIST_SETTINGS[guild_id].discard(normalized_key)
        if not GUILD_DOMAIN_BLOCKLIST_SETTINGS[guild_id]:
            GUILD_DOMAIN_BLOCKLIST_SETTINGS.pop(guild_id, None)


def get_enabled_domain_blocklists_for_guild(guild_id: int) -> Set[str]:
    return set(GUILD_DOMAIN_BLOCKLIST_SETTINGS.get(guild_id, set()))


def format_domain_blocklist_label(blocklist_key: str) -> str:
    return DOMAIN_BLOCKLIST_DISPLAY_NAMES.get(blocklist_key, blocklist_key.title())


def format_enabled_domain_blocklists(guild_id: int) -> str:
    enabled = sorted(get_enabled_domain_blocklists_for_guild(guild_id))
    if not enabled:
        return "None enabled"
    return ", ".join(format_domain_blocklist_label(key) for key in enabled)


def trim_url_candidate(value: str) -> str:
    candidate = str(value or "").strip().strip("<>")
    while candidate and candidate[-1] in URL_TRAILING_PUNCTUATION:
        candidate = candidate[:-1]
    return candidate


def extract_url_candidates_from_text(text: str) -> List[str]:
    raw_text = str(text or "")
    if not raw_text:
        return []

    lowered = raw_text.lower()
    if "http://" not in lowered and "https://" not in lowered and "www." not in lowered and "." not in raw_text:
        return []

    candidates: List[str] = []
    seen: Set[str] = set()
    for pattern in (URL_CANDIDATE_RE, PLAIN_DOMAIN_CANDIDATE_RE):
        for match in pattern.finditer(raw_text):
            candidate = trim_url_candidate(match.group(0))
            if not candidate or candidate in seen:
                continue
            seen.add(candidate)
            candidates.append(candidate)
    return candidates


def blocked_domain_for_host(host: str, blocked_domains: Collection[str]) -> Optional[str]:
    normalized_host = normalize_domain_candidate(host)
    if not normalized_host:
        return None
    if normalized_host in blocked_domains:
        return normalized_host
    if is_ip_address(normalized_host):
        return None

    current = normalized_host
    while "." in current:
        current = current.split(".", 1)[1]
        if current in blocked_domains:
            return current
    return None


def match_text_against_domain_blocklists(text: str, enabled_blocklists: Sequence[str]) -> Optional[DomainBlocklistMatch]:
    if not enabled_blocklists:
        return None

    for candidate in extract_url_candidates_from_text(text):
        parse_value = candidate if "://" in candidate else f"http://{candidate}"
        normalized_host = normalize_domain_candidate(parse_value)
        if not normalized_host:
            continue

        for blocklist_key in enabled_blocklists:
            blocked_domains = LOADED_DOMAIN_BLOCKLISTS.get(blocklist_key, frozenset())
            if not blocked_domains:
                continue
            blocked_host = blocked_domain_for_host(normalized_host, blocked_domains)
            if blocked_host is not None:
                return DomainBlocklistMatch(
                    blocklist_key=blocklist_key,
                    blocked_host=blocked_host,
                    matched_host=normalized_host,
                    matched_value=candidate,
                )
    return None


def classify_text_for_guild_domain_blocklists(text: str, guild_id: int) -> Tuple[bool, str, str, Optional[DomainBlocklistMatch]]:
    enabled_blocklists = sorted(get_enabled_domain_blocklists_for_guild(guild_id))
    if not enabled_blocklists:
        return False, "", normalize_for_scan(text), None

    match = match_text_against_domain_blocklists(text, enabled_blocklists)
    if match is None:
        return False, "", normalize_for_scan(text), None

    return True, DOMAIN_BLOCKLIST_REASON_MAP[match.blocklist_key], normalize_for_scan(text), match


def classify_message_for_domain_blocklists(message: discord.Message) -> Tuple[bool, str, str, Optional[DomainBlocklistMatch]]:
    if message.guild is None:
        return False, "", "", None

    enabled_blocklists = sorted(get_enabled_domain_blocklists_for_guild(message.guild.id))
    if not enabled_blocklists:
        return False, "", "", None

    content = message.content or ""
    match = match_text_against_domain_blocklists(content, enabled_blocklists)
    if match is not None:
        return True, DOMAIN_BLOCKLIST_REASON_MAP[match.blocklist_key], normalize_for_scan(content), match

    if message.attachments or message.embeds:
        media_indicators = render_message_media_indicators(message)
        match = match_text_against_domain_blocklists(media_indicators, enabled_blocklists)
        if match is not None:
            return True, DOMAIN_BLOCKLIST_REASON_MAP[match.blocklist_key], normalize_for_scan(media_indicators), match

    return False, "", normalize_for_scan(content), None


async def add_domain_to_named_blocklist(blocklist_key: str, domain_or_url: str) -> Tuple[str, bool, Dict[str, int]]:
    normalized_key = normalize_domain_blocklist_key(blocklist_key)
    normalized_domain = normalize_domain_candidate(domain_or_url)
    if not normalized_domain:
        raise ValueError("Provide a valid domain or URL, such as example.com or https://example.com/path.")

    path = DOMAIN_BLOCKLIST_PATHS[normalized_key]
    added = await asyncio.to_thread(_append_domain_to_blocklist_file, path, normalized_domain)
    counts = await refresh_domain_blocklists(force=True)
    return normalized_domain, added, counts


# ============================================================
# Runtime state
# ============================================================

@dataclass
class RuntimeState:
    paused: bool = False
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    pause_changed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_ready_at: Optional[datetime] = None
    last_gateway_event_at: Optional[datetime] = None
    last_disconnect_at: Optional[datetime] = None
    last_resumed_at: Optional[datetime] = None
    scanned_messages: int = 0
    deleted_messages: int = 0
    matched_messages: int = 0
    last_match_reason: Optional[str] = None
    last_match_at: Optional[datetime] = None


@dataclass
class RetroScanState:
    running: bool = False
    cancelled: bool = False
    guild_id: Optional[int] = None
    guild_name: str = ""
    requested_by: Optional[int] = None
    months: int = 0
    execute: bool = False
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    cutoff_at: Optional[datetime] = None
    channels_total: int = 0
    channels_scanned: int = 0
    channels_skipped: int = 0
    channel_errors: int = 0
    messages_scanned: int = 0
    matched_messages: int = 0
    matched_users: int = 0
    deleted_messages: int = 0
    delete_failures: int = 0
    actions_taken: int = 0
    action_breakdown: Dict[str, int] = field(default_factory=dict)
    last_channel: Optional[str] = None
    last_error: Optional[str] = None
    summary_lines: List[str] = field(default_factory=list)
    recent_match_lines: List[str] = field(default_factory=list)
    rate_limit_hits: int = 0
    adaptive_delay: float = 0.0
    last_retry_after: float = 0.0
    last_rate_limit_at: Optional[datetime] = None
    last_rate_limit_route: Optional[str] = None
    deep_image_hash_scan: bool = False
    validation_mode: bool = False
    scope_label: str = "All accessible text channels"
    selected_channel_ids: List[int] = field(default_factory=list)
    task: Optional[asyncio.Task] = None


@dataclass
class RuleSuggestion:
    decision: str = "pending"
    target_type: str = ""
    target_name: str = ""
    reason: str = ""
    pattern: str = ""
    exact_values: List[str] = field(default_factory=list)
    custom_rule_id: str = ""
    description: str = ""
    rationale: str = ""
    confidence: str = ""
    tests: List[Dict[str, object]] = field(default_factory=list)
    enhancement_prompt: str = ""
    raw_payload: str = ""
    usage: Dict[str, int] = field(default_factory=dict)


@dataclass
class RuleReportState:
    report_id: str
    cluster_key: str
    source_guild_id: int
    source_guild_name: str
    source_channel_id: int
    source_channel_label: str
    source_message_id: int
    source_author_id: int
    source_author_label: str
    source_jump_url: str
    report_kind: str = "spam_report"
    message_content: str = ""
    normalized_content: str = ""
    media_indicators: str = ""
    image_hashes: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_reported_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    reporter_ids: Set[int] = field(default_factory=set)
    report_count: int = 1
    sample_message_ids: List[int] = field(default_factory=list)
    sample_jump_urls: List[str] = field(default_factory=list)
    current_matched: bool = False
    current_reason: str = ""
    status: str = "reported"
    suggestion: Optional[RuleSuggestion] = None
    suggestion_error: Optional[str] = None
    review_guild_id: Optional[int] = None
    review_channel_id: Optional[int] = None
    review_message_id: Optional[int] = None
    detail_message_ids: List[int] = field(default_factory=list)
    last_generated_by: Optional[int] = None
    approved_by: Optional[int] = None
    denied_by: Optional[int] = None
    proposal_generated_at: Optional[datetime] = None
    reporter_confidence: str = "unknown"
    reporter_history_summary: str = ""
    reporter_cooldown_until: Optional[datetime] = None
    validation_status: str = "not_run"
    validation_summary: str = ""
    validation_hit_lines: List[str] = field(default_factory=list)
    validation_ran_at: Optional[datetime] = None
    validation_bypassed_by: Optional[int] = None
    validation_months: int = 0
    validation_channel_ids: List[int] = field(default_factory=list)
    ai_precheck_matched: bool = False
    ai_precheck_reason: str = ""
    ai_precheck_normalized: str = ""
    ai_ignore_approved_by: Optional[int] = None
    staff_notes: str = ""
    task: Optional[asyncio.Task] = None


@dataclass
class AIUsageState:
    daily: Dict[str, Dict[str, int]] = field(default_factory=dict)
    monthly: Dict[str, Dict[str, int]] = field(default_factory=dict)


@dataclass(frozen=True)
class ReporterMetrics:
    total_reports: int = 0
    matched_reports: int = 0
    merged_reports: int = 0
    approved_reports: int = 0
    denied_reports: int = 0
    penalized_denials_last_day: int = 0
    cooldown_until: Optional[datetime] = None
    confidence: str = "medium"


@dataclass(frozen=True)
class PreparedRuleReportCandidate:
    matched: bool
    reason: str
    normalized: str
    media_indicators: str
    image_hashes: List[str]
    cluster_key: str


@dataclass(frozen=True)
class AuditDeletionDetailPayload:
    guild_id: int
    guild_name: str
    source_channel_id: int
    source_channel_mention: str
    source_author_id: int
    source_author_mention: str
    reason: str
    deleted: bool
    normalized_content: str
    media_indicators: str
    image_hashes: Tuple[str, ...] = ()


@dataclass(frozen=True)
class QueuedModerationLog:
    channel_ids: Tuple[int, ...]
    embeds: Tuple[discord.Embed, ...]
    detail_payload: Optional[AuditDeletionDetailPayload] = None


@dataclass(frozen=True)
class CompiledSuggestionMatchers:
    hook_patterns: Dict[str, safe_regex.Pattern[str]] = field(default_factory=dict)
    custom_rule_pattern: Optional[safe_regex.Pattern[str]] = None
    artifact_values: Set[str] = field(default_factory=set)
    hash_values: Set[str] = field(default_factory=set)


@dataclass(frozen=True)
class DomainBlocklistMatch:
    blocklist_key: str
    blocked_host: str
    matched_host: str
    matched_value: str


STATE = RuntimeState()
RETRO_SCAN = RetroScanState()
LAST_KNOWN_USER_LABELS: Dict[int, Dict[int, Set[str]]] = defaultdict(lambda: defaultdict(set))
LAST_KNOWN_USER_LAST_SEEN: Dict[Tuple[int, int], datetime] = {}
RULE_REPORTS: Dict[str, RuleReportState] = {}
RULE_REPORTS_BY_MESSAGE_ID: Dict[int, str] = {}
RULE_REPORTS_BY_CLUSTER: Dict[str, str] = {}
RULE_REPORTS_LOCK = asyncio.Lock()
AI_USAGE = AIUsageState()
AI_USAGE_LOCK = asyncio.Lock()
AUDIT_DETAIL_PAYLOADS: Dict[int, AuditDeletionDetailPayload] = {}
ATTACHMENT_HASH_CACHE: "OrderedDict[int, Tuple[str, datetime]]" = OrderedDict()
STATE_DB_LOCK = asyncio.Lock()
SPAM_RULES_DEPLOY_LOCK = asyncio.Lock()
STATE_DB_CONNECTION: Optional[aiosqlite.Connection] = None
APP_STATE_LOCK = asyncio.Lock()
DISABLED_GUILD_COMMANDS: Dict[int, Set[str]] = defaultdict(set)
CONFIG_DISABLED_COMMANDS_BY_GUILD: Dict[int, Set[str]] = {}
HEALTHCHECK_SERVER: Optional[asyncio.AbstractServer] = None
WATCHDOG_TASK: Optional[asyncio.Task] = None
INSTANCE_ROLE_TASK: Optional[asyncio.Task] = None
STATE_REFRESH_TASK: Optional[asyncio.Task] = None
STATE_RETENTION_TASK: Optional[asyncio.Task] = None
MODERATION_LOG_TASK: Optional[asyncio.Task] = None
SHUTDOWN_LOCK = asyncio.Lock()
SHUTDOWN_REQUESTED = False
EXIT_STATUS = 0
CURRENT_INSTANCE_ROLE = "leader" if INSTANCE_ROLE == "leader" else "follower"
CPU_WORKER_POOL: Optional[concurrent.futures.ThreadPoolExecutor] = None
MODERATION_LOG_QUEUE: "asyncio.Queue[QueuedModerationLog]" = asyncio.Queue(maxsize=max(1, MODERATION_LOG_QUEUE_LIMIT))
DOMAIN_BLOCKLISTS_LOCK = asyncio.Lock()
GUILD_DOMAIN_BLOCKLIST_SETTINGS: Dict[int, Set[str]] = defaultdict(set)
LOADED_DOMAIN_BLOCKLISTS: Dict[str, frozenset[str]] = {}
DOMAIN_BLOCKLIST_SOURCE_MTIMES: Dict[str, int] = {}
DOMAIN_BLOCKLIST_LAST_LOADED_AT: Dict[str, datetime] = {}

RETRO_SCAN_MAX_MONTHS = 12
RETRO_SCAN_CHANNEL_DELAY_SECONDS = 0.35
RETRO_SCAN_DELETE_DELAY_SECONDS = 0.35
RETRO_SCAN_MATCH_PREVIEW_LIMIT = 5
RETRO_SCAN_MATCH_SNIPPET_LIMIT = 60
RATE_LIMIT_WARNING_RE = re.compile(r"a\A")


class DiscordHTTPRateLimitObserver(logging.Handler):
    def emit(self, record: logging.LogRecord) -> None:
        if not RETRO_SCAN.running:
            return

        message = record.getMessage()
        match = RATE_LIMIT_WARNING_RE.search(message)
        if not match:
            return

        retry_after = float(match.group("retry"))
        RETRO_SCAN.rate_limit_hits += 1
        RETRO_SCAN.last_retry_after = retry_after
        RETRO_SCAN.last_rate_limit_at = datetime.now(timezone.utc)
        RETRO_SCAN.last_rate_limit_route = f"{match.group('method')} {match.group('url')}"
        RETRO_SCAN.adaptive_delay = min(5.0, max(RETRO_SCAN.adaptive_delay, retry_after * 2.0))


discord_http_logger = logging.getLogger("discord.http")
if not any(isinstance(handler, DiscordHTTPRateLimitObserver) for handler in discord_http_logger.handlers):
    discord_http_logger.addHandler(DiscordHTTPRateLimitObserver())


APP_STATE_RUNTIME_KEY = "runtime_state"
APP_STATE_RETRO_SCAN_KEY = "retro_scan_state"


def serialize_runtime_state() -> dict:
    return {
        "paused": STATE.paused,
        "pause_changed_at": STATE.pause_changed_at.isoformat() if STATE.pause_changed_at else None,
    }


def apply_runtime_state_payload(payload: Optional[dict]) -> None:
    if not isinstance(payload, dict):
        return
    paused = payload.get("paused")
    if paused is not None:
        STATE.paused = bool(paused)
    pause_changed_at = parse_optional_datetime(str(payload.get("pause_changed_at", "")).strip() or None)
    if pause_changed_at is not None:
        STATE.pause_changed_at = pause_changed_at


def serialize_retro_scan_state() -> dict:
    return {
        "running": RETRO_SCAN.running,
        "cancelled": RETRO_SCAN.cancelled,
        "guild_id": RETRO_SCAN.guild_id,
        "guild_name": RETRO_SCAN.guild_name,
        "requested_by": RETRO_SCAN.requested_by,
        "months": RETRO_SCAN.months,
        "execute": RETRO_SCAN.execute,
        "started_at": RETRO_SCAN.started_at.isoformat() if RETRO_SCAN.started_at else None,
        "finished_at": RETRO_SCAN.finished_at.isoformat() if RETRO_SCAN.finished_at else None,
        "cutoff_at": RETRO_SCAN.cutoff_at.isoformat() if RETRO_SCAN.cutoff_at else None,
        "channels_total": RETRO_SCAN.channels_total,
        "channels_scanned": RETRO_SCAN.channels_scanned,
        "channels_skipped": RETRO_SCAN.channels_skipped,
        "channel_errors": RETRO_SCAN.channel_errors,
        "messages_scanned": RETRO_SCAN.messages_scanned,
        "matched_messages": RETRO_SCAN.matched_messages,
        "matched_users": RETRO_SCAN.matched_users,
        "deleted_messages": RETRO_SCAN.deleted_messages,
        "delete_failures": RETRO_SCAN.delete_failures,
        "actions_taken": RETRO_SCAN.actions_taken,
        "action_breakdown": dict(RETRO_SCAN.action_breakdown),
        "last_channel": RETRO_SCAN.last_channel,
        "last_error": RETRO_SCAN.last_error,
        "summary_lines": list(RETRO_SCAN.summary_lines),
        "recent_match_lines": list(RETRO_SCAN.recent_match_lines),
        "rate_limit_hits": RETRO_SCAN.rate_limit_hits,
        "adaptive_delay": RETRO_SCAN.adaptive_delay,
        "last_retry_after": RETRO_SCAN.last_retry_after,
        "last_rate_limit_at": RETRO_SCAN.last_rate_limit_at.isoformat() if RETRO_SCAN.last_rate_limit_at else None,
        "last_rate_limit_route": RETRO_SCAN.last_rate_limit_route,
        "deep_image_hash_scan": RETRO_SCAN.deep_image_hash_scan,
        "validation_mode": RETRO_SCAN.validation_mode,
        "scope_label": RETRO_SCAN.scope_label,
        "selected_channel_ids": list(RETRO_SCAN.selected_channel_ids),
    }


def apply_retro_scan_payload(
    payload: Optional[dict],
    *,
    preserve_active_task: bool = False,
    mark_running_as_interrupted: bool = False,
) -> None:
    global RETRO_SCAN
    if not isinstance(payload, dict):
        return
    if preserve_active_task and RETRO_SCAN.task is not None and not RETRO_SCAN.task.done():
        return

    restored = RetroScanState(
        running=bool(payload.get("running", False)),
        cancelled=bool(payload.get("cancelled", False)),
        guild_id=int(payload.get("guild_id", 0) or 0) or None,
        guild_name=str(payload.get("guild_name", "")).strip(),
        requested_by=int(payload.get("requested_by", 0) or 0) or None,
        months=int(payload.get("months", 0) or 0),
        execute=bool(payload.get("execute", False)),
        started_at=parse_optional_datetime(str(payload.get("started_at", "")).strip() or None),
        finished_at=parse_optional_datetime(str(payload.get("finished_at", "")).strip() or None),
        cutoff_at=parse_optional_datetime(str(payload.get("cutoff_at", "")).strip() or None),
        channels_total=int(payload.get("channels_total", 0) or 0),
        channels_scanned=int(payload.get("channels_scanned", 0) or 0),
        channels_skipped=int(payload.get("channels_skipped", 0) or 0),
        channel_errors=int(payload.get("channel_errors", 0) or 0),
        messages_scanned=int(payload.get("messages_scanned", 0) or 0),
        matched_messages=int(payload.get("matched_messages", 0) or 0),
        matched_users=int(payload.get("matched_users", 0) or 0),
        deleted_messages=int(payload.get("deleted_messages", 0) or 0),
        delete_failures=int(payload.get("delete_failures", 0) or 0),
        actions_taken=int(payload.get("actions_taken", 0) or 0),
        action_breakdown={
            str(key): int(value)
            for key, value in dict(payload.get("action_breakdown", {})).items()
        },
        last_channel=str(payload.get("last_channel", "")).strip() or None,
        last_error=str(payload.get("last_error", "")).strip() or None,
        summary_lines=[str(value) for value in payload.get("summary_lines", []) if str(value).strip()],
        recent_match_lines=[str(value) for value in payload.get("recent_match_lines", []) if str(value).strip()],
        rate_limit_hits=int(payload.get("rate_limit_hits", 0) or 0),
        adaptive_delay=float(payload.get("adaptive_delay", 0.0) or 0.0),
        last_retry_after=float(payload.get("last_retry_after", 0.0) or 0.0),
        last_rate_limit_at=parse_optional_datetime(str(payload.get("last_rate_limit_at", "")).strip() or None),
        last_rate_limit_route=str(payload.get("last_rate_limit_route", "")).strip() or None,
        deep_image_hash_scan=bool(payload.get("deep_image_hash_scan", False)),
        validation_mode=bool(payload.get("validation_mode", False)),
        scope_label=str(payload.get("scope_label", "All accessible text channels")).strip() or "All accessible text channels",
        selected_channel_ids=trim_unique_int_list(payload.get("selected_channel_ids", []), limit=10),
        task=None,
    )
    if mark_running_as_interrupted and restored.running:
        restored.running = False
        restored.cancelled = True
        restored.finished_at = utcnow()
        restored.last_error = "Bot restarted while a retro scan was still running."
    RETRO_SCAN = restored


def current_instance_role() -> str:
    return CURRENT_INSTANCE_ROLE


def is_current_leader() -> bool:
    return current_instance_role() == "leader"


async def try_acquire_distributed_lease(lease_key: str, *, owner_id: str, ttl_seconds: int) -> bool:
    now = utcnow()
    lease_until = now + timedelta(seconds=max(5, ttl_seconds))
    async with STATE_DB_LOCK:
        connection = await get_state_db_connection()
        await connection.execute(
            """
            INSERT INTO distributed_leases (lease_key, owner_id, lease_until, updated_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(lease_key) DO UPDATE SET
                owner_id = excluded.owner_id,
                lease_until = excluded.lease_until,
                updated_at = excluded.updated_at
            WHERE distributed_leases.owner_id = excluded.owner_id
               OR distributed_leases.lease_until <= excluded.updated_at
            """,
            (lease_key, owner_id, lease_until.isoformat(), now.isoformat()),
        )
        await connection.commit()
        row = await (
            await connection.execute(
                "SELECT owner_id, lease_until FROM distributed_leases WHERE lease_key = ?",
                (lease_key,),
            )
        ).fetchone()
    return row is not None and str(row["owner_id"]) == owner_id


async def release_distributed_lease(lease_key: str, *, owner_id: str) -> None:
    async with STATE_DB_LOCK:
        connection = await get_state_db_connection()
        await connection.execute(
            "DELETE FROM distributed_leases WHERE lease_key = ? AND owner_id = ?",
            (lease_key, owner_id),
        )
        await connection.commit()


async def refresh_instance_role() -> None:
    global CURRENT_INSTANCE_ROLE

    previous_role = CURRENT_INSTANCE_ROLE
    if INSTANCE_ROLE == "leader":
        CURRENT_INSTANCE_ROLE = "leader"
    elif INSTANCE_ROLE == "follower":
        CURRENT_INSTANCE_ROLE = "follower"
    else:
        acquired = await try_acquire_distributed_lease(
            INSTANCE_LEASE_KEY,
            owner_id=INSTANCE_ID,
            ttl_seconds=INSTANCE_LEASE_SECONDS,
        )
        CURRENT_INSTANCE_ROLE = "leader" if acquired else "follower"

    if CURRENT_INSTANCE_ROLE != previous_role:
        log.info(
            "Instance role changed from %s to %s. instance_id=%s mode=%s",
            previous_role,
            CURRENT_INSTANCE_ROLE,
            INSTANCE_ID,
            INSTANCE_ROLE,
        )


async def get_state_db_connection(path: Path = STATE_DB_PATH) -> aiosqlite.Connection:
    global STATE_DB_CONNECTION

    if STATE_DB_CONNECTION is None:
        path.parent.mkdir(parents=True, exist_ok=True)
        connection = await aiosqlite.connect(path)
        connection.row_factory = aiosqlite.Row
        await connection.execute("PRAGMA journal_mode=WAL")
        await connection.execute("PRAGMA synchronous=NORMAL")
        await connection.execute("PRAGMA foreign_keys=ON")
        await connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS rule_reports (
                report_id TEXT PRIMARY KEY,
                source_message_id INTEGER,
                cluster_key TEXT,
                source_guild_id INTEGER,
                status TEXT,
                created_at TEXT,
                last_reported_at TEXT,
                payload TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_rule_reports_source_message ON rule_reports(source_message_id);
            CREATE INDEX IF NOT EXISTS idx_rule_reports_cluster ON rule_reports(cluster_key);
            CREATE INDEX IF NOT EXISTS idx_rule_reports_status_guild ON rule_reports(status, source_guild_id);

            CREATE TABLE IF NOT EXISTS ai_usage (
                kind TEXT NOT NULL,
                bucket_id TEXT NOT NULL,
                requests INTEGER NOT NULL DEFAULT 0,
                prompt_tokens INTEGER NOT NULL DEFAULT 0,
                completion_tokens INTEGER NOT NULL DEFAULT 0,
                total_tokens INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (kind, bucket_id)
            );

            CREATE TABLE IF NOT EXISTS violation_counts (
                guild_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                count INTEGER NOT NULL DEFAULT 0,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (guild_id, user_id)
            );
            CREATE INDEX IF NOT EXISTS idx_violation_counts_guild ON violation_counts(guild_id);

            CREATE TABLE IF NOT EXISTS reporter_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                guild_id INTEGER NOT NULL,
                reporter_id INTEGER NOT NULL,
                report_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                counts_for_cooldown INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_reporter_events_lookup
                ON reporter_events(guild_id, reporter_id, created_at);

            CREATE TABLE IF NOT EXISTS validation_guild_config (
                guild_id INTEGER PRIMARY KEY,
                months INTEGER NOT NULL DEFAULT 3
            );

            CREATE TABLE IF NOT EXISTS validation_channels (
                guild_id INTEGER NOT NULL,
                channel_id INTEGER NOT NULL,
                PRIMARY KEY (guild_id, channel_id)
            );

            CREATE TABLE IF NOT EXISTS app_state (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS guild_disabled_commands (
                guild_id INTEGER NOT NULL,
                command_name TEXT NOT NULL,
                PRIMARY KEY (guild_id, command_name)
            );

            CREATE TABLE IF NOT EXISTS guild_domain_blocklists (
                guild_id INTEGER NOT NULL,
                blocklist_key TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (guild_id, blocklist_key)
            );
            CREATE INDEX IF NOT EXISTS idx_guild_domain_blocklists_guild
                ON guild_domain_blocklists(guild_id);

            CREATE TABLE IF NOT EXISTS distributed_leases (
                lease_key TEXT PRIMARY KEY,
                owner_id TEXT NOT NULL,
                lease_until TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            """
        )
        await connection.commit()
        STATE_DB_CONNECTION = connection

    return STATE_DB_CONNECTION


async def _upsert_rule_report_row(connection: aiosqlite.Connection, report: RuleReportState) -> None:
    payload = serialize_rule_report(report)
    await connection.execute(
        """
        INSERT INTO rule_reports (
            report_id,
            source_message_id,
            cluster_key,
            source_guild_id,
            status,
            created_at,
            last_reported_at,
            payload
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(report_id) DO UPDATE SET
            source_message_id = excluded.source_message_id,
            cluster_key = excluded.cluster_key,
            source_guild_id = excluded.source_guild_id,
            status = excluded.status,
            created_at = excluded.created_at,
            last_reported_at = excluded.last_reported_at,
            payload = excluded.payload
        """,
        (
            report.report_id,
            report.source_message_id,
            report.cluster_key,
            report.source_guild_id,
            report.status,
            report.created_at.isoformat(),
            report.last_reported_at.isoformat(),
            json.dumps(payload, sort_keys=True),
        ),
    )


async def _delete_rule_report_row(connection: aiosqlite.Connection, report_id: str) -> None:
    await connection.execute("DELETE FROM rule_reports WHERE report_id = ?", (report_id,))


async def _upsert_ai_usage_bucket_row(
    connection: aiosqlite.Connection,
    kind: str,
    bucket_id: str,
    values: Dict[str, int],
) -> None:
    await connection.execute(
        """
        INSERT INTO ai_usage (
            kind,
            bucket_id,
            requests,
            prompt_tokens,
            completion_tokens,
            total_tokens
        ) VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(kind, bucket_id) DO UPDATE SET
            requests = excluded.requests,
            prompt_tokens = excluded.prompt_tokens,
            completion_tokens = excluded.completion_tokens,
            total_tokens = excluded.total_tokens
        """,
        (
            kind,
            str(bucket_id),
            int(values.get("requests", 0) or 0),
            int(values.get("prompt_tokens", 0) or 0),
            int(values.get("completion_tokens", 0) or 0),
            int(values.get("total_tokens", 0) or 0),
        ),
    )


async def write_app_state_value(key: str, payload: dict) -> None:
    async with STATE_DB_LOCK:
        connection = await get_state_db_connection()
        await connection.execute(
            """
            INSERT INTO app_state (key, value, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET
                value = excluded.value,
                updated_at = excluded.updated_at
            """,
            (key, json.dumps(payload, sort_keys=True), utcnow().isoformat()),
        )
        await connection.commit()


async def read_app_state_value(key: str) -> Optional[dict]:
    async with STATE_DB_LOCK:
        connection = await get_state_db_connection()
        row = await (await connection.execute("SELECT value FROM app_state WHERE key = ?", (key,))).fetchone()
    if row is None:
        return None
    try:
        return json.loads(str(row["value"]))
    except (TypeError, json.JSONDecodeError):
        return None


async def persist_runtime_state() -> None:
    async with APP_STATE_LOCK:
        await write_app_state_value(APP_STATE_RUNTIME_KEY, serialize_runtime_state())


async def load_runtime_state() -> None:
    payload = await read_app_state_value(APP_STATE_RUNTIME_KEY)
    apply_runtime_state_payload(payload)


async def persist_retro_scan_state() -> None:
    async with APP_STATE_LOCK:
        await write_app_state_value(APP_STATE_RETRO_SCAN_KEY, serialize_retro_scan_state())


async def load_retro_scan_state(
    *,
    preserve_active_task: bool = False,
    mark_running_as_interrupted: bool = False,
) -> None:
    payload = await read_app_state_value(APP_STATE_RETRO_SCAN_KEY)
    apply_retro_scan_payload(
        payload,
        preserve_active_task=preserve_active_task,
        mark_running_as_interrupted=mark_running_as_interrupted,
    )


async def load_disabled_guild_commands() -> None:
    DISABLED_GUILD_COMMANDS.clear()
    async with STATE_DB_LOCK:
        connection = await get_state_db_connection()
        rows = await (await connection.execute(
            "SELECT guild_id, command_name FROM guild_disabled_commands ORDER BY guild_id, command_name"
        )).fetchall()
    for row in rows:
        guild_id = int(row["guild_id"] or 0)
        command_name = str(row["command_name"] or "").strip().lower()
        if guild_id > 0 and command_name:
            DISABLED_GUILD_COMMANDS[guild_id].add(command_name)


async def set_disabled_guild_command(guild_id: int, command_name: str, *, disabled: bool) -> None:
    normalized_name = command_name.strip().lower()
    if not normalized_name:
        raise ValueError("Command name cannot be blank.")

    async with STATE_DB_LOCK:
        connection = await get_state_db_connection()
        if disabled:
            await connection.execute(
                "INSERT OR IGNORE INTO guild_disabled_commands (guild_id, command_name) VALUES (?, ?)",
                (guild_id, normalized_name),
            )
        else:
            await connection.execute(
                "DELETE FROM guild_disabled_commands WHERE guild_id = ? AND command_name = ?",
                (guild_id, normalized_name),
            )
        await connection.commit()

    if disabled:
        DISABLED_GUILD_COMMANDS[guild_id].add(normalized_name)
    else:
        DISABLED_GUILD_COMMANDS[guild_id].discard(normalized_name)
        if not DISABLED_GUILD_COMMANDS[guild_id]:
            DISABLED_GUILD_COMMANDS.pop(guild_id, None)


async def migrate_legacy_rule_report_state(path: Path = RULE_REPORTS_PATH) -> None:
    connection = await get_state_db_connection()
    row = await (await connection.execute("SELECT COUNT(*) AS count FROM rule_reports")).fetchone()
    if row is not None and int(row["count"] or 0) > 0:
        return
    if not path.exists():
        return

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return

    reports_raw = payload.get("reports", [])
    reports: List[RuleReportState] = []
    if isinstance(reports_raw, list):
        for item in reports_raw:
            if not isinstance(item, dict):
                continue
            try:
                report = deserialize_rule_report(item)
            except Exception:
                continue
            if report.status == "analyzing":
                report.status = "reported"
                report.suggestion_error = "Bot restarted before AI proposal generation completed."
            reports.append(report)
    if reports:
        for report in reports:
            await _upsert_rule_report_row(connection, report)
        await connection.commit()
        log.info("Migrated %s legacy rule review report(s) into %s", len(reports), STATE_DB_PATH)


async def migrate_legacy_ai_usage_state(path: Path = AI_USAGE_PATH) -> None:
    connection = await get_state_db_connection()
    row = await (await connection.execute("SELECT COUNT(*) AS count FROM ai_usage")).fetchone()
    if row is not None and int(row["count"] or 0) > 0:
        return
    if not path.exists():
        return

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return

    AI_USAGE.daily.clear()
    AI_USAGE.monthly.clear()
    daily = payload.get("daily", {})
    monthly = payload.get("monthly", {})
    if isinstance(daily, dict):
        AI_USAGE.daily.update({str(key): {k: int(v) for k, v in value.items()} for key, value in daily.items() if isinstance(value, dict)})
    if isinstance(monthly, dict):
        AI_USAGE.monthly.update({str(key): {k: int(v) for k, v in value.items()} for key, value in monthly.items() if isinstance(value, dict)})
    if AI_USAGE.daily or AI_USAGE.monthly:
        for kind, store in (("daily", AI_USAGE.daily), ("monthly", AI_USAGE.monthly)):
            for bucket_id, values in store.items():
                await _upsert_ai_usage_bucket_row(connection, kind, bucket_id, values)
        await connection.commit()
        log.info("Migrated legacy AI usage state into %s", STATE_DB_PATH)


async def initialize_state_storage() -> None:
    await get_state_db_connection()
    await migrate_legacy_rule_report_state()
    await migrate_legacy_ai_usage_state()
    await load_runtime_state()
    await load_retro_scan_state(mark_running_as_interrupted=True)
    await load_disabled_guild_commands()
    await load_guild_domain_blocklist_settings()
    await refresh_domain_blocklists(force=True)
    await persist_runtime_state()
    await persist_retro_scan_state()


async def get_violation_count(guild_id: int, user_id: int) -> int:
    async with STATE_DB_LOCK:
        connection = await get_state_db_connection()
        row = await (
            await connection.execute(
            "SELECT count FROM violation_counts WHERE guild_id = ? AND user_id = ?",
            (guild_id, user_id),
            )
        ).fetchone()
    return int(row["count"] or 0) if row is not None else 0


async def increment_violation_count(guild_id: int, user_id: int, increment: int = 1) -> int:
    if increment <= 0:
        return await get_violation_count(guild_id, user_id)

    now_iso = utcnow().isoformat()
    async with STATE_DB_LOCK:
        connection = await get_state_db_connection()
        await connection.execute(
                """
                INSERT INTO violation_counts (guild_id, user_id, count, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(guild_id, user_id)
                DO UPDATE SET
                    count = violation_counts.count + excluded.count,
                    updated_at = excluded.updated_at
                """,
                (guild_id, user_id, increment, now_iso),
        )
        await connection.commit()
        row = await (
            await connection.execute(
                "SELECT count FROM violation_counts WHERE guild_id = ? AND user_id = ?",
                (guild_id, user_id),
            )
        ).fetchone()
    return int(row["count"] or 0) if row is not None else increment


async def set_violation_count(guild_id: int, user_id: int, count: int) -> int:
    async with STATE_DB_LOCK:
        connection = await get_state_db_connection()
        if count <= 0:
            await connection.execute(
                "DELETE FROM violation_counts WHERE guild_id = ? AND user_id = ?",
                (guild_id, user_id),
            )
            await connection.commit()
            return 0
        await connection.execute(
            """
            INSERT INTO violation_counts (guild_id, user_id, count, updated_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(guild_id, user_id)
            DO UPDATE SET
                count = excluded.count,
                updated_at = excluded.updated_at
            """,
            (guild_id, user_id, count, utcnow().isoformat()),
        )
        await connection.commit()
    return max(0, count)


async def reset_violation_count(guild_id: int, user_id: int) -> Tuple[int, int]:
    before = await get_violation_count(guild_id, user_id)
    await set_violation_count(guild_id, user_id, 0)
    return before, 0


async def reset_all_violation_counts(guild_id: int) -> int:
    async with STATE_DB_LOCK:
        connection = await get_state_db_connection()
        row = await (
            await connection.execute(
            "SELECT COUNT(*) AS count FROM violation_counts WHERE guild_id = ? AND count > 0",
            (guild_id,),
            )
        ).fetchone()
        affected = int(row["count"] or 0) if row is not None else 0
        await connection.execute("DELETE FROM violation_counts WHERE guild_id = ?", (guild_id,))
        await connection.commit()
    return affected


async def record_reporter_event(
    guild_id: int,
    reporter_id: int,
    report_id: str,
    event_type: str,
    *,
    counts_for_cooldown: bool = False,
    created_at: Optional[datetime] = None,
) -> None:
    timestamp = (created_at or utcnow()).isoformat()
    async with STATE_DB_LOCK:
        connection = await get_state_db_connection()
        await connection.execute(
            """
            INSERT INTO reporter_events (
                guild_id,
                reporter_id,
                report_id,
                event_type,
                counts_for_cooldown,
                created_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (guild_id, reporter_id, report_id, event_type, 1 if counts_for_cooldown else 0, timestamp),
        )
        await connection.commit()


def is_trusted_reporter(guild_id: int, reporter_id: int) -> bool:
    if is_control_operator(reporter_id):
        return True

    guild = bot.get_guild(guild_id)
    if guild is None:
        return False

    if guild.owner_id == reporter_id:
        return True

    member = guild.get_member(reporter_id)
    if member is None:
        return False

    permissions = getattr(member, "guild_permissions", None)
    return bool(
        getattr(permissions, "administrator", False)
        or getattr(permissions, "manage_guild", False)
    )


async def get_reporter_metrics(guild_id: int, reporter_id: int) -> ReporterMetrics:
    since = (utcnow() - timedelta(days=1)).isoformat()
    async with STATE_DB_LOCK:
        connection = await get_state_db_connection()
        rows = await (
            await connection.execute(
            """
            SELECT event_type, COUNT(*) AS count
            FROM reporter_events
            WHERE guild_id = ? AND reporter_id = ?
            GROUP BY event_type
            """,
            (guild_id, reporter_id),
            )
        ).fetchall()
        penalty_rows = await (
            await connection.execute(
            """
            SELECT created_at
            FROM reporter_events
            WHERE guild_id = ?
              AND reporter_id = ?
              AND event_type = 'denied'
              AND counts_for_cooldown = 1
              AND created_at >= ?
            ORDER BY created_at DESC
            """,
            (guild_id, reporter_id, since),
            )
        ).fetchall()

    counts = {str(row["event_type"]): int(row["count"] or 0) for row in rows}
    recent_penalties = [parse_optional_datetime(str(row["created_at"])) for row in penalty_rows]
    recent_penalties = [value for value in recent_penalties if value is not None]

    cooldown_until: Optional[datetime] = None
    if len(recent_penalties) >= REPORTER_DENIAL_LIMIT_PER_DAY:
        latest = max(recent_penalties)
        candidate = latest + timedelta(hours=REPORTER_DENIAL_COOLDOWN_HOURS)
        if candidate > utcnow():
            cooldown_until = candidate

    matched_reports = counts.get("matched_existing", 0)
    approved_reports = counts.get("approved", 0)
    denied_reports = counts.get("denied", 0)
    total_reports = counts.get("submitted", 0) + counts.get("merged", 0) + matched_reports
    merged_reports = counts.get("merged", 0)
    trusted_reporter = is_trusted_reporter(guild_id, reporter_id)

    confidence = "medium"
    if trusted_reporter:
        confidence = "high"
        cooldown_until = None
    elif cooldown_until is not None or (denied_reports >= 2 and (approved_reports + matched_reports) == 0):
        confidence = "low"
    elif (approved_reports + matched_reports) >= 3 and denied_reports == 0:
        confidence = "high"

    return ReporterMetrics(
        total_reports=total_reports,
        matched_reports=matched_reports,
        merged_reports=merged_reports,
        approved_reports=approved_reports,
        denied_reports=denied_reports,
        penalized_denials_last_day=0 if trusted_reporter else len(recent_penalties),
        cooldown_until=cooldown_until,
        confidence=confidence,
    )


async def refresh_rule_reporter_snapshot(report: RuleReportState) -> None:
    if not report.reporter_ids:
        report.reporter_confidence = "unknown"
        report.reporter_history_summary = "No reporters recorded."
        report.reporter_cooldown_until = None
        return

    reporter_ids = sorted(report.reporter_ids)
    summaries: List[str] = []
    aggregate_cooldown: Optional[datetime] = None
    confidence = "high"

    for reporter_id in reporter_ids[:3]:
        metrics = await get_reporter_metrics(report.source_guild_id, reporter_id)
        if metrics.confidence == "low":
            confidence = "low"
        elif metrics.confidence == "medium" and confidence != "low":
            confidence = "medium"
        if metrics.cooldown_until is not None and (aggregate_cooldown is None or metrics.cooldown_until > aggregate_cooldown):
            aggregate_cooldown = metrics.cooldown_until
        detail = (
            f"<@{reporter_id}>: {metrics.confidence} | total={metrics.total_reports} | "
            f"matched={metrics.matched_reports} | approved={metrics.approved_reports} | denied={metrics.denied_reports}"
        )
        if metrics.cooldown_until is not None:
            detail += f" | cooldown until {pretty_ts(metrics.cooldown_until, 'R')}"
        summaries.append(detail)

    if len(reporter_ids) > 3:
        summaries.append(f"+{len(reporter_ids) - 3} more reporter(s)")

    report.reporter_confidence = confidence
    report.reporter_history_summary = "\n".join(summaries) or "No reporter history available."
    report.reporter_cooldown_until = aggregate_cooldown


async def get_reporter_cooldown_until(guild_id: int, reporter_id: int) -> Optional[datetime]:
    metrics = await get_reporter_metrics(guild_id, reporter_id)
    return metrics.cooldown_until


async def set_validation_channel_config(guild_id: int, *, months: int, channel_ids: Sequence[int]) -> None:
    cleaned_channel_ids = trim_unique_int_list(channel_ids, limit=20)
    async with STATE_DB_LOCK:
        connection = await get_state_db_connection()
        await connection.execute(
            """
            INSERT INTO validation_guild_config (guild_id, months)
            VALUES (?, ?)
            ON CONFLICT(guild_id)
            DO UPDATE SET months = excluded.months
            """,
            (guild_id, months),
        )
        await connection.execute("DELETE FROM validation_channels WHERE guild_id = ?", (guild_id,))
        if cleaned_channel_ids:
            await connection.executemany(
                "INSERT INTO validation_channels (guild_id, channel_id) VALUES (?, ?)",
                [(guild_id, channel_id) for channel_id in cleaned_channel_ids],
            )
        await connection.commit()


async def get_validation_channel_config(guild_id: int) -> Tuple[int, List[int]]:
    async with STATE_DB_LOCK:
        connection = await get_state_db_connection()
        config_row = await (
            await connection.execute(
                "SELECT months FROM validation_guild_config WHERE guild_id = ?",
                (guild_id,),
            )
        ).fetchone()
        channel_rows = await (
            await connection.execute(
                "SELECT channel_id FROM validation_channels WHERE guild_id = ? ORDER BY channel_id",
                (guild_id,),
            )
        ).fetchall()

    months = int(config_row["months"] or REPORT_VALIDATION_MONTHS) if config_row is not None else REPORT_VALIDATION_MONTHS
    channel_ids = [int(row["channel_id"]) for row in channel_rows]
    if not channel_ids and REPORT_FP_CHANNEL_IDS:
        channel_ids = sorted(int(channel_id) for channel_id in REPORT_FP_CHANNEL_IDS)
    return months, channel_ids


def get_effective_validation_guild_id(source_guild_id: int) -> int:
    return int(REPORT_VALIDATION_MASTER_GUILD_ID or source_guild_id)


def describe_guild_for_logs(guild_id: int) -> str:
    guild = bot.get_guild(guild_id)
    if guild is not None:
        return f"{guild.name} (`{guild_id}`)"
    return f"`{guild_id}`"


def describe_validation_scope(source_guild_id: int) -> str:
    effective_guild_id = get_effective_validation_guild_id(source_guild_id)
    if REPORT_VALIDATION_MASTER_GUILD_ID:
        return f"validation master guild {describe_guild_for_logs(effective_guild_id)}"
    return f"source guild {describe_guild_for_logs(effective_guild_id)}"


def remember_user_identity(guild_id: int, user: discord.abc.User) -> None:
    values: Set[str] = set()
    values.add(str(user.id))
    if getattr(user, "name", None):
        values.add(user.name.lower())
    if getattr(user, "display_name", None):
        values.add(user.display_name.lower())
    if getattr(user, "global_name", None):
        values.add(str(user.global_name).lower())
    values.add(str(user).lower())

    LAST_KNOWN_USER_LABELS[guild_id][user.id].update(filter(None, values))
    LAST_KNOWN_USER_LAST_SEEN[(guild_id, user.id)] = utcnow()

    guild_users = LAST_KNOWN_USER_LABELS.get(guild_id, {})
    while len(guild_users) > KNOWN_USER_CACHE_MAX_USERS_PER_GUILD:
        oldest_key: Optional[Tuple[int, int]] = None
        oldest_seen: Optional[datetime] = None
        for key, seen_at in LAST_KNOWN_USER_LAST_SEEN.items():
            if key[0] != guild_id:
                continue
            if oldest_seen is None or seen_at < oldest_seen:
                oldest_key = key
                oldest_seen = seen_at
        if oldest_key is None:
            break
        guild_users.pop(oldest_key[1], None)
        LAST_KNOWN_USER_LAST_SEEN.pop(oldest_key, None)


def safe_display_text(text: str) -> str:
    return discord.utils.escape_mentions(discord.utils.escape_markdown(str(text or ""), as_needed=True))


def format_known_user(guild_id: int, user_id: int) -> str:
    labels = LAST_KNOWN_USER_LABELS.get(guild_id, {}).get(user_id, set())
    pretty = next((label for label in labels if not label.isdigit()), None)
    if pretty:
        return f"{safe_display_text(pretty)} ({user_id})"
    return str(user_id)


# ============================================================
# Intents
# ============================================================

intents = discord.Intents(guilds=True, messages=True, message_content=True)


# ============================================================
# Command check exceptions
# ============================================================

class ControlAdminOnly(app_commands.CheckFailure):
    pass


class GuildAdminOrSuperUserOnly(app_commands.CheckFailure):
    pass


class GuildOnlyCommand(app_commands.CheckFailure):
    pass


class GuildCommandDisabled(app_commands.CheckFailure):
    pass


def guild_only_check():
    async def predicate(interaction: discord.Interaction) -> bool:
        if interaction.guild is None:
            raise GuildOnlyCommand("This command must be used in a guild.")
        return True

    return app_commands.check(predicate)


def control_admin_only():
    async def predicate(interaction: discord.Interaction) -> bool:
        if interaction.user.id not in CONTROL_ADMIN_USER_IDS:
            raise ControlAdminOnly("You are not authorized to use this control command.")
        return True

    return app_commands.check(predicate)


def user_can_manage_guild_settings(interaction: discord.Interaction) -> bool:
    if interaction.guild is None:
        return False
    if interaction.user.id in CONTROL_SUPER_USER_IDS or interaction.user.id in CONTROL_ADMIN_USER_IDS:
        return True
    permissions = getattr(interaction.user, "guild_permissions", None)
    return bool(
        getattr(permissions, "administrator", False)
        or getattr(permissions, "manage_guild", False)
    )


def get_member_for_guild(*, guild_id: int, user_id: int) -> Optional[discord.Member]:
    guild = bot.get_guild(guild_id)
    if guild is None:
        return None
    return guild.get_member(user_id)


def user_can_manage_specific_guild(*, guild_id: int, user_id: int) -> bool:
    if user_id in CONTROL_SUPER_USER_IDS or user_id in CONTROL_ADMIN_USER_IDS:
        return True

    guild = bot.get_guild(guild_id)
    if guild is None:
        return False
    if guild.owner_id == user_id:
        return True

    member = guild.get_member(user_id)
    if member is None:
        return False

    permissions = getattr(member, "guild_permissions", None)
    return bool(
        getattr(permissions, "administrator", False)
        or getattr(permissions, "manage_guild", False)
    )


def guild_admin_or_super_user_only():
    async def predicate(interaction: discord.Interaction) -> bool:
        if user_can_manage_guild_settings(interaction):
            return True

        raise GuildAdminOrSuperUserOnly(
            "You must have Administrator or Manage Server in this guild, or be a configured control admin/super-user."
        )

    return app_commands.check(predicate)


def normalize_command_name(command_name: str) -> str:
    normalized = command_name.strip().lower().lstrip("/")
    normalized = re.sub(r"\s+", " ", normalized)
    return normalized


def command_name_prefixes(command_name: str) -> List[str]:
    normalized = normalize_command_name(command_name)
    if not normalized:
        return []
    parts = normalized.split(" ")
    return [" ".join(parts[:index]) for index in range(1, len(parts) + 1)]


def get_disabled_commands_for_guild(guild_id: int) -> Set[str]:
    return set(CONFIG_DISABLED_COMMANDS_BY_GUILD.get(guild_id, set())) | set(DISABLED_GUILD_COMMANDS.get(guild_id, set()))


def is_command_disabled_for_guild(guild_id: int, command_name: str) -> bool:
    disabled_commands = get_disabled_commands_for_guild(guild_id)
    return any(prefix in disabled_commands for prefix in command_name_prefixes(command_name))


def user_can_review_rule_changes_for_report(report: RuleReportState, *, user_id: int) -> bool:
    if user_can_manage_specific_guild(guild_id=report.source_guild_id, user_id=user_id):
        return True

    review_guild_ids = {
        int(guild_id)
        for guild_id in (
            report.review_guild_id,
            REPORT_VALIDATION_MASTER_GUILD_ID,
        )
        if guild_id
    }
    for guild_id in review_guild_ids:
        if user_can_manage_specific_guild(guild_id=guild_id, user_id=user_id):
            return True
    return False


def user_can_deploy_rule_changes(interaction: discord.Interaction) -> bool:
    if interaction.guild is None:
        return False
    if is_control_operator(interaction.user.id):
        return True
    if interaction.user.id in RULE_DEPLOYER_USER_IDS:
        return True
    if isinstance(interaction.user, discord.Member):
        return any(role.id in RULE_DEPLOYER_ROLE_IDS for role in interaction.user.roles)
    return False


def user_can_deploy_rule_changes_for_report(report: RuleReportState, *, user_id: int) -> bool:
    if is_control_operator(user_id):
        return True
    if user_id in RULE_DEPLOYER_USER_IDS:
        return True

    member = get_member_for_guild(guild_id=report.source_guild_id, user_id=user_id)
    if member is None:
        return False
    return any(role.id in RULE_DEPLOYER_ROLE_IDS for role in member.roles)


# ============================================================
# Bot
# ============================================================

class SpamGuardBot(commands.Bot):
    def __init__(self) -> None:
        super().__init__(
            command_prefix=commands.when_mentioned,
            intents=intents,
            help_command=None,
            allowed_mentions=discord.AllowedMentions.none(),
            enable_debug_events=True,
        )
        self.startup_command_sync_performed = False

    async def sync_application_commands(self) -> str:
        async with COMMAND_SYNC_LOCK:
            if not is_current_leader():
                raise RuntimeError("Application-command sync is only allowed on the leader instance.")
            cleaned: List[str] = []

            for guild_id in STALE_COMMAND_CLEANUP_GUILD_IDS:
                guild_obj = discord.Object(id=guild_id)
                self.tree.clear_commands(guild=guild_obj)
                await self.tree.sync(guild=guild_obj)
                cleaned.append(str(guild_id))

            if USE_GUILD_SYNC_FOR_DEV and DEV_GUILD_ID:
                dev_obj = discord.Object(id=DEV_GUILD_ID)
                self.tree.clear_commands(guild=dev_obj)
                self.tree.copy_global_to(guild=dev_obj)
                synced = await self.tree.sync(guild=dev_obj)
                cleanup_note = f" Cleared stale guild command sets: {', '.join(cleaned)}." if cleaned else ""
                return f"Synced {len(synced)} commands to dev guild {DEV_GUILD_ID}.{cleanup_note}"

            synced = await self.tree.sync()
            cleanup_note = f" Cleared stale guild command sets: {', '.join(cleaned)}." if cleaned else ""
            return f"Synced {len(synced)} global commands.{cleanup_note}"

    async def setup_hook(self) -> None:
        await initialize_state_storage()
        await refresh_instance_role()
        await load_rule_reports_state()
        await load_ai_usage_state()
        refreshed_reporters = False
        for report in RULE_REPORTS.values():
            if not report.reporter_history_summary:
                await refresh_rule_reporter_snapshot(report)
                refreshed_reporters = True
        if refreshed_reporters:
            await persist_rule_reports_state()
        await self.add_cog(ReportCog(self))
        await self.add_cog(AdminCog(self))
        self.add_view(AuditDeletionDetailView())
        for report in RULE_REPORTS.values():
            if report.review_message_id is not None and report.status not in {"approved", "denied"}:
                self.add_view(RuleReviewView(report.report_id), message_id=report.review_message_id)
                await refresh_rule_review_message(report)

        await start_healthcheck_server()
        start_watchdog_task()
        start_instance_role_task()
        start_state_refresh_task()
        start_state_retention_task()
        start_moderation_log_task()

        if STARTUP_COMMAND_SYNC_ENABLED and is_current_leader():
            try:
                result = await self.sync_application_commands()
                self.startup_command_sync_performed = True
                log.info(result)
            except app_commands.CommandSyncFailure as exc:
                log.error("Command sync failure: %s", exc)
            except discord.Forbidden as exc:
                log.error("Missing access during command sync: %s", exc)
            except discord.HTTPException as exc:
                log.error(
                    "HTTP error during command sync: status=%s text=%s",
                    getattr(exc, "status", None),
                    getattr(exc, "text", str(exc)),
                )
        else:
            log.info(
                "Skipping startup command sync. enabled=%s instance_role=%s",
                STARTUP_COMMAND_SYNC_ENABLED,
                current_instance_role(),
            )

    async def on_ready(self) -> None:
        assert self.user is not None
        note_gateway_activity("ready")
        STATE.last_ready_at = utcnow()
        log.info("Ready as %s (%s)", self.user, self.user.id)

        for guild in list(self.guilds):
            await self._enforce_guild_allowlist(guild, source="startup")

    async def on_guild_join(self, guild: discord.Guild) -> None:
        note_gateway_activity("guild_join")
        await self._enforce_guild_allowlist(guild, source="guild_join")

    async def on_socket_raw_receive(self, msg: object) -> None:
        note_gateway_activity("socket_raw_receive")

    async def on_disconnect(self) -> None:
        STATE.last_disconnect_at = utcnow()
        log.debug("Gateway disconnect detected.")

    async def on_resumed(self) -> None:
        note_gateway_activity("resumed")
        STATE.last_resumed_at = utcnow()
        disconnect_age_seconds: Optional[float] = None
        if STATE.last_disconnect_at is not None:
            disconnect_age_seconds = max(
                0.0,
                (STATE.last_resumed_at - STATE.last_disconnect_at).total_seconds(),
            )
        if (
            disconnect_age_seconds is not None
            and disconnect_age_seconds >= GATEWAY_RESUME_LOG_MIN_SECONDS
        ):
            log.info("Gateway session resumed after %.2fs.", disconnect_age_seconds)
        else:
            log.debug("Gateway session resumed.")

    async def _enforce_guild_allowlist(self, guild: discord.Guild, source: str) -> None:
        if not GUILD_ALLOWLIST_ENABLED:
            return
        if not ALLOWED_GUILD_IDS:
            return
        if guild.id in ALLOWED_GUILD_IDS:
            return

        log.warning("Guild %s (%s) not allowlisted; leaving. source=%s", guild.name, guild.id, source)
        try:
            await guild.leave()
        except discord.Forbidden:
            log.error("Forbidden while trying to leave guild %s (%s)", guild.name, guild.id)
        except discord.HTTPException as exc:
            log.error(
                "HTTP error while leaving guild %s (%s): status=%s text=%s",
                guild.name,
                guild.id,
                getattr(exc, "status", None),
                getattr(exc, "text", str(exc)),
            )


bot = SpamGuardBot()


@bot.tree.interaction_check
async def global_command_availability_check(interaction: discord.Interaction) -> bool:
    command = interaction.command
    if interaction.guild is None or command is None:
        return True
    if is_control_operator(interaction.user.id):
        return True
    qualified_name = normalize_command_name(getattr(command, "qualified_name", "") or getattr(command, "name", ""))
    if qualified_name and is_command_disabled_for_guild(interaction.guild.id, qualified_name):
        raise GuildCommandDisabled(
            f"The `/{qualified_name}` command is disabled for this guild. Ask an admin to re-enable it if needed."
        )
    return True


# ============================================================
# Normalization
# ============================================================

ZERO_WIDTH_RE = re.compile(r"a\A")
# Unicode escapes keep the active normalization table stable across editors/code pages.
CONFUSABLES = str.maketrans({
    "\uFF20": "@",
    "\u3002": ".",
    "\uFF0E": ".",
    "\uFF61": ".",
    "\uFF0C": ",",
    "\uFE52": ".",
    "\uFE50": ",",
    "\uFF1A": ":",
    "\uFF1B": ";",
    "\uFF0F": "/",
    "\uFF3C": "\\",
    "\uFF5C": "|",
    "\uFF0D": "-",
    "\u2010": "-",
    "\u2012": "-",
    "\u2013": "-",
    "\u2014": "-",
    "\u2015": "-",
    "\uFE63": "-",
    "\uFF0B": "+",
    "\uFF08": "(",
    "\uFF09": ")",
    "\uFF3B": "[",
    "\uFF3D": "]",
    "\uFF5B": "{",
    "\uFF5D": "}",
    "\u2018": "'",
    "\u2019": "'",
    "\u201A": "'",
    "\u201C": '"',
    "\u201D": '"',
    "\u201E": '"',
    "\u2022": " ",
    "\u00B7": " ",
    "\u2026": "...",
    "\u0430": "a",
    "\u0410": "A",
    "\u0435": "e",
    "\u0415": "E",
    "\u043E": "o",
    "\u041E": "O",
    "\u0440": "p",
    "\u0420": "P",
    "\u0441": "c",
    "\u0421": "C",
    "\u0443": "y",
    "\u0423": "Y",
    "\u0445": "x",
    "\u0425": "X",
    "\u0456": "i",
    "\u0406": "I",
    "\u0458": "j",
    "\u0408": "J",
    "\u217C": "l",
    "\u0261": "g",
    "\uFF4D": "m",
    "\uFF41": "a",
    "\uFF49": "i",
    "\uFF4C": "l",
})


def normalize_for_scan(text: str) -> str:
    text = unicodedata.normalize("NFKC", text)
    text = ZERO_WIDTH_RE.sub("", text)
    text = text.translate(CONFUSABLES)
    text = "".join(" " if unicodedata.category(ch).startswith("C") else ch for ch in text)
    text = text.lower()
    text = re.sub(r"[*_`~>|#]+", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


apply_spam_rules(load_spam_rules(SPAM_RULES_PATH))


# ============================================================
# Spam patterns
# ============================================================

# Public export note: private static detector expressions and built-in artifacts
# were replaced with non-matching placeholders. Put deploy-specific rules in
# spam_rules.toml, domain_blocklists/*.txt, or your private fork.

DISCORD_ID_TOKEN = r"a\A"
PHONE = r"a\A"
EMAIL = r"a\A"
DISCORD_INVITE = r"a\A"
KNOWN_SPAM_ARTIFACTS = re.compile(r"a\A")

TICKET_WORDS = re.compile(r"a\A")
ARTIST_EVENT_WORDS = re.compile(r"a\A")
VENUE_LOCATION_WORDS = re.compile(r"a\A")
TICKET_CONTACT = re.compile(r"a\A")
GENERIC_TICKET_CONTEXT = re.compile(r"a\A")
ANTI_TICKET_CONTEXT = re.compile(r"a\A")

GIVEAWAY_INTENT = re.compile(r"a\A")
GIVEAWAY_INTENT_STRICT = re.compile(r"a\A")
GIVEAWAY_BROADCAST = re.compile(r"a\A")
GIVEAWAY_SOFT_VOCAB = re.compile(r"a\A")
ITEM_WORDS = re.compile(r"a\A")
CAMERA_GEAR_TERMS = re.compile(r"a\A")
GIVEAWAY_CONTACT = re.compile(r"a\A")
ANTI_GIVEAWAY_CONTEXT = re.compile(r"a\A")

JOB_ROLE = re.compile(r"a\A")
JOB_REMOTE = re.compile(r"a\A")
JOB_PAY = re.compile(r"a\A")
JOB_TASKS = re.compile(r"a\A")
JOB_RESPONSE = re.compile(r"a\A")

ACADEMIC_INTENT = re.compile(r"a\A")
ACADEMIC_CONTACT = re.compile(r"a\A")

LEGIT_HANDSHAKE_ROLE_POST = re.compile(r"a\A")
LEGIT_OFFERUP_CAMPUS_SALE = re.compile(r"a\A")
LEGIT_CLASS_COMMUNITY_INVITE = re.compile(r"a\A")
LEGIT_ASI_ANNOUNCEMENT = re.compile(r"a\A")
LEGIT_RECRUITER_WORKSHOP = re.compile(r"a\A")
LEGIT_CAMPUS_EVENT_ANNOUNCEMENT = re.compile(r"a\A")
LEGIT_CAMPUS_ADVOCACY_EMAIL = re.compile(r"a\A")
LEGIT_STUDENT_HUB_ANNOUNCEMENT = re.compile(r"a\A")
LEGIT_CAREER_EVENT_POST = re.compile(r"a\A")
LEGIT_CAREER_EVENT_CONTEXT = re.compile(r"a\A")
SUSPICIOUS_TUTOR_SPAM_CONTEXT = re.compile(r"a\A")
LEGIT_OFFICIAL_TUTORING_CENTER = re.compile(r"a\A")
LEGIT_SERVER_ADMIN_UPDATE = re.compile(r"a\A")
LEGIT_FUNDRAISER_EVENT = re.compile(r"a\A")
LEGIT_ACCESSIBILITY_SCRIBE_REQUEST = re.compile(r"a\A")
LEGIT_EXACT_TUTORING_LINK = re.compile(r"a\A")
LEGIT_EVENT_PROMOTION = re.compile(r"a\A")
LEGIT_OFFICER_ELECTION_TEMPLATE = re.compile(r"a\A")
LEGIT_JOB_REFERRAL_POST = re.compile(r"a\A")
LEGIT_INTERNAL_CLUB_UPDATE = re.compile(r"a\A")


def managed_hook_search(hook_name: str, normalized: str) -> bool:
    return any(safe_dynamic_regex_search(pattern, normalized) for pattern in MANAGED_HOOK_PATTERNS.get(hook_name, tuple()))


def matches_known_spam_artifact(normalized: str) -> bool:
    if KNOWN_SPAM_ARTIFACTS.search(normalized):
        return True
    return any(value and value in normalized for value in MANAGED_KNOWN_SPAM_ARTIFACTS)


def match_managed_custom_rule(normalized: str) -> Optional[ManagedCustomRule]:
    for rule in MANAGED_CUSTOM_RULES:
        pattern = MANAGED_CUSTOM_RULE_PATTERNS.get(rule.rule_id)
        if pattern is not None and safe_dynamic_regex_search(pattern, normalized):
            return rule
    return None


def is_likely_legit_campus_post(normalized: str) -> bool:
    # Narrow false-positive guardrails for known legitimate campus message families.
    if LEGIT_HANDSHAKE_ROLE_POST.search(normalized):
        return True
    if LEGIT_OFFERUP_CAMPUS_SALE.search(normalized):
        return True
    if LEGIT_CLASS_COMMUNITY_INVITE.search(normalized):
        return True
    if LEGIT_ASI_ANNOUNCEMENT.search(normalized):
        return True
    if LEGIT_RECRUITER_WORKSHOP.search(normalized):
        return True
    if (
        LEGIT_CAMPUS_EVENT_ANNOUNCEMENT.search(normalized)
        and re.search(r"\b(?:meeting|workshop|officer|conference|announcement|server[\W_]*hub|club)\b", normalized, re.IGNORECASE)
    ):
        return True
    if (
        LEGIT_CAMPUS_ADVOCACY_EMAIL.search(normalized)
        and re.search(r"\b(?:dean|csus|sac[\W_]*state|computer[\W_]*science)\b", normalized, re.IGNORECASE)
    ):
        return True
    if (
        LEGIT_STUDENT_HUB_ANNOUNCEMENT.search(normalized)
        and re.search(r"\b(?:discord(?:\.gg|\.com/invite)|student[\W_]*hub|server[\W_]*hub)\b", normalized, re.IGNORECASE)
        and not SUSPICIOUS_TUTOR_SPAM_CONTEXT.search(normalized)
    ):
        return True
    if (
        LEGIT_CAREER_EVENT_POST.search(normalized)
        and LEGIT_CAREER_EVENT_CONTEXT.search(normalized)
        and not SUSPICIOUS_TUTOR_SPAM_CONTEXT.search(normalized)
    ):
        return True
    if (
        LEGIT_JOB_REFERRAL_POST.search(normalized)
        and re.search(r"\b(?:https?://[^\s]+|www\.)", normalized, re.IGNORECASE)
        and not SUSPICIOUS_TUTOR_SPAM_CONTEXT.search(normalized)
    ):
        return True
    if LEGIT_INTERNAL_CLUB_UPDATE.search(normalized):
        return True
    if LEGIT_OFFICIAL_TUTORING_CENTER.search(normalized):
        return True
    if LEGIT_SERVER_ADMIN_UPDATE.search(normalized):
        return True
    if LEGIT_FUNDRAISER_EVENT.search(normalized):
        return True
    if LEGIT_ACCESSIBILITY_SCRIBE_REQUEST.search(normalized):
        return True
    if LEGIT_EXACT_TUTORING_LINK.search(normalized):
        return True
    if LEGIT_OFFICER_ELECTION_TEMPLATE.search(normalized):
        return True
    if (
        LEGIT_EVENT_PROMOTION.search(normalized)
        and re.search(r"\b(?:club|chapter|students?|university|college|campus|acm|sacramento|sac[\W_]*state|ecs|hornet)\b", normalized, re.IGNORECASE)
        and not SUSPICIOUS_TUTOR_SPAM_CONTEXT.search(normalized)
    ):
        return True
    return False


def classify_spam(content: str) -> Tuple[bool, str, str]:
    normalized = normalize_for_scan(content)
    anti_ticket = ANTI_TICKET_CONTEXT.search(normalized) or managed_hook_search("anti_ticket", normalized)
    anti_giveaway = ANTI_GIVEAWAY_CONTEXT.search(normalized) or managed_hook_search("anti_giveaway", normalized)

    if (
        matches_known_spam_artifact(normalized)
        and not anti_ticket
        and not anti_giveaway
    ):
        return True, "known_spam_artifact", normalized

    if is_likely_legit_campus_post(normalized):
        return False, "", normalized

    ticket_words_hit = TICKET_WORDS.search(normalized) or managed_hook_search("ticket_words", normalized)
    ticket_context_hit = (
        ARTIST_EVENT_WORDS.search(normalized)
        or VENUE_LOCATION_WORDS.search(normalized)
        or GENERIC_TICKET_CONTEXT.search(normalized)
        or managed_hook_search("ticket_context", normalized)
    )
    ticket_contact_hit = TICKET_CONTACT.search(normalized) or managed_hook_search("ticket_contact", normalized)

    detailed_ticket = (
        ticket_words_hit
        and (ARTIST_EVENT_WORDS.search(normalized) or managed_hook_search("ticket_context", normalized))
        and (VENUE_LOCATION_WORDS.search(normalized) or managed_hook_search("ticket_context", normalized))
        and ticket_contact_hit
    )

    generic_ticket = (
        ticket_words_hit
        and ticket_contact_hit
        and ticket_context_hit
    )

    if (detailed_ticket or generic_ticket) and not anti_ticket:
        return True, "ticket_resale", normalized

    giveaway_item_hit = (
        ITEM_WORDS.search(normalized)
        or CAMERA_GEAR_TERMS.search(normalized)
        or managed_hook_search("giveaway_item", normalized)
    )
    strict_giveaway_intent_hit = (
        GIVEAWAY_INTENT_STRICT.search(normalized)
        or (GIVEAWAY_BROADCAST.search(normalized) and GIVEAWAY_SOFT_VOCAB.search(normalized))
        or managed_hook_search("giveaway_intent", normalized)
    )
    if (
        strict_giveaway_intent_hit
        and (GIVEAWAY_INTENT.search(normalized) or managed_hook_search("giveaway_intent", normalized))
        and giveaway_item_hit
        and (GIVEAWAY_CONTACT.search(normalized) or managed_hook_search("giveaway_contact", normalized))
        and not anti_giveaway
    ):
        return True, "giveaway_spam", normalized

    job_features = sum(
        bool(pattern.search(normalized))
        for pattern in (JOB_REMOTE, JOB_PAY, JOB_TASKS, JOB_RESPONSE)
    )
    job_features += int(managed_hook_search("job_remote", normalized))
    job_features += int(managed_hook_search("job_pay", normalized))
    job_features += int(managed_hook_search("job_tasks", normalized))
    job_features += int(managed_hook_search("job_response", normalized))
    if (
        (JOB_ROLE.search(normalized) or managed_hook_search("job_role", normalized))
        and job_features >= 2
        and (
            JOB_PAY.search(normalized)
            or JOB_TASKS.search(normalized)
            or managed_hook_search("job_pay", normalized)
            or managed_hook_search("job_tasks", normalized)
        )
    ):
        return True, "job_spam", normalized

    if (
        (ACADEMIC_INTENT.search(normalized) or managed_hook_search("academic_intent", normalized))
        and (ACADEMIC_CONTACT.search(normalized) or managed_hook_search("academic_contact", normalized))
    ):
        return True, "academic_spam", normalized

    custom_rule = match_managed_custom_rule(normalized)
    if custom_rule is not None:
        return True, custom_rule.reason, normalized

    return False, "", normalized


def extract_message_media_indicators(message: discord.Message) -> List[str]:
    values: List[str] = []
    seen: Set[str] = set()

    def add(value: Optional[str]) -> None:
        if not value:
            return
        cleaned = str(value).strip()
        if not cleaned or cleaned in seen:
            return
        seen.add(cleaned)
        values.append(cleaned)

    for attachment in message.attachments:
        add(getattr(attachment, "filename", None))
        add(getattr(attachment, "url", None))
        proxy_url = getattr(attachment, "proxy_url", None)
        if proxy_url and proxy_url != getattr(attachment, "url", None):
            add(proxy_url)

    for embed in message.embeds:
        add(getattr(embed, "url", None))
        add(getattr(getattr(embed, "author", None), "url", None))
        add(getattr(getattr(embed, "image", None), "url", None))
        add(getattr(getattr(embed, "thumbnail", None), "url", None))
        add(getattr(getattr(embed, "video", None), "url", None))

    return values


def render_message_media_indicators(message: discord.Message) -> str:
    return "\n".join(extract_message_media_indicators(message))


def classify_known_spam_media(message: discord.Message) -> Tuple[bool, str, str]:
    media_text = render_message_media_indicators(message)
    if not media_text:
        return False, "", ""

    normalized_context = normalize_for_scan(message.content or "")
    if (
        ANTI_TICKET_CONTEXT.search(normalized_context)
        or ANTI_GIVEAWAY_CONTEXT.search(normalized_context)
        or managed_hook_search("anti_ticket", normalized_context)
        or managed_hook_search("anti_giveaway", normalized_context)
    ):
        return False, "", normalize_for_scan(media_text)

    normalized_media = normalize_for_scan(media_text)
    if matches_known_spam_artifact(normalized_media):
        return True, "known_spam_artifact", normalized_media

    return False, "", normalized_media


def classify_message_for_moderation(message: discord.Message) -> Tuple[bool, str, str]:
    content = message.content or ""
    if content.strip():
        matched, reason, normalized = classify_spam(content)
        if matched:
            return matched, reason, normalized

    return classify_known_spam_media(message)


def build_message_match_preview(message: discord.Message) -> str:
    preview = re.sub(r"\s+", " ", message.content or "").strip()
    if not preview:
        preview = re.sub(r"\s+", " ", render_message_media_indicators(message)).strip()
    if not preview:
        preview = "[no text or media indicators]"
    preview = safe_display_text(preview)
    if len(preview) > RETRO_SCAN_MATCH_SNIPPET_LIMIT:
        preview = preview[:RETRO_SCAN_MATCH_SNIPPET_LIMIT].rstrip() + "..."
    return preview


def parse_optional_datetime(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def trim_unique_list(values: Sequence[str], *, limit: int = 5) -> List[str]:
    result: List[str] = []
    seen: Set[str] = set()
    for value in values:
        cleaned = str(value).strip()
        if not cleaned or cleaned in seen:
            continue
        seen.add(cleaned)
        result.append(cleaned)
        if len(result) >= limit:
            break
    return result


def trim_unique_int_list(values: Sequence[int], *, limit: int = 5) -> List[int]:
    result: List[int] = []
    seen: Set[int] = set()
    for value in values:
        try:
            cleaned = int(value)
        except (TypeError, ValueError):
            continue
        if cleaned in seen:
            continue
        seen.add(cleaned)
        result.append(cleaned)
        if len(result) >= limit:
            break
    return result


def normalize_rule_report_kind(value: Optional[str]) -> str:
    cleaned = str(value or "").strip().lower()
    if cleaned == "false_positive":
        return "false_positive"
    return "spam_report"


def is_false_positive_report(report: RuleReportState) -> bool:
    return normalize_rule_report_kind(getattr(report, "report_kind", "")) == "false_positive"


def serialize_rule_suggestion(suggestion: Optional[RuleSuggestion]) -> Optional[dict]:
    if suggestion is None:
        return None
    return {
        "decision": suggestion.decision,
        "target_type": suggestion.target_type,
        "target_name": suggestion.target_name,
        "reason": suggestion.reason,
        "pattern": suggestion.pattern,
        "exact_values": list(suggestion.exact_values),
        "custom_rule_id": suggestion.custom_rule_id,
        "description": suggestion.description,
        "rationale": suggestion.rationale,
        "confidence": suggestion.confidence,
        "tests": list(suggestion.tests),
        "enhancement_prompt": suggestion.enhancement_prompt,
        "raw_payload": suggestion.raw_payload,
        "usage": dict(suggestion.usage),
    }


def deserialize_rule_suggestion(payload: Optional[dict]) -> Optional[RuleSuggestion]:
    if not isinstance(payload, dict):
        return None
    return RuleSuggestion(
        decision=str(payload.get("decision", "pending")).strip(),
        target_type=str(payload.get("target_type", "")).strip(),
        target_name=str(payload.get("target_name", "")).strip(),
        reason=str(payload.get("reason", "")).strip(),
        pattern=str(payload.get("pattern", "")).strip(),
        exact_values=[str(value).strip() for value in payload.get("exact_values", []) if str(value).strip()],
        custom_rule_id=str(payload.get("custom_rule_id", "")).strip(),
        description=str(payload.get("description", "")).strip(),
        rationale=str(payload.get("rationale", "")).strip(),
        confidence=str(payload.get("confidence", "")).strip(),
        tests=[item for item in payload.get("tests", []) if isinstance(item, dict)],
        enhancement_prompt=str(payload.get("enhancement_prompt", "")).strip(),
        raw_payload=str(payload.get("raw_payload", "")).strip(),
        usage={str(key): int(value) for key, value in payload.get("usage", {}).items() if str(key)},
    )


def serialize_rule_report(report: RuleReportState) -> dict:
    return {
        "report_id": report.report_id,
        "cluster_key": report.cluster_key,
        "report_kind": normalize_rule_report_kind(report.report_kind),
        "source_guild_id": report.source_guild_id,
        "source_guild_name": report.source_guild_name,
        "source_channel_id": report.source_channel_id,
        "source_channel_label": report.source_channel_label,
        "source_message_id": report.source_message_id,
        "source_author_id": report.source_author_id,
        "source_author_label": report.source_author_label,
        "source_jump_url": report.source_jump_url,
        "message_content": report.message_content,
        "normalized_content": report.normalized_content,
        "media_indicators": report.media_indicators,
        "image_hashes": list(report.image_hashes),
        "created_at": report.created_at.isoformat(),
        "last_reported_at": report.last_reported_at.isoformat(),
        "reporter_ids": sorted(report.reporter_ids),
        "report_count": report.report_count,
        "sample_message_ids": list(report.sample_message_ids),
        "sample_jump_urls": list(report.sample_jump_urls),
        "current_matched": report.current_matched,
        "current_reason": report.current_reason,
        "status": report.status,
        "suggestion": serialize_rule_suggestion(report.suggestion),
        "suggestion_error": report.suggestion_error,
        "review_guild_id": report.review_guild_id,
        "review_channel_id": report.review_channel_id,
        "review_message_id": report.review_message_id,
        "detail_message_ids": list(report.detail_message_ids),
        "last_generated_by": report.last_generated_by,
        "approved_by": report.approved_by,
        "denied_by": report.denied_by,
        "proposal_generated_at": report.proposal_generated_at.isoformat() if report.proposal_generated_at else None,
        "reporter_confidence": report.reporter_confidence,
        "reporter_history_summary": report.reporter_history_summary,
        "reporter_cooldown_until": report.reporter_cooldown_until.isoformat() if report.reporter_cooldown_until else None,
        "validation_status": report.validation_status,
        "validation_summary": report.validation_summary,
        "validation_hit_lines": list(report.validation_hit_lines),
        "validation_ran_at": report.validation_ran_at.isoformat() if report.validation_ran_at else None,
        "validation_bypassed_by": report.validation_bypassed_by,
        "validation_months": report.validation_months,
        "validation_channel_ids": list(report.validation_channel_ids),
        "ai_precheck_matched": report.ai_precheck_matched,
        "ai_precheck_reason": report.ai_precheck_reason,
        "ai_precheck_normalized": report.ai_precheck_normalized,
        "ai_ignore_approved_by": report.ai_ignore_approved_by,
        "staff_notes": report.staff_notes,
    }


def deserialize_rule_report(payload: dict) -> RuleReportState:
    created_at = parse_optional_datetime(str(payload.get("created_at", "")).strip()) or datetime.now(timezone.utc)
    last_reported_at = parse_optional_datetime(str(payload.get("last_reported_at", "")).strip()) or created_at
    report = RuleReportState(
        report_id=str(payload.get("report_id", "")).strip(),
        cluster_key=str(payload.get("cluster_key", "")).strip(),
        source_guild_id=int(payload.get("source_guild_id", 0) or 0),
        source_guild_name=str(payload.get("source_guild_name", "")).strip(),
        source_channel_id=int(payload.get("source_channel_id", 0) or 0),
        source_channel_label=str(payload.get("source_channel_label", "")).strip(),
        source_message_id=int(payload.get("source_message_id", 0) or 0),
        source_author_id=int(payload.get("source_author_id", 0) or 0),
        source_author_label=str(payload.get("source_author_label", "")).strip(),
        source_jump_url=str(payload.get("source_jump_url", "")).strip(),
        report_kind=normalize_rule_report_kind(payload.get("report_kind")),
        message_content=str(payload.get("message_content", "")).strip(),
        normalized_content=str(payload.get("normalized_content", "")).strip(),
        media_indicators=str(payload.get("media_indicators", "")).strip(),
        image_hashes=[str(value).strip() for value in payload.get("image_hashes", []) if str(value).strip()],
        created_at=created_at,
        last_reported_at=last_reported_at,
        reporter_ids={int(value) for value in payload.get("reporter_ids", [])},
        report_count=max(1, int(payload.get("report_count", 1) or 1)),
        sample_message_ids=trim_unique_int_list(payload.get("sample_message_ids", []), limit=8),
        sample_jump_urls=trim_unique_list(payload.get("sample_jump_urls", []), limit=8),
        current_matched=bool(payload.get("current_matched", False)),
        current_reason=str(payload.get("current_reason", "")).strip(),
        status=str(payload.get("status", "reported")).strip() or "reported",
        suggestion=deserialize_rule_suggestion(payload.get("suggestion")),
        suggestion_error=str(payload.get("suggestion_error", "")).strip() or None,
        review_guild_id=int(payload.get("review_guild_id", 0) or 0) or None,
        review_channel_id=int(payload.get("review_channel_id", 0) or 0) or None,
        review_message_id=int(payload.get("review_message_id", 0) or 0) or None,
        detail_message_ids=trim_unique_int_list(payload.get("detail_message_ids", []), limit=20),
        last_generated_by=int(payload.get("last_generated_by", 0) or 0) or None,
        approved_by=int(payload.get("approved_by", 0) or 0) or None,
        denied_by=int(payload.get("denied_by", 0) or 0) or None,
        proposal_generated_at=parse_optional_datetime(str(payload.get("proposal_generated_at", "")).strip()),
        reporter_confidence=str(payload.get("reporter_confidence", "unknown")).strip() or "unknown",
        reporter_history_summary=str(payload.get("reporter_history_summary", "")).strip(),
        reporter_cooldown_until=parse_optional_datetime(str(payload.get("reporter_cooldown_until", "")).strip()),
        validation_status=str(payload.get("validation_status", "not_run")).strip() or "not_run",
        validation_summary=str(payload.get("validation_summary", "")).strip(),
        validation_hit_lines=trim_unique_list(payload.get("validation_hit_lines", []), limit=10),
        validation_ran_at=parse_optional_datetime(str(payload.get("validation_ran_at", "")).strip()),
        validation_bypassed_by=int(payload.get("validation_bypassed_by", 0) or 0) or None,
        validation_months=max(0, int(payload.get("validation_months", 0) or 0)),
        validation_channel_ids=trim_unique_int_list(payload.get("validation_channel_ids", []), limit=10),
        ai_precheck_matched=bool(payload.get("ai_precheck_matched", False)),
        ai_precheck_reason=str(payload.get("ai_precheck_reason", "")).strip(),
        ai_precheck_normalized=str(payload.get("ai_precheck_normalized", "")).strip(),
        ai_ignore_approved_by=int(payload.get("ai_ignore_approved_by", 0) or 0) or None,
        staff_notes=str(payload.get("staff_notes", "")).strip(),
    )
    return report


def rule_report_cluster_map_key(guild_id: int, cluster_key: str) -> str:
    cleaned_cluster_key = str(cluster_key or "").strip()
    return f"{guild_id}:{cleaned_cluster_key}" if cleaned_cluster_key else ""


async def load_rule_reports_state(path: Path = RULE_REPORTS_PATH, *, preserve_tasks: bool = False) -> None:
    existing_tasks = (
        {
            report_id: report.task
            for report_id, report in RULE_REPORTS.items()
            if preserve_tasks and report.task is not None
        }
        if preserve_tasks
        else {}
    )
    RULE_REPORTS.clear()
    RULE_REPORTS_BY_MESSAGE_ID.clear()
    RULE_REPORTS_BY_CLUSTER.clear()
    connection = await get_state_db_connection()
    rows = await (
        await connection.execute(
        """
        SELECT payload
        FROM rule_reports
        ORDER BY COALESCE(created_at, ''), COALESCE(last_reported_at, '')
        """
        )
    ).fetchall()

    for row in rows:
        try:
            item = json.loads(str(row["payload"]))
            report = deserialize_rule_report(item)
        except Exception:
            continue
        if report.status == "analyzing":
            report.status = "reported"
            report.suggestion_error = "Bot restarted before AI proposal generation completed."
        if report.report_id in existing_tasks:
            report.task = existing_tasks[report.report_id]
        RULE_REPORTS[report.report_id] = report
        if report.source_message_id:
            RULE_REPORTS_BY_MESSAGE_ID[report.source_message_id] = report.report_id
        if report.cluster_key and report.status not in {"approved", "denied"}:
            cluster_map_key = rule_report_cluster_map_key(report.source_guild_id, report.cluster_key)
            if cluster_map_key:
                RULE_REPORTS_BY_CLUSTER[cluster_map_key] = report.report_id


async def persist_rule_report_state(report: RuleReportState) -> None:
    async with STATE_DB_LOCK:
        connection = await get_state_db_connection()
        await _upsert_rule_report_row(connection, report)
        await connection.commit()


async def remove_rule_report_state(report_id: str) -> None:
    async with STATE_DB_LOCK:
        connection = await get_state_db_connection()
        await _delete_rule_report_row(connection, report_id)
        await connection.commit()


async def persist_rule_reports_state(*, prune_missing: bool = False) -> None:
    async with RULE_REPORTS_LOCK:
        snapshot = list(RULE_REPORTS.values())
        expected_ids = {report.report_id for report in snapshot}

    async with STATE_DB_LOCK:
        connection = await get_state_db_connection()
        for report in snapshot:
            await _upsert_rule_report_row(connection, report)
        if prune_missing:
            rows = await (await connection.execute("SELECT report_id FROM rule_reports")).fetchall()
            for row in rows:
                report_id = str(row["report_id"] or "")
                if report_id and report_id not in expected_ids:
                    await _delete_rule_report_row(connection, report_id)
        await connection.commit()


async def load_ai_usage_state(path: Path = AI_USAGE_PATH) -> None:
    AI_USAGE.daily.clear()
    AI_USAGE.monthly.clear()
    connection = await get_state_db_connection()
    rows = await (
        await connection.execute(
            """
            SELECT kind, bucket_id, requests, prompt_tokens, completion_tokens, total_tokens
            FROM ai_usage
            """
        )
    ).fetchall()
    for row in rows:
        target = AI_USAGE.daily if str(row["kind"]) == "daily" else AI_USAGE.monthly
        target[str(row["bucket_id"])] = {
            "requests": int(row["requests"] or 0),
            "prompt_tokens": int(row["prompt_tokens"] or 0),
            "completion_tokens": int(row["completion_tokens"] or 0),
            "total_tokens": int(row["total_tokens"] or 0),
        }


async def persist_ai_usage_state() -> None:
    async with AI_USAGE_LOCK:
        async with STATE_DB_LOCK:
            connection = await get_state_db_connection()
            for kind, store in (("daily", AI_USAGE.daily), ("monthly", AI_USAGE.monthly)):
                for bucket_id, values in store.items():
                    await _upsert_ai_usage_bucket_row(connection, kind, bucket_id, values)
            await connection.commit()


def update_rule_report_cluster_map(report: RuleReportState) -> None:
    cluster_map_key = rule_report_cluster_map_key(report.source_guild_id, report.cluster_key)
    if cluster_map_key:
        if report.status in {"approved", "denied"}:
            RULE_REPORTS_BY_CLUSTER.pop(cluster_map_key, None)
        else:
            RULE_REPORTS_BY_CLUSTER[cluster_map_key] = report.report_id


def redact_sensitive_for_ai(text: str) -> str:
    if not text or not AI_REVIEW_REDACT_SENSITIVE:
        return text
    redacted = re.sub(DISCORD_INVITE, "[discord-invite]", text, flags=re.IGNORECASE)
    redacted = re.sub(PHONE, "[phone]", redacted, flags=re.IGNORECASE)
    redacted = re.sub(EMAIL, "[email]", redacted, flags=re.IGNORECASE)
    redacted = re.sub(r"\b\d{15,25}\b", "[id]", redacted)
    return redacted


def build_report_cluster_key(normalized_content: str, media_indicators: str, image_hashes: Sequence[str]) -> str:
    base = normalized_content.strip()
    if not base:
        base = normalize_for_scan(media_indicators)
    if image_hashes:
        base = f"{base} | {'|'.join(sorted(image_hashes))}".strip()
    if not base:
        base = "empty-report"
    canonical = re.sub(DISCORD_INVITE, "[discord-invite]", base, flags=re.IGNORECASE)
    canonical = re.sub(PHONE, "[phone]", canonical, flags=re.IGNORECASE)
    canonical = re.sub(EMAIL, "[email]", canonical, flags=re.IGNORECASE)
    canonical = re.sub(r"https?://\S+", "[url]", canonical, flags=re.IGNORECASE)
    canonical = re.sub(r"\b\d{15,25}\b", "[id]", canonical)
    canonical = re.sub(r"\s+", " ", canonical).strip()
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def prune_attachment_hash_cache(*, now: Optional[datetime] = None) -> None:
    current_time = now or utcnow()
    while ATTACHMENT_HASH_CACHE:
        attachment_id, (_, cached_at) = next(iter(ATTACHMENT_HASH_CACHE.items()))
        if (current_time - cached_at).total_seconds() <= ATTACHMENT_HASH_CACHE_TTL_SECONDS:
            break
        ATTACHMENT_HASH_CACHE.pop(attachment_id, None)

    while len(ATTACHMENT_HASH_CACHE) > ATTACHMENT_HASH_CACHE_LIMIT:
        ATTACHMENT_HASH_CACHE.popitem(last=False)


def attachment_hash_cache_get(attachment_id: int) -> Optional[str]:
    if attachment_id <= 0:
        return None

    prune_attachment_hash_cache()
    cached = ATTACHMENT_HASH_CACHE.get(attachment_id)
    if cached is None:
        return None

    digest, cached_at = cached
    if (utcnow() - cached_at).total_seconds() > ATTACHMENT_HASH_CACHE_TTL_SECONDS:
        ATTACHMENT_HASH_CACHE.pop(attachment_id, None)
        return None

    ATTACHMENT_HASH_CACHE.move_to_end(attachment_id)
    return digest


def attachment_hash_cache_put(attachment_id: int, digest: str) -> None:
    if attachment_id <= 0 or not digest:
        return

    ATTACHMENT_HASH_CACHE[attachment_id] = (digest, utcnow())
    ATTACHMENT_HASH_CACHE.move_to_end(attachment_id)
    prune_attachment_hash_cache()


def is_hashable_image_attachment(attachment: discord.Attachment) -> bool:
    filename = (getattr(attachment, "filename", "") or "").lower()
    content_type = (getattr(attachment, "content_type", "") or "").lower()
    if content_type.startswith("image/"):
        return True
    return Path(filename).suffix.lower() in KNOWN_IMAGE_HASH_EXTENSIONS


def should_attempt_live_image_hash_lookup(message: discord.Message) -> bool:
    if LIVE_IMAGE_HASH_MODE == "disabled":
        return False

    hashable_attachments = [
        attachment
        for attachment in message.attachments
        if is_hashable_image_attachment(attachment)
        and 0 < int(getattr(attachment, "size", 0) or 0) <= KNOWN_IMAGE_HASH_MAX_BYTES
    ]
    if not hashable_attachments:
        return False

    if LIVE_IMAGE_HASH_MODE == "always":
        return True

    normalized = normalize_for_scan(message.content or "")
    if not normalized:
        return True
    if len(normalized) <= LIVE_IMAGE_HASH_SUSPICIOUS_TEXT_MAX_CHARS:
        return True
    if "@everyone" in normalized or "@here" in normalized:
        return True
    if len(hashable_attachments) >= 2:
        return True
    return False


async def read_attachment_bytes(attachment: discord.Attachment) -> bytes:
    try:
        return await attachment.read(use_cached=True)
    except TypeError:
        return await attachment.read()


def _sha256_hexdigest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


async def compute_attachment_sha256(attachment: discord.Attachment) -> Optional[str]:
    attachment_id = int(getattr(attachment, "id", 0) or 0)
    cached_digest = attachment_hash_cache_get(attachment_id)
    if cached_digest is not None:
        return cached_digest

    size = int(getattr(attachment, "size", 0) or 0)
    if size <= 0 or size > KNOWN_IMAGE_HASH_MAX_BYTES:
        return None
    if not is_hashable_image_attachment(attachment):
        return None

    try:
        payload = await read_attachment_bytes(attachment)
    except (discord.Forbidden, discord.NotFound, discord.HTTPException):
        return None

    digest = await asyncio.to_thread(_sha256_hexdigest, payload)
    if attachment_id:
        attachment_hash_cache_put(attachment_id, digest)
    return digest


async def compute_message_image_hashes(message: discord.Message) -> List[str]:
    hashes: List[str] = []
    for attachment in message.attachments:
        digest = await compute_attachment_sha256(attachment)
        if digest and digest not in hashes:
            hashes.append(digest)
    return hashes


async def classify_known_spam_image_hashes(message: discord.Message) -> Tuple[bool, str, str, List[str]]:
    if not MANAGED_KNOWN_IMAGE_HASHES:
        return False, "", "", []

    hashes = await compute_message_image_hashes(message)
    hits = [digest for digest in hashes if digest in MANAGED_KNOWN_IMAGE_HASHES]
    if hits:
        return True, "known_spam_artifact", "sha256:" + ", ".join(hits), hashes
    return False, "", "", hashes


async def classify_message_for_moderation_async(
    message: discord.Message,
    *,
    allow_image_hashes: bool = True,
    force_image_hashes: bool = False,
) -> Tuple[bool, str, str]:
    matched, reason, normalized = classify_message_for_moderation(message)
    if matched:
        return matched, reason, normalized

    matched, reason, normalized, _ = classify_message_for_domain_blocklists(message)
    if matched:
        return matched, reason, normalized

    should_hash = allow_image_hashes and (force_image_hashes or should_attempt_live_image_hash_lookup(message))
    if should_hash:
        matched, reason, normalized, _ = await classify_known_spam_image_hashes(message)
        if matched:
            return matched, reason, normalized

    return False, "", normalized


def suggestion_hook_search(
    suggestion: Optional[RuleSuggestion],
    hook_name: str,
    normalized: str,
    *,
    compiled_matchers: Optional[CompiledSuggestionMatchers] = None,
) -> bool:
    if suggestion is None or suggestion.decision != "propose":
        return False
    if suggestion.target_type != "hook" or suggestion.target_name != hook_name or not suggestion.pattern:
        return False
    compiled = None
    if compiled_matchers is not None:
        compiled = compiled_matchers.hook_patterns.get(hook_name)
    if compiled is None:
        try:
            compiled = compile_dynamic_regex(suggestion.pattern, where=f"suggestion.hook.{hook_name}")
        except ValueError:
            return False
    return safe_dynamic_regex_search(compiled, normalized)


def suggestion_custom_rule_match(
    suggestion: Optional[RuleSuggestion],
    normalized: str,
    *,
    compiled_matchers: Optional[CompiledSuggestionMatchers] = None,
) -> bool:
    if suggestion is None or suggestion.decision != "propose":
        return False
    if suggestion.target_type != "custom_rule" or not suggestion.pattern:
        return False
    compiled = compiled_matchers.custom_rule_pattern if compiled_matchers is not None else None
    if compiled is None:
        try:
            compiled = compile_dynamic_regex(suggestion.pattern, where="suggestion.custom_rule")
        except ValueError:
            return False
    return safe_dynamic_regex_search(compiled, normalized)


def suggestion_artifact_values(suggestion: Optional[RuleSuggestion]) -> Tuple[Set[str], Set[str]]:
    normalized_values: Set[str] = set()
    hash_values: Set[str] = set()
    if suggestion is None or suggestion.decision != "propose" or suggestion.target_type != "artifact":
        return normalized_values, hash_values

    for value in suggestion.exact_values:
        cleaned = str(value).strip()
        if not cleaned:
            continue
        if cleaned.lower().startswith("sha256:"):
            hash_values.add(cleaned.split(":", 1)[1].strip().lower())
            continue
        normalized_values.add(normalize_for_scan(cleaned))
    return normalized_values, hash_values


def compile_suggestion_matchers(suggestion: Optional[RuleSuggestion]) -> CompiledSuggestionMatchers:
    if suggestion is None or suggestion.decision != "propose":
        return CompiledSuggestionMatchers()

    artifact_values, hash_values = suggestion_artifact_values(suggestion)
    hook_patterns: Dict[str, safe_regex.Pattern[str]] = {}
    custom_rule_pattern: Optional[safe_regex.Pattern[str]] = None

    if suggestion.pattern:
        if suggestion.target_type == "hook" and suggestion.target_name:
            try:
                hook_patterns[suggestion.target_name] = compile_dynamic_regex(
                    suggestion.pattern,
                    where=f"suggestion.hook.{suggestion.target_name}",
                )
            except ValueError:
                pass
        elif suggestion.target_type == "custom_rule":
            try:
                custom_rule_pattern = compile_dynamic_regex(
                    suggestion.pattern,
                    where="suggestion.custom_rule",
                )
            except ValueError:
                pass

    return CompiledSuggestionMatchers(
        hook_patterns=hook_patterns,
        custom_rule_pattern=custom_rule_pattern,
        artifact_values=artifact_values,
        hash_values=hash_values,
    )


def matches_known_spam_artifact_with_suggestion(
    normalized_content: str,
    normalized_media: str,
    *,
    suggestion: Optional[RuleSuggestion] = None,
    compiled_suggestion: Optional[CompiledSuggestionMatchers] = None,
) -> bool:
    if matches_known_spam_artifact(normalized_content) or matches_known_spam_artifact(normalized_media):
        return True

    values = compiled_suggestion.artifact_values if compiled_suggestion is not None else suggestion_artifact_values(suggestion)[0]
    if not values:
        return False
    return any(value in normalized_content or value in normalized_media for value in values)


def classify_candidate_content_and_media(
    *,
    content: str,
    media_indicators: str = "",
    image_hashes: Optional[Sequence[str]] = None,
    suggestion: Optional[RuleSuggestion] = None,
    compiled_suggestion: Optional[CompiledSuggestionMatchers] = None,
) -> Tuple[bool, str, str]:
    normalized = normalize_for_scan(content or "")
    normalized_media = normalize_for_scan(media_indicators or "")
    image_hashes = [str(value).strip().lower() for value in (image_hashes or []) if str(value).strip()]
    candidate_hashes = compiled_suggestion.hash_values if compiled_suggestion is not None else suggestion_artifact_values(suggestion)[1]
    managed_hook_hits: Dict[str, bool] = {}
    suggestion_hook_hits: Dict[str, bool] = {}

    def managed_hook_hit(hook_name: str) -> bool:
        if hook_name not in managed_hook_hits:
            managed_hook_hits[hook_name] = managed_hook_search(hook_name, normalized)
        return managed_hook_hits[hook_name]

    def suggestion_hook_hit(hook_name: str) -> bool:
        if hook_name not in suggestion_hook_hits:
            suggestion_hook_hits[hook_name] = suggestion_hook_search(
                suggestion,
                hook_name,
                normalized,
                compiled_matchers=compiled_suggestion,
            )
        return suggestion_hook_hits[hook_name]

    anti_ticket = (
        ANTI_TICKET_CONTEXT.search(normalized)
        or managed_hook_hit("anti_ticket")
        or suggestion_hook_hit("anti_ticket")
    )
    anti_giveaway = (
        ANTI_GIVEAWAY_CONTEXT.search(normalized)
        or managed_hook_hit("anti_giveaway")
        or suggestion_hook_hit("anti_giveaway")
    )

    if (
        (
            matches_known_spam_artifact_with_suggestion(
                normalized,
                normalized_media,
                suggestion=suggestion,
                compiled_suggestion=compiled_suggestion,
            )
            or any(digest in MANAGED_KNOWN_IMAGE_HASHES or digest in candidate_hashes for digest in image_hashes)
        )
        and not anti_ticket
        and not anti_giveaway
    ):
        artifact_normalized = normalized if normalized.strip() else normalized_media
        if image_hashes and any(digest in MANAGED_KNOWN_IMAGE_HASHES or digest in candidate_hashes for digest in image_hashes):
            artifact_normalized = "sha256:" + ", ".join(
                digest for digest in image_hashes
                if digest in MANAGED_KNOWN_IMAGE_HASHES or digest in candidate_hashes
            )
        return True, "known_spam_artifact", artifact_normalized

    if is_likely_legit_campus_post(normalized):
        return False, "", normalized

    ticket_words_hit = (
        TICKET_WORDS.search(normalized)
        or managed_hook_hit("ticket_words")
        or suggestion_hook_hit("ticket_words")
    )
    ticket_context_hit = (
        ARTIST_EVENT_WORDS.search(normalized)
        or VENUE_LOCATION_WORDS.search(normalized)
        or GENERIC_TICKET_CONTEXT.search(normalized)
        or managed_hook_hit("ticket_context")
        or suggestion_hook_hit("ticket_context")
    )
    ticket_contact_hit = (
        TICKET_CONTACT.search(normalized)
        or managed_hook_hit("ticket_contact")
        or suggestion_hook_hit("ticket_contact")
    )
    detailed_ticket = (
        ticket_words_hit
        and (
            ARTIST_EVENT_WORDS.search(normalized)
            or managed_hook_hit("ticket_context")
            or suggestion_hook_hit("ticket_context")
        )
        and (
            VENUE_LOCATION_WORDS.search(normalized)
            or managed_hook_hit("ticket_context")
            or suggestion_hook_hit("ticket_context")
        )
        and ticket_contact_hit
    )
    generic_ticket = ticket_words_hit and ticket_contact_hit and ticket_context_hit
    if (detailed_ticket or generic_ticket) and not anti_ticket:
        return True, "ticket_resale", normalized

    giveaway_item_hit = (
        ITEM_WORDS.search(normalized)
        or CAMERA_GEAR_TERMS.search(normalized)
        or managed_hook_hit("giveaway_item")
        or suggestion_hook_hit("giveaway_item")
    )
    strict_giveaway_intent_hit = (
        GIVEAWAY_INTENT_STRICT.search(normalized)
        or (GIVEAWAY_BROADCAST.search(normalized) and GIVEAWAY_SOFT_VOCAB.search(normalized))
        or managed_hook_hit("giveaway_intent")
        or suggestion_hook_hit("giveaway_intent")
    )
    if (
        (
            strict_giveaway_intent_hit
            and (
                GIVEAWAY_INTENT.search(normalized)
                or managed_hook_hit("giveaway_intent")
                or suggestion_hook_hit("giveaway_intent")
            )
        )
        and giveaway_item_hit
        and (
            GIVEAWAY_CONTACT.search(normalized)
            or managed_hook_hit("giveaway_contact")
            or suggestion_hook_hit("giveaway_contact")
        )
        and not anti_giveaway
    ):
        return True, "giveaway_spam", normalized

    job_features = sum(
        bool(pattern.search(normalized))
        for pattern in (JOB_REMOTE, JOB_PAY, JOB_TASKS, JOB_RESPONSE)
    )
    job_features += int(managed_hook_hit("job_remote") or suggestion_hook_hit("job_remote"))
    job_features += int(managed_hook_hit("job_pay") or suggestion_hook_hit("job_pay"))
    job_features += int(managed_hook_hit("job_tasks") or suggestion_hook_hit("job_tasks"))
    job_features += int(managed_hook_hit("job_response") or suggestion_hook_hit("job_response"))
    if (
        (
            JOB_ROLE.search(normalized)
            or managed_hook_hit("job_role")
            or suggestion_hook_hit("job_role")
        )
        and job_features >= 2
        and (
            JOB_PAY.search(normalized)
            or JOB_TASKS.search(normalized)
            or managed_hook_hit("job_pay")
            or managed_hook_hit("job_tasks")
            or suggestion_hook_hit("job_pay")
            or suggestion_hook_hit("job_tasks")
        )
    ):
        return True, "job_spam", normalized

    if (
        (
            ACADEMIC_INTENT.search(normalized)
            or managed_hook_hit("academic_intent")
            or suggestion_hook_hit("academic_intent")
        )
        and (
            ACADEMIC_CONTACT.search(normalized)
            or managed_hook_hit("academic_contact")
            or suggestion_hook_hit("academic_contact")
        )
    ):
        return True, "academic_spam", normalized

    custom_rule = match_managed_custom_rule(normalized)
    if custom_rule is not None or suggestion_custom_rule_match(
        suggestion,
        normalized,
        compiled_matchers=compiled_suggestion,
    ):
        reason = custom_rule.reason if custom_rule is not None else (suggestion.reason if suggestion is not None else "")
        return True, reason, normalized

    return False, "", normalized


# ============================================================
# Allowlist / exemptions
# ============================================================

def is_allowlisted_member(member: discord.Member) -> bool:
    if member.id in ALLOWLIST_USER_IDS:
        return True
    if any(role.id in ALLOWLIST_ROLE_IDS for role in member.roles):
        return True
    return False


def is_exempt_message(message: discord.Message) -> bool:
    if IGNORE_BOTS and message.author.bot:
        return True

    if message.channel.id in ALLOWLIST_CHANNEL_IDS:
        return True

    if isinstance(message.author, discord.Member):
        if IGNORE_GUILD_ADMINS and message.author.guild_permissions.administrator:
            return True
        return is_allowlisted_member(message.author)

    return False


# ============================================================
# Audit/logging helpers
# ============================================================

def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def pretty_ts(dt: datetime, style: str = "F") -> str:
    return discord.utils.format_dt(dt, style=style)


def base_embed(title: str, color: discord.Color, description: Optional[str] = None) -> discord.Embed:
    embed = discord.Embed(
        title=title,
        description=description,
        color=color,
        timestamp=utcnow(),
    )
    embed.set_footer(text="SpamFighter")
    return embed


def limit_text(text: str, limit: int = MAX_AUDIT_CONTENT_LEN) -> Tuple[str, bool]:
    if not text:
        return "[empty]", False

    if len(text) <= limit:
        return text, False

    remaining = len(text) - limit
    trimmed = text[:limit].rstrip()
    return f"{trimmed}\n...[truncated {remaining} chars]", True


def escape_codeblock(text: str) -> str:
    return text.replace("```", "`\u200b``")


def format_embed_field_value(text: str, *, limit: int = 1024, codeblock: bool = False) -> str:
    value = text or "[empty]"
    if codeblock:
        value = escape_codeblock(value)

    if len(value) > limit - (6 if codeblock else 0):
        inner_limit = max(1, limit - (6 if codeblock else 0))
        suffix = "\n...[truncated]"
        keep = max(1, inner_limit - len(suffix))
        value = value[:keep].rstrip() + suffix

    return f"```{value}```" if codeblock else value


def split_text_chunks(text: str, chunk_size: int = 3900) -> List[str]:
    text = escape_codeblock(text)
    if len(text) <= chunk_size:
        return [text]

    chunks: List[str] = []
    start = 0
    while start < len(text):
        end = min(start + chunk_size, len(text))
        if end < len(text):
            split_at = text.rfind("\n", start, end)
            if split_at <= start:
                split_at = end
            end = split_at
        chunk = text[start:end].strip()
        if not chunk:
            chunk = text[start:min(start + chunk_size, len(text))]
            end = min(start + chunk_size, len(text))
        chunks.append(chunk)
        start = end

    return chunks


def embed_text_size(embed: discord.Embed) -> int:
    total = 0
    total += len(embed.title or "")
    total += len(embed.description or "")
    if embed.footer and embed.footer.text:
        total += len(embed.footer.text)
    if embed.author and embed.author.name:
        total += len(embed.author.name)
    for field in embed.fields:
        total += len(field.name or "")
        total += len(field.value or "")
    return total


def batch_embeds(embeds: Sequence[discord.Embed], max_embeds: int = 10, max_chars: int = 5800) -> List[List[discord.Embed]]:
    batches: List[List[discord.Embed]] = []
    current: List[discord.Embed] = []
    current_chars = 0

    for embed in embeds:
        size = embed_text_size(embed)
        if current and (len(current) >= max_embeds or current_chars + size > max_chars):
            batches.append(current)
            current = []
            current_chars = 0

        current.append(embed)
        current_chars += size

    if current:
        batches.append(current)

    return batches


def build_text_embeds(title: str, text: str, color: discord.Color) -> List[discord.Embed]:
    chunks = split_text_chunks(text)
    embeds: List[discord.Embed] = []

    for index, chunk in enumerate(chunks, start=1):
        chunk_title = title if len(chunks) == 1 else f"{title} ({index}/{len(chunks)})"
        embed = base_embed(
            title=chunk_title,
            color=color,
            description=f"```{chunk}```",
        )
        embeds.append(embed)

    return embeds


def resolve_audit_channel_ids(guild_id: Optional[int]) -> List[int]:
    ids: List[int] = []
    if DEFAULT_AUDIT_LOG_CHANNEL_ID:
        ids.append(DEFAULT_AUDIT_LOG_CHANNEL_ID)
    if guild_id is not None and guild_id in AUDIT_LOG_CHANNEL_MAP:
        ids.append(AUDIT_LOG_CHANNEL_MAP[guild_id])

    unique_ids: List[int] = []
    seen: Set[int] = set()
    for channel_id in ids:
        if channel_id not in seen:
            seen.add(channel_id)
            unique_ids.append(channel_id)
    return unique_ids


def resolve_enforcement_channel_ids(guild_id: Optional[int]) -> List[int]:
    ids: List[int] = []
    if DEFAULT_ENFORCEMENT_LOG_CHANNEL_ID:
        ids.append(DEFAULT_ENFORCEMENT_LOG_CHANNEL_ID)
    if guild_id is not None and guild_id in ENFORCEMENT_LOG_CHANNEL_MAP:
        ids.append(ENFORCEMENT_LOG_CHANNEL_MAP[guild_id])

    unique_ids: List[int] = []
    seen: Set[int] = set()
    for channel_id in ids:
        if channel_id not in seen:
            seen.add(channel_id)
            unique_ids.append(channel_id)
    return unique_ids


async def fetch_messageable_channel(channel_id: int) -> Optional[discord.abc.Messageable]:
    channel = bot.get_channel(channel_id)
    if channel is None:
        try:
            channel = await bot.fetch_channel(channel_id)
        except discord.NotFound:
            log.warning("Channel %s was not found while logging", channel_id)
            return None
        except discord.Forbidden:
            log.warning("Forbidden while fetching log channel %s", channel_id)
            return None
        except discord.HTTPException as exc:
            log.warning(
                "HTTP error while fetching log channel %s: status=%s text=%s",
                channel_id,
                getattr(exc, "status", None),
                getattr(exc, "text", str(exc)),
            )
            return None

    if not isinstance(channel, discord.abc.Messageable):
        log.warning("Configured log channel %s is not messageable", channel_id)
        return None

    return channel


async def send_embeds_to_channel(channel: discord.abc.Messageable, embeds: Sequence[discord.Embed]) -> None:
    for batch in batch_embeds(embeds):
        await channel.send(
            embeds=batch,
            allowed_mentions=discord.AllowedMentions.none(),
        )


async def send_embed_batches(channel_ids: Sequence[int], embeds: Sequence[discord.Embed]) -> None:
    if not channel_ids:
        return

    for channel_id in channel_ids:
        channel = await fetch_messageable_channel(channel_id)
        if channel is None:
            continue

        try:
            await send_embeds_to_channel(channel, embeds)
        except discord.Forbidden:
            log.warning("Forbidden sending logs to channel %s", channel_id)
        except discord.NotFound:
            log.warning("Log channel %s disappeared before send", channel_id)
        except discord.HTTPException as exc:
            log.warning(
                "HTTP error sending logs to %s: status=%s text=%s",
                channel_id,
                getattr(exc, "status", None),
                getattr(exc, "text", str(exc)),
            )


async def send_audit_embeds(guild: Optional[discord.Guild], embeds: Sequence[discord.Embed]) -> None:
    await send_embed_batches(resolve_audit_channel_ids(guild.id if guild else None), embeds)


async def send_enforcement_embeds(guild: Optional[discord.Guild], embeds: Sequence[discord.Embed]) -> None:
    await send_embed_batches(resolve_enforcement_channel_ids(guild.id if guild else None), embeds)


async def dispatch_queued_moderation_log(item: QueuedModerationLog) -> None:
    if not item.channel_ids:
        return

    if item.detail_payload is None:
        await send_embed_batches(item.channel_ids, item.embeds)
        return

    summary_embed = item.embeds[0] if item.embeds else None
    if summary_embed is None:
        return

    for channel_id in item.channel_ids:
        channel = await fetch_messageable_channel(channel_id)
        if channel is None:
            continue

        try:
            sent_message = await channel.send(
                embed=summary_embed,
                view=AuditDeletionDetailView(),
                allowed_mentions=discord.AllowedMentions.none(),
            )
            remember_audit_detail_payload(sent_message.id, item.detail_payload)
            if len(item.embeds) > 1:
                await send_embeds_to_channel(channel, item.embeds[1:])
        except discord.Forbidden:
            log.warning("Forbidden sending queued moderation log to channel %s", channel_id)
        except discord.NotFound:
            log.warning("Queued moderation log channel %s disappeared before send", channel_id)
        except discord.HTTPException as exc:
            log.warning(
                "HTTP error sending queued moderation log to %s: status=%s text=%s",
                channel_id,
                getattr(exc, "status", None),
                getattr(exc, "text", str(exc)),
            )


async def enqueue_moderation_log(item: QueuedModerationLog) -> None:
    try:
        MODERATION_LOG_QUEUE.put_nowait(item)
    except asyncio.QueueFull:
        dropped_item = False
        with contextlib.suppress(asyncio.QueueEmpty):
            MODERATION_LOG_QUEUE.get_nowait()
            MODERATION_LOG_QUEUE.task_done()
            dropped_item = True
        try:
            MODERATION_LOG_QUEUE.put_nowait(item)
        except asyncio.QueueFull:
            log.warning("Moderation log queue is full; dropping newest queued moderation log.")
            return
        if dropped_item:
            log.warning("Moderation log queue is full; dropped the oldest queued moderation log to preserve latency.")


async def moderation_log_worker() -> None:
    while True:
        item = await MODERATION_LOG_QUEUE.get()
        try:
            await dispatch_queued_moderation_log(item)
        except Exception as exc:
            log.warning("Queued moderation log delivery failed: %s", exc)
        finally:
            MODERATION_LOG_QUEUE.task_done()


def start_moderation_log_task() -> None:
    global MODERATION_LOG_TASK
    if MODERATION_LOG_TASK is not None:
        return
    MODERATION_LOG_TASK = asyncio.create_task(
        moderation_log_worker(),
        name="spamfighter-moderation-log-worker",
    )


async def flush_moderation_log_queue(timeout_seconds: float = 5.0) -> None:
    if MODERATION_LOG_QUEUE.empty():
        return
    try:
        await asyncio.wait_for(MODERATION_LOG_QUEUE.join(), timeout=timeout_seconds)
    except asyncio.TimeoutError:
        log.warning(
            "Timed out waiting for queued moderation logs to drain. pending=%s",
            MODERATION_LOG_QUEUE.qsize(),
        )


def remember_audit_detail_payload(message_id: int, payload: AuditDeletionDetailPayload) -> None:
    AUDIT_DETAIL_PAYLOADS[message_id] = payload
    while len(AUDIT_DETAIL_PAYLOADS) > AUDIT_DETAIL_CACHE_LIMIT:
        oldest_message_id = next(iter(AUDIT_DETAIL_PAYLOADS))
        AUDIT_DETAIL_PAYLOADS.pop(oldest_message_id, None)


def build_enforcement_warning(guild_id: int) -> Optional[str]:
    if guild_id in ENFORCEMENT_LOG_CHANNEL_MAP:
        return None
    if resolve_enforcement_channel_ids(guild_id):
        return (
            "No guild-specific enforcement channel is configured for this guild. "
            "Critical alerts are only reaching the main enforcement sink. "
            "Use `/spamfighter set-enforcement-channel` to add a local enforcement log."
        )
    return (
        "No enforcement channel is configured for this guild. "
        "Critical deletion and escalation logs are currently missing. "
        "Use `/spamfighter set-enforcement-channel` to restore this critical log."
    )


def build_audit_detail_embeds(
    payload: AuditDeletionDetailPayload,
    *,
    detail_kind: str,
    requested_by,
) -> List[discord.Embed]:
    detail_text = "[empty]"
    detail_title = "Audit Detail"
    detail_color = discord.Color.blurple()

    if detail_kind == "normalized":
        detail_title = "Normalized Content"
        detail_text = payload.normalized_content or "[empty]"
        detail_color = discord.Color.blurple()
    elif detail_kind == "media":
        detail_title = "Media Indicators"
        detail_text = payload.media_indicators or "No media indicators were recorded for this message."
        detail_color = discord.Color.gold()
    elif detail_kind == "hashes":
        detail_title = "Image Hashes"
        detail_text = "\n".join(payload.image_hashes) if payload.image_hashes else "No image hashes were generated for this message."
        detail_color = discord.Color.green()

    summary = base_embed(
        title=f"Audit Detail: {detail_title}",
        color=detail_color,
        description="Expanded from a spam audit log button.",
    )
    summary.add_field(
        name="Source",
        value=(
            f"Guild: {payload.guild_name} (`{payload.guild_id}`)\n"
            f"Channel: {payload.source_channel_mention} (`{payload.source_channel_id}`)\n"
            f"Author: {payload.source_author_mention} (`{payload.source_author_id}`)"
        ),
        inline=False,
    )
    summary.add_field(name="Reason", value=payload.reason or "unknown", inline=True)
    summary.add_field(name="Event", value="Deleted" if payload.deleted else "Dry Run", inline=True)
    summary.add_field(name="Requested By", value=f"{requested_by.mention} (`{requested_by.id}`)", inline=False)

    embeds = [summary]
    embeds.extend(build_text_embeds(detail_title, detail_text, detail_color))
    return embeds


async def send_audit_deletion_summary(
    guild: Optional[discord.Guild],
    embed: discord.Embed,
    detail_payload: AuditDeletionDetailPayload,
) -> None:
    channel_ids = resolve_audit_channel_ids(guild.id if guild else None)
    if not channel_ids:
        return
    await enqueue_moderation_log(
        QueuedModerationLog(
            channel_ids=tuple(channel_ids),
            embeds=(embed,),
            detail_payload=detail_payload,
        )
    )


async def audit_message_deletion(
    message: discord.Message,
    reason: str,
    normalized: str,
    deleted: bool,
    violation_count: int,
    image_hashes: Optional[Sequence[str]] = None,
) -> None:
    original_preview, original_trimmed = limit_text(message.content or "[no text]", limit=min(MAX_AUDIT_CONTENT_LEN, 900))
    media_text = render_message_media_indicators(message)
    media_items = extract_message_media_indicators(message)
    image_hash_list = tuple(image_hashes or ())
    summary = base_embed(
        title="Spam Message Deleted" if deleted else "Spam Match (Dry Run)",
        color=discord.Color.red() if deleted else discord.Color.orange(),
        description=(
            "The message matched a spam rule and was deleted."
            if deleted
            else "The message matched a spam rule in dry-run mode. No deletion was performed."
        ),
    )
    summary.add_field(
        name="Source",
        value=(
            f"Guild: {message.guild.name} (`{message.guild.id}`)\n"
            f"Channel: {message.channel.mention} (`{message.channel.id}`)\n"
            f"Author: {message.author.mention} (`{message.author.id}`)"
        ),
        inline=False,
    )
    summary.add_field(name="Reason", value=reason or "unknown", inline=True)
    summary.add_field(name="Violation Count", value=str(violation_count), inline=True)
    summary.add_field(name="Created", value=pretty_ts(message.created_at, "F"), inline=True)
    summary.add_field(name="Detected", value=pretty_ts(utcnow(), "F"), inline=True)
    summary.add_field(name="Media Items", value=str(len(media_items)), inline=True)
    summary.add_field(name="Image Hashes", value=str(len(image_hash_list)), inline=True)
    if getattr(message, "jump_url", None):
        summary.add_field(name="Jump URL", value=message.jump_url, inline=False)
    summary.add_field(
        name="Original Content",
        value=format_embed_field_value(original_preview, limit=1000, codeblock=True),
        inline=False,
    )
    details_text = (
        "Use the buttons below to post normalized content, media indicators, or image hashes into this audit channel."
    )
    if original_trimmed:
        details_text += "\nOriginal content preview was truncated in this summary."
    summary.add_field(name="More Details", value=format_embed_field_value(details_text, limit=500), inline=False)

    enforcement_warning = build_enforcement_warning(message.guild.id)
    if enforcement_warning:
        summary.add_field(
            name="Enforcement Warning",
            value=format_embed_field_value(enforcement_warning, limit=500),
            inline=False,
        )

    detail_payload = AuditDeletionDetailPayload(
        guild_id=message.guild.id,
        guild_name=message.guild.name,
        source_channel_id=message.channel.id,
        source_channel_mention=message.channel.mention,
        source_author_id=message.author.id,
        source_author_mention=message.author.mention,
        reason=reason or "unknown",
        deleted=deleted,
        normalized_content=normalized or "[empty]",
        media_indicators=media_text,
        image_hashes=image_hash_list,
    )
    await send_audit_deletion_summary(message.guild, summary, detail_payload)


async def enforcement_log_deletion(
    message: discord.Message,
    reason: str,
    violation_count: int,
    deleted: bool,
    image_hashes: Optional[Sequence[str]] = None,
) -> None:
    media_items = extract_message_media_indicators(message)

    summary = base_embed(
        title="Spam Message Deleted" if deleted else "Spam Match (Dry Run)",
        color=discord.Color.red() if deleted else discord.Color.orange(),
        description=(
            "A spam message was deleted and counted toward enforcement."
            if deleted
            else "A spam match was recorded in dry-run mode. No deletion or escalation was performed."
        ),
    )
    summary.add_field(
        name="Source",
        value=(
            f"Guild: {message.guild.name} (`{message.guild.id}`)\n"
            f"Channel: {message.channel.mention} (`{message.channel.id}`)\n"
            f"User: {message.author.mention} (`{message.author.id}`)"
        ),
        inline=False,
    )
    summary.add_field(name="Reason", value=reason or "unknown", inline=True)
    summary.add_field(name="Violation Count", value=str(violation_count), inline=True)
    summary.add_field(name="Created", value=pretty_ts(message.created_at, "F"), inline=True)
    summary.add_field(name="Media Items", value=str(len(media_items)), inline=True)
    summary.add_field(name="Image Hashes", value=str(len(image_hashes or ())), inline=True)
    if getattr(message, "jump_url", None):
        summary.add_field(name="Jump URL", value=message.jump_url, inline=False)

    channel_ids = resolve_enforcement_channel_ids(message.guild.id if message.guild else None)
    if not channel_ids:
        return
    await enqueue_moderation_log(
        QueuedModerationLog(
            channel_ids=tuple(channel_ids),
            embeds=(summary,),
        )
    )


async def audit_control_action(
    interaction: discord.Interaction,
    action: str,
    details: str,
) -> None:
    embed = base_embed(
        title=f"Control Action: {action}",
        color=discord.Color.blurple(),
        description=details,
    )
    guild_name = interaction.guild.name if interaction.guild else "DM/Unknown"
    guild_id = interaction.guild.id if interaction.guild else 0
    embed.add_field(name="Actor", value=f"{interaction.user.mention} (`{interaction.user.id}`)", inline=False)
    embed.add_field(name="Guild", value=f"{guild_name} (`{guild_id}`)", inline=False)
    embed.add_field(name="When", value=pretty_ts(utcnow(), "F"), inline=False)
    await send_audit_embeds(interaction.guild, [embed])


async def audit_error(
    guild: Optional[discord.Guild],
    title: str,
    where: str,
    exc: BaseException,
    extra: Optional[Dict[str, str]] = None,
) -> None:
    embed = base_embed(
        title=title,
        color=discord.Color.dark_red(),
        description=f"Location: `{where}`",
    )
    embed.add_field(name="Error Type", value=type(exc).__name__, inline=True)
    embed.add_field(name="When", value=pretty_ts(utcnow(), "F"), inline=True)

    embed.add_field(
        name="Details",
        value=format_embed_field_value(str(exc) or "[no error text]", codeblock=True),
        inline=False,
    )

    if extra:
        for key, value in extra.items():
            embed.add_field(name=key, value=format_embed_field_value(value, limit=500), inline=False)

    await send_audit_embeds(guild, [embed])


def interaction_component_id(interaction: discord.Interaction) -> str:
    data = getattr(interaction, "data", None)
    if isinstance(data, dict):
        return str(data.get("custom_id", "")).strip()
    return ""


async def audit_unauthorized_component_interaction(
    interaction: discord.Interaction,
    *,
    title: str,
    where: str,
    details: str,
    extra: Optional[Dict[str, str]] = None,
) -> None:
    component_id = interaction_component_id(interaction) or "unknown"
    payload_extra = {
        "User": f"{interaction.user} ({interaction.user.id})",
        "Component": component_id,
    }
    message = getattr(interaction, "message", None)
    if message is not None:
        payload_extra["Message"] = str(getattr(message, "id", 0) or 0)
    if extra:
        payload_extra.update(extra)
    await audit_error(
        interaction.guild,
        title=title,
        where=where,
        exc=PermissionError(details),
        extra=payload_extra,
    )


class AuditDeletionDetailView(discord.ui.View):
    def __init__(self) -> None:
        super().__init__(timeout=None)

    async def on_error(self, interaction: discord.Interaction, error: Exception, item: discord.ui.Item) -> None:
        try:
            await respond_ephemeral(interaction, content="That audit detail request failed.")
        except Exception:
            pass
        await audit_error(
            interaction.guild,
            "Audit Detail Button Failed",
            f"AuditDeletionDetailView.on_error:{getattr(item, 'custom_id', None) or type(item).__name__}",
            error,
            extra={
                "User": f"{interaction.user} ({interaction.user.id})",
                "Message": str(getattr(getattr(interaction, 'message', None), 'id', 0) or 0),
            },
        )

    async def _post_detail(self, interaction: discord.Interaction, detail_kind: str) -> None:
        message = getattr(interaction, "message", None)
        message_id = getattr(message, "id", 0) if message is not None else 0
        payload = AUDIT_DETAIL_PAYLOADS.get(message_id)
        if payload is None:
            await respond_ephemeral(
                interaction,
                content="Those audit details are no longer available. New audit events will still include working buttons while the bot stays online.",
            )
            return

        channel = interaction.channel
        if channel is None or not isinstance(channel, discord.abc.Messageable):
            await respond_ephemeral(interaction, content="I couldn't find a messageable channel for that audit detail request.")
            return

        await interaction.response.defer()
        embeds = build_audit_detail_embeds(payload, detail_kind=detail_kind, requested_by=interaction.user)
        try:
            await send_embeds_to_channel(channel, embeds)
        except discord.Forbidden:
            await respond_ephemeral(interaction, content="I don't have permission to post the requested audit details here.")
        except discord.HTTPException as exc:
            await respond_ephemeral(interaction, content=f"Failed to post the requested audit details: {exc}")

    @discord.ui.button(label="Normalized Content", style=discord.ButtonStyle.primary, custom_id="spamfighter:audit:normalized")
    async def normalized(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        await self._post_detail(interaction, "normalized")

    @discord.ui.button(label="Media Indicators", style=discord.ButtonStyle.secondary, custom_id="spamfighter:audit:media")
    async def media(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        await self._post_detail(interaction, "media")

    @discord.ui.button(label="Image Hashes", style=discord.ButtonStyle.success, custom_id="spamfighter:audit:hashes")
    async def hashes(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        await self._post_detail(interaction, "hashes")


# ============================================================
# Misc helpers
# ============================================================

async def respond_ephemeral(
    interaction: discord.Interaction,
    *,
    content: Optional[str] = None,
    embed: Optional[discord.Embed] = None,
    view: Optional[discord.ui.View] = None,
) -> None:
    kwargs: Dict[str, object] = {
        "ephemeral": True,
        "allowed_mentions": discord.AllowedMentions.none(),
    }

    if content is not None:
        kwargs["content"] = content
    if embed is not None:
        kwargs["embed"] = embed
    if view is not None:
        kwargs["view"] = view

    # Prevent sending a completely empty response if a caller forgets content/embed/view.
    if content is None and embed is None and view is None:
        kwargs["content"] = "\u200b"

    try:
        if interaction.response.is_done():
            await interaction.followup.send(**kwargs)
        else:
            await interaction.response.send_message(**kwargs)
    except discord.NotFound:
        command_name = getattr(getattr(interaction, "command", None), "qualified_name", "unknown")
        log.warning("Interaction expired before an ephemeral response could be sent for command %s.", command_name)


async def get_bot_member(guild: discord.Guild) -> discord.Member:
    if bot.user is None:
        raise RuntimeError("Bot user is not available yet.")

    member = guild.get_member(bot.user.id)
    if member is not None:
        return member

    return await guild.fetch_member(bot.user.id)


def format_permission(value: bool) -> str:
    return "âœ… Yes" if value else "âŒ No"


def build_loaded_domain_blocklist_summary(*, include_paths: bool = False) -> str:
    lines: List[str] = []
    for key in DOMAIN_BLOCKLIST_KEYS:
        path = DOMAIN_BLOCKLIST_PATHS[key]
        count = len(LOADED_DOMAIN_BLOCKLISTS.get(key, frozenset()))
        loaded_at = DOMAIN_BLOCKLIST_LAST_LOADED_AT.get(key)
        line = f"{format_domain_blocklist_label(key)}: {count} domain(s)"
        if loaded_at is not None:
            line += f" | loaded {pretty_ts(loaded_at, 'R')}"
        if include_paths:
            line += f"\n`{path}`"
        lines.append(line)
    return "\n".join(lines)


def build_permission_embed(
    *,
    guild: discord.Guild,
    channel: Optional[discord.abc.GuildChannel],
    member: discord.Member,
) -> discord.Embed:
    perms = member.guild_permissions if channel is None else channel.permissions_for(member)

    embed = base_embed(
        title="Bot Permissions Check",
        color=discord.Color.blurple(),
        description="Resolved bot permissions for this guild/channel.",
    )
    embed.add_field(name="Guild", value=f"{guild.name} (`{guild.id}`)", inline=False)
    embed.add_field(
        name="Channel",
        value=(f"{channel.mention} (`{channel.id}`)" if channel is not None else "Guild-level permissions"),
        inline=False,
    )
    embed.add_field(name="Bot User", value=f"{member.mention} (`{member.id}`)", inline=False)

    embed.add_field(name="View Channel", value=format_permission(perms.view_channel), inline=True)
    embed.add_field(name="Send Messages", value=format_permission(getattr(perms, "send_messages", False)), inline=True)
    embed.add_field(name="Embed Links", value=format_permission(getattr(perms, "embed_links", False)), inline=True)
    embed.add_field(name="Manage Messages", value=format_permission(perms.manage_messages), inline=True)
    embed.add_field(name="Read Message History", value=format_permission(getattr(perms, "read_message_history", False)), inline=True)
    embed.add_field(name="Attach Files", value=format_permission(getattr(perms, "attach_files", False)), inline=True)
    embed.add_field(name="Moderate Members", value=format_permission(getattr(perms, "moderate_members", False)), inline=True)
    embed.add_field(name="Kick Members", value=format_permission(getattr(perms, "kick_members", False)), inline=True)
    embed.add_field(name="Ban Members", value=format_permission(getattr(perms, "ban_members", False)), inline=True)
    return embed


def build_guild_settings_embed(guild: discord.Guild) -> discord.Embed:
    moderation = resolve_moderation_settings(guild.id)

    embed = base_embed(
        title="SpamFighter Guild Configuration",
        color=discord.Color.blurple(),
        description="This is the effective configuration for the current guild.",
    )
    embed.add_field(name="Guild", value=f"{guild.name} (`{guild.id}`)", inline=False)
    embed.add_field(
        name="Audit Channel",
        value=f"<#{AUDIT_LOG_CHANNEL_MAP[guild.id]}>" if guild.id in AUDIT_LOG_CHANNEL_MAP else "Not configured",
        inline=True,
    )
    embed.add_field(
        name="Enforcement Channel",
        value=f"<#{ENFORCEMENT_LOG_CHANNEL_MAP[guild.id]}>" if guild.id in ENFORCEMENT_LOG_CHANNEL_MAP else "Not configured",
        inline=True,
    )
    embed.add_field(name="Main Audit Log", value=f"<#{DEFAULT_AUDIT_LOG_CHANNEL_ID}>" if DEFAULT_AUDIT_LOG_CHANNEL_ID else "Disabled", inline=True)
    embed.add_field(name="Main Enforcement Log", value=f"<#{DEFAULT_ENFORCEMENT_LOG_CHANNEL_ID}>" if DEFAULT_ENFORCEMENT_LOG_CHANNEL_ID else "Disabled", inline=True)
    embed.add_field(name="Guild Allowlist Enabled", value=str(GUILD_ALLOWLIST_ENABLED), inline=True)
    embed.add_field(name="Enabled Blocklists", value=format_enabled_domain_blocklists(guild.id), inline=False)
    embed.add_field(name="Deletion Enabled", value=str(moderation.enable_deletion), inline=True)
    embed.add_field(name="Escalation Enabled", value=str(moderation.enable_escalation), inline=True)
    embed.add_field(name="Warn Threshold", value=str(moderation.warn_threshold), inline=True)
    embed.add_field(name="Timeout Threshold", value=str(moderation.timeout_threshold), inline=True)
    embed.add_field(name="Kick Threshold", value=str(moderation.kick_threshold), inline=True)
    embed.add_field(name="Ban Threshold", value=str(moderation.ban_threshold), inline=True)
    embed.add_field(name="Timeout Minutes", value=str(moderation.timeout_minutes), inline=True)
    return embed


async def write_guild_channels(
    guild_id: int,
    *,
    audit_channel_id: Optional[int] = None,
    enforcement_channel_id: Optional[int] = None,
) -> Config:
    def mutator(raw: dict) -> None:
        if audit_channel_id is not None:
            audit_section = raw.setdefault("audit", {})
            channel_map = audit_section.setdefault("channel_map", {})
            channel_map[str(guild_id)] = audit_channel_id

        if enforcement_channel_id is not None:
            enforcement_section = raw.setdefault("enforcement", {})
            channel_map = enforcement_section.setdefault("channel_map", {})
            channel_map[str(guild_id)] = enforcement_channel_id

    return await mutate_config(mutator)


async def write_guild_moderation_overrides(
    guild_id: int,
    *,
    enable_deletion: Optional[bool] = None,
    enable_escalation: Optional[bool] = None,
    warn_threshold: Optional[int] = None,
    timeout_threshold: Optional[int] = None,
    kick_threshold: Optional[int] = None,
    ban_threshold: Optional[int] = None,
    timeout_minutes: Optional[int] = None,
) -> Config:
    def mutator(raw: dict) -> None:
        moderation = raw.setdefault("moderation", {})
        if "defaults" not in moderation and any(
            key in moderation
            for key in ("enable_deletion", "enable_escalation", "warn_threshold", "timeout_threshold", "kick_threshold", "ban_threshold", "timeout_minutes")
        ):
            moderation["defaults"] = {
                "enable_deletion": moderation.pop("enable_deletion", True),
                "enable_escalation": moderation.pop("enable_escalation", False),
                "warn_threshold": moderation.pop("warn_threshold", 1),
                "timeout_threshold": moderation.pop("timeout_threshold", 2),
                "kick_threshold": moderation.pop("kick_threshold", 3),
                "ban_threshold": moderation.pop("ban_threshold", 4),
                "timeout_minutes": moderation.pop("timeout_minutes", 60),
            }

        overrides = moderation.setdefault("guild_overrides", {})
        current = overrides.setdefault(str(guild_id), {})

        if enable_deletion is not None:
            current["enable_deletion"] = bool(enable_deletion)
        if enable_escalation is not None:
            current["enable_escalation"] = bool(enable_escalation)
        if warn_threshold is not None:
            current["warn_threshold"] = int(warn_threshold)
        if timeout_threshold is not None:
            current["timeout_threshold"] = int(timeout_threshold)
        if kick_threshold is not None:
            current["kick_threshold"] = int(kick_threshold)
        if ban_threshold is not None:
            current["ban_threshold"] = int(ban_threshold)
        if timeout_minutes is not None:
            current["timeout_minutes"] = int(timeout_minutes)

    return await mutate_config(mutator)


async def set_global_guild_allowlist_enabled(enabled: bool) -> Config:
    def mutator(raw: dict) -> None:
        guilds = raw.setdefault("guilds", {})
        guilds["allowlist_enabled"] = bool(enabled)

    return await mutate_config(mutator)


async def add_allowed_guild_id(guild_id: int) -> Config:
    normalized_guild_id = int(guild_id)
    if normalized_guild_id <= 0:
        raise ValueError("Guild ID must be a positive integer.")

    def mutator(raw: dict) -> None:
        guilds = raw.setdefault("guilds", {})
        allowed = {int(value) for value in guilds.get("allowed_guild_ids", [])}
        allowed.add(normalized_guild_id)
        guilds["allowed_guild_ids"] = sorted(allowed)

    return await mutate_config(mutator)


async def add_control_admin_user(user_id: int) -> Config:
    normalized_user_id = int(user_id)
    if normalized_user_id <= 0:
        raise ValueError("User ID must be a positive integer.")

    def mutator(raw: dict) -> None:
        control = raw.setdefault("control", {})
        admin_ids = {int(value) for value in control.get("admin_user_ids", [])}
        admin_ids.add(normalized_user_id)
        control["admin_user_ids"] = sorted(admin_ids)

    return await mutate_config(mutator)


async def add_control_super_user(user_id: int) -> Config:
    normalized_user_id = int(user_id)
    if normalized_user_id <= 0:
        raise ValueError("User ID must be a positive integer.")

    def mutator(raw: dict) -> None:
        control = raw.setdefault("control", {})
        super_ids = {int(value) for value in control.get("super_user_ids", [])}
        super_ids.add(normalized_user_id)
        control["super_user_ids"] = sorted(super_ids)

    return await mutate_config(mutator)


async def write_review_channel(channel_id: int) -> Config:
    def mutator(raw: dict) -> None:
        reports = raw.setdefault("reports", {})
        reports["review_channel_id"] = int(channel_id)

    return await mutate_config(mutator)


async def write_review_validation_settings(*, months: int, channel_ids: Sequence[int]) -> Config:
    def mutator(raw: dict) -> None:
        reports = raw.setdefault("reports", {})
        reports["validation_months"] = int(months)
        reports["false_positive_channel_ids"] = [int(channel_id) for channel_id in channel_ids]

    return await mutate_config(mutator)


def is_message_history_channel(channel: object) -> bool:
    return isinstance(channel, MESSAGE_HISTORY_CHANNEL_TYPES)


def iter_message_history_channels(guild: discord.Guild) -> List[MessageHistoryChannel]:
    channels: List[MessageHistoryChannel] = []
    channels.extend(guild.text_channels)
    channels.extend(guild.voice_channels)
    channels.sort(key=lambda item: (getattr(item, "position", 0), getattr(item, "id", 0)))
    return channels


def get_message_history_channel(guild: discord.Guild, channel_id: int) -> Optional[MessageHistoryChannel]:
    channel = guild.get_channel(channel_id)
    if is_message_history_channel(channel):
        return channel
    return None


async def ensure_guild_log_channels(guild: discord.Guild) -> Tuple[discord.TextChannel, discord.TextChannel]:
    overwrite_bot = discord.PermissionOverwrite(
        view_channel=True,
        send_messages=True,
        embed_links=True,
        read_message_history=True,
        manage_messages=True,
    )
    overwrite_everyone = discord.PermissionOverwrite(view_channel=False)

    overwrites = {
        guild.default_role: overwrite_everyone,
    }

    bot_member = await get_bot_member(guild)
    overwrites[bot_member] = overwrite_bot

    audit_channel = discord.utils.get(guild.text_channels, name="spamfighter-audit")
    if audit_channel is None:
        audit_channel = await guild.create_text_channel(
            name="spamfighter-audit",
            reason="SpamFighter setup wizard",
            overwrites=overwrites,
        )

    enforcement_channel = discord.utils.get(guild.text_channels, name="spamfighter-enforcement")
    if enforcement_channel is None:
        enforcement_channel = await guild.create_text_channel(
            name="spamfighter-enforcement",
            reason="SpamFighter setup wizard",
            overwrites=overwrites,
        )

    await write_guild_channels(
        guild.id,
        audit_channel_id=audit_channel.id,
        enforcement_channel_id=enforcement_channel.id,
    )
    return audit_channel, enforcement_channel


def format_channel_scan_label(channel: object) -> str:
    name = getattr(channel, "name", "unknown")
    channel_id = getattr(channel, "id", 0)
    parent = getattr(channel, "parent", None)
    parent_name = getattr(parent, "name", None)
    if parent_name:
        return f"{parent_name}/{name} ({channel_id})"
    return f"{name} ({channel_id})"


async def resolve_bot_moderator_member(guild: discord.Guild) -> Optional[discord.Member]:
    me = guild.me or guild.get_member(bot.user.id if bot.user else 0)
    if me is not None:
        return me

    try:
        return await get_bot_member(guild)
    except Exception:
        return None


def resolve_escalation_action(
    guild: discord.Guild,
    member: Optional[discord.Member],
    violation_count: int,
    moderator: Optional[discord.Member],
) -> Optional[str]:
    settings = resolve_moderation_settings(guild.id)
    if not settings.enable_escalation:
        return None
    if member is None or moderator is None:
        return None
    if bot.user is not None and member.id == bot.user.id:
        return None
    if member.id == guild.owner_id:
        return None
    if member.top_role >= moderator.top_role:
        return None

    if violation_count >= settings.ban_threshold and moderator.guild_permissions.ban_members:
        return "ban"
    if violation_count >= settings.kick_threshold and moderator.guild_permissions.kick_members:
        return "kick"
    if violation_count >= settings.timeout_threshold and moderator.guild_permissions.moderate_members:
        return "timeout"
    if violation_count >= settings.warn_threshold:
        return "warn"
    return None


async def apply_escalation_action(
    guild: discord.Guild,
    member: discord.Member,
    violation_count: int,
) -> Optional[str]:
    moderator = await resolve_bot_moderator_member(guild)
    action = resolve_escalation_action(guild, member, violation_count, moderator)
    if action is None:
        return None

    settings = resolve_moderation_settings(guild.id)

    try:
        if action == "ban":
            await guild.ban(member, reason="Repeated spam violations", delete_message_seconds=0)
        elif action == "kick":
            await guild.kick(member, reason="Repeated spam violations")
        elif action == "timeout":
            until = utcnow() + timedelta(minutes=settings.timeout_minutes)
            await member.edit(
                timed_out_until=until,
                reason="Repeated spam violations",
            )
        elif action == "warn":
            await maybe_warn_member(member, guild, violation_count)
        else:
            return None
    except discord.Forbidden as exc:
        await audit_error(guild, "Moderation Escalation Forbidden", "apply_escalation_action", exc)
        return None
    except discord.HTTPException as exc:
        await audit_error(guild, "Moderation Escalation HTTP Error", "apply_escalation_action", exc)
        return None

    return action


def summarize_action_breakdown(breakdown: Dict[str, int], *, execute: bool) -> str:
    if not breakdown:
        return "None"

    ordered = ("warn", "timeout", "kick", "ban")
    prefix = "" if execute else "would "
    parts = [f"{prefix}{action}: {breakdown[action]}" for action in ordered if breakdown.get(action)]
    return ", ".join(parts) if parts else "None"


def current_retro_scan_backoff() -> float:
    if not RETRO_SCAN.running or RETRO_SCAN.last_rate_limit_at is None or RETRO_SCAN.adaptive_delay <= 0:
        return 0.0

    elapsed = (utcnow() - RETRO_SCAN.last_rate_limit_at).total_seconds()
    if elapsed >= 30:
        return 0.0

    decay = max(0.25, 1.0 - (elapsed / 30.0))
    return round(RETRO_SCAN.adaptive_delay * decay, 2)


async def sleep_for_retro_scan_backoff(base_delay: float = 0.0) -> None:
    delay = max(base_delay, current_retro_scan_backoff())
    if delay > 0:
        await asyncio.sleep(delay)


def record_retro_scan_match(message: discord.Message, reason: str) -> None:
    preview = build_message_match_preview(message)
    line = (
        f"{format_channel_scan_label(message.channel)} | {reason} | "
        f"{format_known_user(message.guild.id, message.author.id)} | {preview} | {message.jump_url}"
    )
    RETRO_SCAN.recent_match_lines.append(line)
    if len(RETRO_SCAN.recent_match_lines) > RETRO_SCAN_MATCH_PREVIEW_LIMIT:
        RETRO_SCAN.recent_match_lines.pop(0)


def build_retro_scan_targets(
    guild: discord.Guild,
    bot_member: discord.Member,
    *,
    selected_channel_ids: Optional[Sequence[int]] = None,
) -> Tuple[List[object], int]:
    targets: List[object] = []
    seen: Set[int] = set()
    skipped = 0

    if selected_channel_ids:
        selected_ids = trim_unique_int_list(selected_channel_ids, limit=50)

        for channel_id in selected_ids:
            channel = get_message_history_channel(guild, channel_id)
            if channel is None:
                skipped += 1
                continue
            perms = channel.permissions_for(bot_member)
            if not perms.view_channel or not perms.read_message_history:
                skipped += 1
                continue
            targets.append(channel)
            seen.add(channel.id)

        for thread in getattr(guild, "threads", []):
            if thread.id in seen or getattr(thread, "parent_id", None) not in selected_ids:
                continue
            perms = thread.permissions_for(bot_member)
            if not perms.view_channel or not perms.read_message_history:
                skipped += 1
                continue
            targets.append(thread)
            seen.add(thread.id)
    else:
        for channel in iter_message_history_channels(guild):
            perms = channel.permissions_for(bot_member)
            if not perms.view_channel or not perms.read_message_history:
                skipped += 1
                continue
            targets.append(channel)
            seen.add(channel.id)

        for thread in getattr(guild, "threads", []):
            if thread.id in seen:
                continue
            perms = thread.permissions_for(bot_member)
            if not perms.view_channel or not perms.read_message_history:
                skipped += 1
                continue
            targets.append(thread)
            seen.add(thread.id)

    targets.sort(key=lambda item: (getattr(item, "position", 0), getattr(item, "id", 0)))
    return targets, skipped


def build_retro_scan_embed(scan: RetroScanState) -> discord.Embed:
    if scan.running:
        title = "Retro Scan Running"
        color = discord.Color.blurple()
    elif scan.cancelled:
        title = "Retro Scan Cancelled"
        color = discord.Color.orange()
    elif scan.finished_at is not None:
        title = "Retro Scan Completed"
        color = discord.Color.green() if scan.execute else discord.Color.blurple()
    else:
        title = "Retro Scan Status"
        color = discord.Color.blurple()

    mode = "validate-clean" if scan.validation_mode else ("execute" if scan.execute else "preview")
    if scan.cancelled:
        description = "The retro scan was cancelled. Counts shown may be partial and no further retroactive moderation will be applied."
    elif scan.validation_mode:
        description = "Validation mode scans known-clean channels and treats any matches as potential false positives. No deletions or moderation actions are applied."
    elif not scan.execute:
        description = "Preview mode reports what would happen without deleting messages or moderating members."
    else:
        description = "Execute mode deletes matched messages when possible and applies retroactive moderation."
    embed = base_embed(title=title, color=color, description=description)
    embed.add_field(name="Mode", value=mode, inline=True)
    embed.add_field(name="Months", value=str(scan.months or 0), inline=True)
    embed.add_field(name="Deep Image Hashing", value=str(scan.deep_image_hash_scan), inline=True)
    embed.add_field(name="Guild", value=f"{scan.guild_name or 'Unknown'} (`{scan.guild_id or 0}`)", inline=False)
    embed.add_field(name="Scope", value=format_embed_field_value(scan.scope_label or "All accessible text channels"), inline=False)
    if scan.requested_by:
        embed.add_field(name="Requested By", value=f"<@{scan.requested_by}> (`{scan.requested_by}`)", inline=False)
    if scan.started_at:
        embed.add_field(name="Started", value=pretty_ts(scan.started_at, "F"), inline=True)
    if scan.finished_at:
        embed.add_field(name="Finished", value=pretty_ts(scan.finished_at, "F"), inline=True)
    elif scan.started_at:
        embed.add_field(name="Running For", value=pretty_ts(scan.started_at, "R"), inline=True)
    if scan.cutoff_at:
        embed.add_field(name="Cutoff", value=pretty_ts(scan.cutoff_at, "F"), inline=False)

    adaptive_delay_value = current_retro_scan_backoff() if scan.running else scan.adaptive_delay
    embed.add_field(
        name="Channel Progress",
        value=(
            f"scanned={scan.channels_scanned}/{scan.channels_total} | "
            f"skipped={scan.channels_skipped} | errors={scan.channel_errors}"
        ),
        inline=False,
    )
    embed.add_field(
        name="Message Summary",
        value=(
            f"scanned={scan.messages_scanned} | "
            f"{'potential false positives' if scan.validation_mode else 'matched'}={scan.matched_messages} | "
            f"{'affected users' if scan.validation_mode else 'users'}={scan.matched_users}"
        ),
        inline=False,
    )
    embed.add_field(name="Rate Limit Hits", value=str(scan.rate_limit_hits), inline=True)
    embed.add_field(name="Adaptive Delay", value=f"{adaptive_delay_value:.2f}s", inline=True)
    embed.add_field(name="Last Retry After", value=f"{scan.last_retry_after:.2f}s" if scan.last_retry_after else "None", inline=True)
    if scan.execute:
        embed.add_field(name="Deleted Messages", value=str(scan.deleted_messages), inline=True)
        embed.add_field(name="Delete Failures", value=str(scan.delete_failures), inline=True)
        embed.add_field(name="Actions Taken", value=str(scan.actions_taken), inline=True)
    embed.add_field(
        name="Action Summary",
        value=format_embed_field_value(
            summarize_action_breakdown(scan.action_breakdown, execute=scan.execute and not scan.cancelled)
        ),
        inline=False,
    )
    if scan.last_channel:
        embed.add_field(name="Last Channel", value=format_embed_field_value(scan.last_channel), inline=False)
    if scan.last_rate_limit_route:
        embed.add_field(
            name="Last Rate Limit Route",
            value=format_embed_field_value(scan.last_rate_limit_route),
            inline=False,
        )
    if scan.last_error:
        embed.add_field(name="Last Error", value=format_embed_field_value(scan.last_error), inline=False)
    if scan.summary_lines:
        top_users = "\n".join(scan.summary_lines)
        embed.add_field(
            name="Top Matched Users",
            value=format_embed_field_value(top_users, codeblock=True),
            inline=False,
        )
    if scan.recent_match_lines:
        recent_matches = "\n".join(scan.recent_match_lines)
        embed.add_field(
            name="Recent Matched Messages",
            value=format_embed_field_value(recent_matches),
            inline=False,
        )

    return embed


async def publish_retro_scan_summary(guild: Optional[discord.Guild], scan: RetroScanState) -> None:
    embed = build_retro_scan_embed(scan)
    await send_audit_embeds(guild, [embed])
    if scan.execute:
        await send_enforcement_embeds(guild, [embed])


async def start_retro_scan_request(
    *,
    target_guild: discord.Guild,
    requested_by: int,
    months: int,
    execute: bool,
    deep_image_hash_scan: bool,
    scope_label: str = "All accessible text channels",
    selected_channel_ids: Optional[Sequence[int]] = None,
    validation_mode: bool = False,
) -> RetroScanState:
    global RETRO_SCAN

    if not is_current_leader():
        raise RuntimeError("Retro scans can only run on the leader instance.")
    acquired_scan_lease = await try_acquire_distributed_lease(
        RETRO_SCAN_LEASE_KEY,
        owner_id=INSTANCE_ID,
        ttl_seconds=RETRO_SCAN_LEASE_SECONDS,
    )
    if not acquired_scan_lease:
        raise RuntimeError("A retro scan is already running on another SpamFighter instance.")

    RETRO_SCAN = RetroScanState(
        running=True,
        guild_id=target_guild.id,
        guild_name=target_guild.name,
        requested_by=requested_by,
        months=months,
        execute=execute,
        started_at=utcnow(),
        deep_image_hash_scan=deep_image_hash_scan,
        validation_mode=validation_mode,
        scope_label=scope_label,
        selected_channel_ids=trim_unique_int_list(selected_channel_ids or [], limit=10),
    )
    RETRO_SCAN.task = asyncio.create_task(
        run_retro_scan(),
        name=(
            f"spamfighter-retro-validate-{target_guild.id}"
            if validation_mode
            else f"spamfighter-retro-scan-{target_guild.id}"
        ),
    )
    await persist_retro_scan_state()
    return RETRO_SCAN


async def run_retro_scan() -> None:
    guild = bot.get_guild(RETRO_SCAN.guild_id or 0)
    if guild is None:
        RETRO_SCAN.running = False
        RETRO_SCAN.finished_at = utcnow()
        RETRO_SCAN.last_error = "The guild was not available when the retro scan started."
        RETRO_SCAN.task = None
        await persist_retro_scan_state()
        return

    bot_member = await resolve_bot_moderator_member(guild)
    if bot_member is None:
        RETRO_SCAN.running = False
        RETRO_SCAN.finished_at = utcnow()
        RETRO_SCAN.last_error = "Could not resolve the bot member for this guild."
        RETRO_SCAN.task = None
        await persist_retro_scan_state()
        await publish_retro_scan_summary(guild, RETRO_SCAN)
        return

    targets, skipped = build_retro_scan_targets(
        guild,
        bot_member,
        selected_channel_ids=RETRO_SCAN.selected_channel_ids,
    )
    RETRO_SCAN.channels_total = len(targets)
    RETRO_SCAN.channels_skipped = skipped
    RETRO_SCAN.cutoff_at = utcnow() - timedelta(days=30 * max(RETRO_SCAN.months, 1))

    user_match_counts: Dict[int, int] = defaultdict(int)
    member_cache: Dict[int, discord.Member] = {}

    try:
        for channel in targets:
            if RETRO_SCAN.cancelled:
                break

            RETRO_SCAN.last_channel = format_channel_scan_label(channel)
            channel_perms = channel.permissions_for(bot_member)
            can_delete = bool(getattr(channel_perms, "manage_messages", False))
            channel_message_count = 0

            try:
                async for message in channel.history(limit=None, after=RETRO_SCAN.cutoff_at):
                    if RETRO_SCAN.cancelled:
                        break

                    RETRO_SCAN.messages_scanned += 1
                    channel_message_count += 1
                    remember_user_identity(guild.id, message.author)

                    member = message.author if isinstance(message.author, discord.Member) else guild.get_member(message.author.id)
                    if member is not None:
                        member_cache[member.id] = member

                    if is_exempt_message(message):
                        if channel_message_count % 100 == 0:
                            await sleep_for_retro_scan_backoff()
                        continue

                    matched, reason, _ = await classify_message_for_moderation_async(
                        message,
                        allow_image_hashes=RETRO_SCAN.deep_image_hash_scan,
                        force_image_hashes=RETRO_SCAN.deep_image_hash_scan,
                    )
                    if not matched:
                        if channel_message_count % 100 == 0:
                            await sleep_for_retro_scan_backoff()
                        continue

                    RETRO_SCAN.matched_messages += 1
                    user_match_counts[message.author.id] += 1
                    record_retro_scan_match(message, reason)

                    if RETRO_SCAN.execute and can_delete:
                        try:
                            await message.delete()
                            RETRO_SCAN.deleted_messages += 1
                        except discord.NotFound:
                            RETRO_SCAN.delete_failures += 1
                        except discord.Forbidden:
                            RETRO_SCAN.delete_failures += 1
                        except discord.HTTPException:
                            RETRO_SCAN.delete_failures += 1
                        await sleep_for_retro_scan_backoff(RETRO_SCAN_DELETE_DELAY_SECONDS)
                    elif channel_message_count % 100 == 0:
                        await sleep_for_retro_scan_backoff()
            except discord.Forbidden as exc:
                RETRO_SCAN.channels_skipped += 1
                RETRO_SCAN.channel_errors += 1
                RETRO_SCAN.last_error = f"{format_channel_scan_label(channel)}: {type(exc).__name__}"
            except discord.HTTPException as exc:
                RETRO_SCAN.channel_errors += 1
                RETRO_SCAN.last_error = (
                    f"{format_channel_scan_label(channel)}: HTTP {getattr(exc, 'status', 'error')}"
                )

            RETRO_SCAN.channels_scanned += 1
            await persist_retro_scan_state()
            await try_acquire_distributed_lease(
                RETRO_SCAN_LEASE_KEY,
                owner_id=INSTANCE_ID,
                ttl_seconds=RETRO_SCAN_LEASE_SECONDS,
            )
            await sleep_for_retro_scan_backoff(RETRO_SCAN_CHANNEL_DELAY_SECONDS)

        RETRO_SCAN.matched_users = len(user_match_counts)

        breakdown: Dict[str, int] = defaultdict(int)
        summary_lines: List[str] = []
        moderator = await resolve_bot_moderator_member(guild)
        effective_execute = RETRO_SCAN.execute and not RETRO_SCAN.cancelled
        sorted_users = sorted(user_match_counts.items(), key=lambda item: (-item[1], item[0]))

        for user_id, matched_count in sorted_users:
            member = member_cache.get(user_id) or guild.get_member(user_id)
            current_count = await get_violation_count(guild.id, user_id)
            effective_count = current_count + matched_count
            action = resolve_escalation_action(guild, member, effective_count, moderator)

            if action:
                breakdown[action] = breakdown.get(action, 0) + 1

            if len(summary_lines) < 10:
                action_label = action or "no action"
                prefix = "" if effective_execute else "would "
                summary_lines.append(
                    f"{format_known_user(guild.id, user_id)}: {matched_count} match(es) -> {prefix}{action_label} at {effective_count}"
                )

            if not effective_execute:
                continue

            await set_violation_count(guild.id, user_id, effective_count)
            if member is None:
                continue

            applied_action = await apply_escalation_action(guild, member, effective_count)
            if applied_action is not None:
                RETRO_SCAN.actions_taken += 1

        RETRO_SCAN.action_breakdown = dict(breakdown)
        RETRO_SCAN.summary_lines = summary_lines
    except asyncio.CancelledError:
        RETRO_SCAN.cancelled = True
        if SHUTDOWN_REQUESTED:
            RETRO_SCAN.last_error = "Retro scan interrupted while the bot was shutting down."
        else:
            RETRO_SCAN.last_error = "Retro scan cancelled by an administrator."
    except Exception as exc:
        RETRO_SCAN.last_error = str(exc) or type(exc).__name__
        await audit_error(
            guild,
            "Retro Scan Failed",
            "run_retro_scan",
            exc,
            extra={
                "Guild": f"{guild.name} ({guild.id})",
                "Mode": "execute" if RETRO_SCAN.execute else "preview",
            },
        )
    finally:
        RETRO_SCAN.running = False
        RETRO_SCAN.finished_at = utcnow()
        RETRO_SCAN.task = None
        await persist_retro_scan_state()
        await release_distributed_lease(RETRO_SCAN_LEASE_KEY, owner_id=INSTANCE_ID)
        await publish_retro_scan_summary(guild, RETRO_SCAN)


def resolve_user_id_from_ref(guild_id: int, user_ref: str) -> Optional[int]:
    user_ref = user_ref.strip()
    mention_match = re.fullmatch(r"<@!?(\d{15,25})>", user_ref)
    if mention_match:
        return int(mention_match.group(1))

    if re.fullmatch(r"\d{15,25}", user_ref):
        return int(user_ref)

    lowered = user_ref.lower()
    for user_id, labels in LAST_KNOWN_USER_LABELS.get(guild_id, {}).items():
        if lowered in labels:
            return user_id

    return None


def is_control_operator(user_id: int) -> bool:
    return user_id in CONTROL_ADMIN_USER_IDS or user_id in CONTROL_SUPER_USER_IDS


def resolve_guild_id_from_ref(guild_ref: Optional[str]) -> Optional[int]:
    if guild_ref is None:
        return None

    guild_ref = guild_ref.strip()
    if not guild_ref:
        return None

    if re.fullmatch(r"\d{15,25}", guild_ref):
        return int(guild_ref)

    return None


def resolve_discord_message_ref(message_ref: Optional[str]) -> Optional[Tuple[int, int, int]]:
    if message_ref is None:
        return None

    cleaned = str(message_ref).strip().strip("<>")
    if not cleaned:
        return None

    match = re.search(
        r"https?://(?:canary\.|ptb\.)?discord(?:app)?\.com/channels/(\d{15,25})/(\d{15,25})/(\d{15,25})",
        cleaned,
        flags=re.IGNORECASE,
    )
    if match is None:
        return None
    return int(match.group(1)), int(match.group(2)), int(match.group(3))


def build_discord_message_url(guild_id: int, channel_id: int, message_id: int) -> str:
    if guild_id <= 0 or channel_id <= 0 or message_id <= 0:
        return ""
    return f"https://discord.com/channels/{guild_id}/{channel_id}/{message_id}"


# ============================================================
# Rule review workflow
# ============================================================

class RuleSuggestionGenerationError(RuntimeError):
    def __init__(self, message: str, *, usage: Optional[Dict[str, int]] = None):
        super().__init__(message)
        self.usage = dict(usage or {})


def user_can_review_rule_changes(interaction: discord.Interaction) -> bool:
    if is_control_operator(interaction.user.id):
        return True
    permissions = getattr(interaction.user, "guild_permissions", None)
    return bool(getattr(permissions, "administrator", False))


def validate_rule_deployment_approval(report: RuleReportState, actor_id: int) -> None:
    if (
        REQUIRE_SECOND_APPROVER_FOR_AI
        and report.suggestion is not None
        and bool(report.suggestion.usage)
        and report.last_generated_by is not None
        and report.last_generated_by == actor_id
    ):
        raise PermissionError(
            "A second approver is required for AI-generated rule drafts. Ask a different configured deployer to confirm deployment."
        )


def append_match_signal(signals: Dict[str, List[str]], key: str, value: Optional[str]) -> None:
    cleaned = str(value or "").strip()
    if not cleaned:
        return
    bucket = signals.setdefault(key, [])
    if cleaned not in bucket:
        bucket.append(cleaned)


def first_regex_hit(pattern: re.Pattern[str], normalized: str) -> Optional[str]:
    match = pattern.search(normalized)
    if match is None:
        return None
    return match.group(0).strip()


def known_artifact_hits(normalized_content: str, normalized_media: str) -> List[str]:
    hits: List[str] = []

    def add_hit(value: Optional[str]) -> None:
        cleaned = str(value or "").strip()
        if cleaned and cleaned not in hits:
            hits.append(cleaned)

    for match in KNOWN_SPAM_ARTIFACTS.finditer(normalized_content):
        add_hit(match.group(0))
    for match in KNOWN_SPAM_ARTIFACTS.finditer(normalized_media):
        add_hit(match.group(0))
    for value in MANAGED_KNOWN_SPAM_ARTIFACTS:
        if value and (value in normalized_content or value in normalized_media):
            add_hit(value)
    return hits


def build_rule_report_match_signals(report: RuleReportState) -> Dict[str, List[str]]:
    normalized = report.normalized_content or normalize_for_scan(report.message_content or "")
    normalized_media = normalize_for_scan(report.media_indicators or "")
    signals: Dict[str, List[str]] = {}
    blocklist_source_text = "\n".join(part for part in (report.message_content, report.media_indicators) if part)

    artifact_hits = known_artifact_hits(normalized, normalized_media)
    for hit in artifact_hits:
        append_match_signal(signals, "known_spam_artifact", hit)
    for digest in report.image_hashes:
        if digest in MANAGED_KNOWN_IMAGE_HASHES:
            append_match_signal(signals, "known_spam_image_hash", f"sha256:{digest}")

    ticket_word = first_regex_hit(TICKET_WORDS, normalized)
    ticket_artist = first_regex_hit(ARTIST_EVENT_WORDS, normalized)
    ticket_venue = first_regex_hit(VENUE_LOCATION_WORDS, normalized)
    ticket_context = first_regex_hit(GENERIC_TICKET_CONTEXT, normalized)
    ticket_contact = first_regex_hit(TICKET_CONTACT, normalized)
    anti_ticket = first_regex_hit(ANTI_TICKET_CONTEXT, normalized)
    if ticket_word:
        append_match_signal(signals, "ticket_words", ticket_word)
    if managed_hook_search("ticket_words", normalized):
        append_match_signal(signals, "ticket_words", "managed_hook")
    if ticket_artist:
        append_match_signal(signals, "ticket_context", ticket_artist)
    if ticket_venue:
        append_match_signal(signals, "ticket_context", ticket_venue)
    if ticket_context:
        append_match_signal(signals, "ticket_context", ticket_context)
    if managed_hook_search("ticket_context", normalized):
        append_match_signal(signals, "ticket_context", "managed_hook")
    if ticket_contact:
        append_match_signal(signals, "ticket_contact", ticket_contact)
    if managed_hook_search("ticket_contact", normalized):
        append_match_signal(signals, "ticket_contact", "managed_hook")
    if anti_ticket:
        append_match_signal(signals, "anti_ticket", anti_ticket)
    if managed_hook_search("anti_ticket", normalized):
        append_match_signal(signals, "anti_ticket", "managed_hook")

    giveaway_intent = first_regex_hit(GIVEAWAY_INTENT, normalized)
    giveaway_item = first_regex_hit(ITEM_WORDS, normalized)
    camera_gear = first_regex_hit(CAMERA_GEAR_TERMS, normalized)
    giveaway_contact = first_regex_hit(GIVEAWAY_CONTACT, normalized)
    anti_giveaway = first_regex_hit(ANTI_GIVEAWAY_CONTEXT, normalized)
    if giveaway_intent:
        append_match_signal(signals, "giveaway_intent", giveaway_intent)
    if managed_hook_search("giveaway_intent", normalized):
        append_match_signal(signals, "giveaway_intent", "managed_hook")
    if giveaway_item:
        append_match_signal(signals, "giveaway_item", giveaway_item)
    if camera_gear:
        append_match_signal(signals, "giveaway_item", camera_gear)
    if managed_hook_search("giveaway_item", normalized):
        append_match_signal(signals, "giveaway_item", "managed_hook")
    if giveaway_contact:
        append_match_signal(signals, "giveaway_contact", giveaway_contact)
    if managed_hook_search("giveaway_contact", normalized):
        append_match_signal(signals, "giveaway_contact", "managed_hook")
    if anti_giveaway:
        append_match_signal(signals, "anti_giveaway", anti_giveaway)
    if managed_hook_search("anti_giveaway", normalized):
        append_match_signal(signals, "anti_giveaway", "managed_hook")

    job_role = first_regex_hit(JOB_ROLE, normalized)
    job_remote = first_regex_hit(JOB_REMOTE, normalized)
    job_pay = first_regex_hit(JOB_PAY, normalized)
    job_tasks = first_regex_hit(JOB_TASKS, normalized)
    job_response = first_regex_hit(JOB_RESPONSE, normalized)
    if job_role:
        append_match_signal(signals, "job_role", job_role)
    if managed_hook_search("job_role", normalized):
        append_match_signal(signals, "job_role", "managed_hook")
    if job_remote:
        append_match_signal(signals, "job_remote", job_remote)
    if managed_hook_search("job_remote", normalized):
        append_match_signal(signals, "job_remote", "managed_hook")
    if job_pay:
        append_match_signal(signals, "job_pay", job_pay)
    if managed_hook_search("job_pay", normalized):
        append_match_signal(signals, "job_pay", "managed_hook")
    if job_tasks:
        append_match_signal(signals, "job_tasks", job_tasks)
    if managed_hook_search("job_tasks", normalized):
        append_match_signal(signals, "job_tasks", "managed_hook")
    if job_response:
        append_match_signal(signals, "job_response", job_response)
    if managed_hook_search("job_response", normalized):
        append_match_signal(signals, "job_response", "managed_hook")

    academic_intent = first_regex_hit(ACADEMIC_INTENT, normalized)
    academic_contact = first_regex_hit(ACADEMIC_CONTACT, normalized)
    if academic_intent:
        append_match_signal(signals, "academic_intent", academic_intent)
    if managed_hook_search("academic_intent", normalized):
        append_match_signal(signals, "academic_intent", "managed_hook")
    if academic_contact:
        append_match_signal(signals, "academic_contact", academic_contact)
    if managed_hook_search("academic_contact", normalized):
        append_match_signal(signals, "academic_contact", "managed_hook")

    custom_rule = match_managed_custom_rule(normalized)
    if custom_rule is not None:
        append_match_signal(signals, "custom_rule", custom_rule.rule_id)

    for key in DOMAIN_BLOCKLIST_KEYS:
        blocklist_match = match_text_against_domain_blocklists(blocklist_source_text, [key])
        if blocklist_match is not None:
            append_match_signal(signals, f"domain_blocklist_{key}", blocklist_match.blocked_host)

    return signals


def assess_rule_report_coverage(report: RuleReportState, matched_signals: Dict[str, List[str]]) -> str:
    if not report.current_matched:
        return "not_currently_matched"

    reason = report.current_reason
    if reason == "known_spam_artifact":
        if matched_signals.get("known_spam_artifact") or matched_signals.get("known_spam_image_hash"):
            return "robust_existing_match"
        return "partial_existing_match"

    if reason == "ticket_resale":
        if matched_signals.get("ticket_words") and matched_signals.get("ticket_context") and matched_signals.get("ticket_contact"):
            return "robust_existing_match"
        return "partial_existing_match"

    if reason == "giveaway_spam":
        if matched_signals.get("giveaway_intent") and matched_signals.get("giveaway_item") and matched_signals.get("giveaway_contact"):
            return "robust_existing_match"
        return "partial_existing_match"

    if reason == "job_spam":
        job_feature_groups = sum(
            1
            for key in ("job_remote", "job_pay", "job_tasks", "job_response")
            if matched_signals.get(key)
        )
        if matched_signals.get("job_role") and job_feature_groups >= 2 and (matched_signals.get("job_pay") or matched_signals.get("job_tasks")):
            return "robust_existing_match"
        return "partial_existing_match"

    if reason == "academic_spam":
        if matched_signals.get("academic_intent") and matched_signals.get("academic_contact"):
            return "robust_existing_match"
        return "partial_existing_match"

    for key, mapped_reason in DOMAIN_BLOCKLIST_REASON_MAP.items():
        if reason == mapped_reason:
            if matched_signals.get(f"domain_blocklist_{key}"):
                return "robust_existing_match"
            return "partial_existing_match"

    if matched_signals.get("custom_rule"):
        return "robust_existing_match"

    return "matched_but_unclear_coverage"


def build_rule_library_snapshot(reason: Optional[str] = None) -> Dict[str, object]:
    static_patterns = {
        "known_spam_artifacts": KNOWN_SPAM_ARTIFACTS.pattern,
        "ticket_words": TICKET_WORDS.pattern,
        "ticket_context": [
            ARTIST_EVENT_WORDS.pattern,
            VENUE_LOCATION_WORDS.pattern,
            GENERIC_TICKET_CONTEXT.pattern,
        ],
        "ticket_contact": TICKET_CONTACT.pattern,
        "anti_ticket": ANTI_TICKET_CONTEXT.pattern,
        "giveaway_intent": GIVEAWAY_INTENT.pattern,
        "giveaway_item": [ITEM_WORDS.pattern, CAMERA_GEAR_TERMS.pattern],
        "giveaway_contact": GIVEAWAY_CONTACT.pattern,
        "anti_giveaway": ANTI_GIVEAWAY_CONTEXT.pattern,
        "job_role": JOB_ROLE.pattern,
        "job_remote": JOB_REMOTE.pattern,
        "job_pay": JOB_PAY.pattern,
        "job_tasks": JOB_TASKS.pattern,
        "job_response": JOB_RESPONSE.pattern,
        "academic_intent": ACADEMIC_INTENT.pattern,
        "academic_contact": ACADEMIC_CONTACT.pattern,
    }
    managed_rules = {
        "artifacts": list(SPAM_RULES.artifact_values),
        "image_hashes": list(SPAM_RULES.image_hashes),
        "hooks": {name: list(values) for name, values in SPAM_RULES.hooks.items()},
        "custom_rules": [
            {
                "id": rule.rule_id,
                "reason": rule.reason,
                "pattern": rule.pattern,
                "enabled": rule.enabled,
                "description": rule.description,
            }
            for rule in SPAM_RULES.custom_rules
        ],
    }

    focus_map = {
        "ticket_resale": {
            "hooks": ["ticket_words", "ticket_context", "ticket_contact", "anti_ticket"],
            "static": ["ticket_words", "ticket_context", "ticket_contact", "anti_ticket"],
            "include_artifacts": False,
        },
        "giveaway_spam": {
            "hooks": ["giveaway_intent", "giveaway_item", "giveaway_contact", "anti_giveaway"],
            "static": ["giveaway_intent", "giveaway_item", "giveaway_contact", "anti_giveaway"],
            "include_artifacts": False,
        },
        "job_spam": {
            "hooks": ["job_role", "job_remote", "job_pay", "job_tasks", "job_response"],
            "static": ["job_role", "job_remote", "job_pay", "job_tasks", "job_response"],
            "include_artifacts": False,
        },
        "academic_spam": {
            "hooks": ["academic_intent", "academic_contact"],
            "static": ["academic_intent", "academic_contact"],
            "include_artifacts": False,
        },
        "known_spam_artifact": {
            "hooks": [],
            "static": ["known_spam_artifacts"],
            "include_artifacts": True,
        },
    }

    focus = focus_map.get(reason or "")
    if focus is not None:
        hook_names = focus["hooks"]
        static_keys = focus["static"]
        return {
            "scope": "focused_to_current_reason",
            "managed_hooks": hook_names,
            "managed_reasons": sorted(MANAGED_RULE_REASONS),
            "static_patterns": {key: static_patterns[key] for key in static_keys if key in static_patterns},
            "managed_rules": {
                "artifacts": managed_rules["artifacts"] if focus["include_artifacts"] else [],
                "image_hashes": managed_rules["image_hashes"] if focus["include_artifacts"] else [],
                "hooks": {name: managed_rules["hooks"].get(name, []) for name in hook_names},
                "custom_rules": [
                    rule
                    for rule in managed_rules["custom_rules"]
                    if rule.get("reason") == reason
                ],
            },
        }

    return {
        "scope": "full",
        "managed_hooks": list(MANAGED_RULE_HOOK_NAMES),
        "managed_reasons": sorted(MANAGED_RULE_REASONS),
        "static_patterns": static_patterns,
        "managed_rules": managed_rules,
    }


def trim_for_ai(text: str, *, limit: int) -> str:
    if len(text) <= limit:
        return text
    remaining = len(text) - limit
    return text[:limit].rstrip() + f"\n...[truncated {remaining} chars]"


def estimate_ai_input_tokens(text: str) -> int:
    return max(1, (len(text) + 3) // 4)


def normalize_pricing_model_name(model_name: str) -> str:
    cleaned = str(model_name or "").strip().lower()
    if cleaned == "gpt-5-mini":
        return "gpt-5.4-mini"
    return cleaned


def estimate_model_cost_usd(token_count: int, *, rate_per_million: float) -> float:
    return (max(0, int(token_count)) / 1_000_000.0) * rate_per_million


def format_usd_estimate(value: float) -> str:
    if value <= 0:
        return "$0.000000"
    if value < 0.01:
        return f"${value:.6f}"
    if value < 1.0:
        return f"${value:.4f}"
    return f"${value:.2f}"


def estimate_ai_request_costs(prompt_tokens: int, *, completion_tokens_cap: int = AI_REVIEW_MAX_COMPLETION_TOKENS) -> Dict[str, Dict[str, float]]:
    estimates: Dict[str, Dict[str, float]] = {}
    for model_name in ("gpt-5.4-mini", "gpt-5.4"):
        pricing = MODEL_PRICING_PER_MILLION.get(model_name, {})
        prompt_cost = estimate_model_cost_usd(prompt_tokens, rate_per_million=float(pricing.get("input", 0.0) or 0.0))
        completion_cost = estimate_model_cost_usd(completion_tokens_cap, rate_per_million=float(pricing.get("output", 0.0) or 0.0))
        estimates[model_name] = {
            "prompt_cost": prompt_cost,
            "completion_cap_cost": completion_cost,
            "max_total_cost": prompt_cost + completion_cost,
        }
    return estimates


def build_ai_cost_estimate_lines(prompt_tokens: int, *, completion_tokens_cap: int = AI_REVIEW_MAX_COMPLETION_TOKENS) -> List[str]:
    estimates = estimate_ai_request_costs(prompt_tokens, completion_tokens_cap=completion_tokens_cap)
    return [
        (
            f"{model_name}: input {format_usd_estimate(costs['prompt_cost'])} | "
            f"max output {format_usd_estimate(costs['completion_cap_cost'])} | "
            f"max total {format_usd_estimate(costs['max_total_cost'])}"
        )
        for model_name, costs in estimates.items()
    ]


def estimate_rule_review_prompt_tokens(report: RuleReportState) -> int:
    system_prompt = OPENAI_RULE_SYSTEM_PROMPT
    user_prompt = build_openai_rule_prompt(report)
    return estimate_ai_input_tokens(system_prompt) + estimate_ai_input_tokens(user_prompt)


def current_usage_bucket(kind: str, bucket_id: str) -> Dict[str, int]:
    store = AI_USAGE.daily if kind == "daily" else AI_USAGE.monthly
    return store.setdefault(
        bucket_id,
        {
            "requests": 0,
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "total_tokens": 0,
        },
    )


async def ensure_ai_budget_available(prompt_tokens_estimate: int) -> None:
    now = utcnow()
    day_key = now.strftime("%Y-%m-%d")
    month_key = now.strftime("%Y-%m")

    async with AI_USAGE_LOCK:
        day_bucket = current_usage_bucket("daily", day_key)
        month_bucket = current_usage_bucket("monthly", month_key)

        if day_bucket["requests"] >= AI_REVIEW_DAILY_REQUEST_LIMIT:
            raise RuntimeError("The daily AI proposal request limit has been reached.")
        if month_bucket["requests"] >= AI_REVIEW_MONTHLY_REQUEST_LIMIT:
            raise RuntimeError("The monthly AI proposal request limit has been reached.")
        if day_bucket["completion_tokens"] >= AI_REVIEW_DAILY_OUTPUT_TOKEN_LIMIT:
            raise RuntimeError("The daily AI output-token budget has been reached.")
        if month_bucket["completion_tokens"] >= AI_REVIEW_MONTHLY_OUTPUT_TOKEN_LIMIT:
            raise RuntimeError("The monthly AI output-token budget has been reached.")
        if day_bucket["prompt_tokens"] + prompt_tokens_estimate > AI_REVIEW_DAILY_INPUT_TOKEN_LIMIT:
            raise RuntimeError("Generating this proposal would exceed the daily AI input-token budget.")
        if month_bucket["prompt_tokens"] + prompt_tokens_estimate > AI_REVIEW_MONTHLY_INPUT_TOKEN_LIMIT:
            raise RuntimeError("Generating this proposal would exceed the monthly AI input-token budget.")


async def record_ai_usage(usage: Dict[str, int]) -> None:
    now = utcnow()
    day_key = now.strftime("%Y-%m-%d")
    month_key = now.strftime("%Y-%m")

    async with AI_USAGE_LOCK:
        for kind, bucket_id in (("daily", day_key), ("monthly", month_key)):
            bucket = current_usage_bucket(kind, bucket_id)
            bucket["requests"] += 1
            bucket["prompt_tokens"] += int(usage.get("prompt_tokens", 0) or 0)
            bucket["completion_tokens"] += int(usage.get("completion_tokens", 0) or 0)
            bucket["total_tokens"] += int(usage.get("total_tokens", 0) or 0)
        async with STATE_DB_LOCK:
            connection = await get_state_db_connection()
            await _upsert_ai_usage_bucket_row(connection, "daily", day_key, AI_USAGE.daily[day_key])
            await _upsert_ai_usage_bucket_row(connection, "monthly", month_key, AI_USAGE.monthly[month_key])
            await connection.commit()


async def log_ai_usage(report: RuleReportState, usage: Dict[str, int], actor_id: int) -> None:
    guild = bot.get_guild(report.source_guild_id)
    embed = base_embed(
        title="AI Draft Usage",
        color=discord.Color.blurple(),
        description="An administrator requested an AI rule draft for a reported spam message.",
    )
    embed.add_field(name="Report ID", value=report.report_id, inline=True)
    embed.add_field(name="Requested By", value=f"<@{actor_id}> (`{actor_id}`)", inline=True)
    embed.add_field(name="Prompt Tokens", value=str(usage.get("prompt_tokens", 0)), inline=True)
    embed.add_field(name="Completion Tokens", value=str(usage.get("completion_tokens", 0)), inline=True)
    embed.add_field(name="Total Tokens", value=str(usage.get("total_tokens", 0)), inline=True)
    embed.add_field(name="Source Guild", value=f"{report.source_guild_name} (`{report.source_guild_id}`)", inline=False)
    await send_audit_embeds(guild, [embed])


def build_openai_rule_prompt(report: RuleReportState) -> str:
    content = redact_sensitive_for_ai(report.message_content)
    media = redact_sensitive_for_ai(report.media_indicators)
    normalized_content = trim_for_ai(redact_sensitive_for_ai(report.normalized_content), limit=max(500, AI_REVIEW_MAX_INPUT_CHARS // 3))
    matched_signals = build_rule_report_match_signals(report)
    coverage_assessment = assess_rule_report_coverage(report, matched_signals)
    per_field_limit = max(500, AI_REVIEW_MAX_INPUT_CHARS // 3)
    content = trim_for_ai(content, limit=per_field_limit)
    media = trim_for_ai(media, limit=per_field_limit)

    payload = {
        "instruction": DEFAULT_RULE_SUGGESTION_PROMPT,
        "report": {
            "current_detector_match": report.current_matched,
            "current_detector_reason": report.current_reason,
            "precheck_matched": report.ai_precheck_matched,
            "precheck_reason": report.ai_precheck_reason,
            "coverage_assessment": coverage_assessment,
            "report_count": report.report_count,
            "message_content": content,
            "normalized_content": normalized_content,
            "media_indicators": media,
            "image_hashes": list(report.image_hashes),
            "matched_signals": matched_signals,
        },
        "output_contract": {
            "decision": "Use 'propose' when you have a safe rule suggestion. Use 'ignore' when no rule change should be made or existing coverage already appears robust.",
            "target_type": "One of: artifact, hook, custom_rule",
            "target_name": f"When target_type=hook, choose one of: {', '.join(MANAGED_RULE_HOOK_NAMES)}",
            "reason": f"One of: {', '.join(sorted(MANAGED_RULE_REASONS))}",
            "pattern": "Smallest safe regex pattern to add. Leave blank for pure artifact additions.",
            "exact_values": "Exact filenames or URLs to add for artifact-based spam. You may also return sha256:<64-hex> for exact known images.",
            "custom_rule_id": "Required when target_type=custom_rule. Provide a short, unique, lowercase snake_case identifier for the new rule (e.g. 'cam_invite', 'crypto_promo'). Must be a non-empty string.",
            "description": "Short human-readable explanation of the change",
            "rationale": "Why this is the safest change",
            "confidence": "low, medium, or high",
            "tests": [
                {"text": "positive example", "should_match": True, "note": "why"},
                {"text": "negative example", "should_match": False, "note": "why"},
            ],
            "enhancement_prompt": "A follow-up prompt for improving the current regex while keeping existing coverage and adding the new syntax.",
        },
        "constraints": [
            "Prefer artifact suggestions for photo-only spam or exact known media.",
            "Prefer extending an existing managed hook before proposing a custom_rule.",
            "A hook proposal must make the reported message satisfy all required signals for that managed detector family; otherwise use a custom_rule.",
            "For precheck_matched=false reports that do not fit an existing managed detector family, propose a custom_rule whose regex directly matches report.normalized_content.",
            "If current_detector_match is true and coverage_assessment is robust_existing_match, prefer ignore unless you can point to a concrete uncovered syntax or evasion.",
            "If precheck_matched is false, do not return ignore. You must return a concrete propose draft.",
            "Only propose a change when you can identify a specific uncovered span or failure mode in the reported message.",
            "Do not suggest a rule change just because the message was reported.",
            "Do not remove or weaken existing protections.",
            "Avoid broad patterns that would match normal student conversation.",
            "Return JSON only with no markdown fences.",
        ],
        "rule_library": build_rule_library_snapshot(report.current_reason or None),
    }
    prompt = json.dumps(payload, indent=2)
    if len(prompt) <= AI_REVIEW_MAX_INPUT_CHARS:
        return prompt

    payload["rule_library"] = {
        "scope": "minimal_fallback",
        "managed_hooks": list(MANAGED_RULE_HOOK_NAMES),
        "managed_reasons": sorted(MANAGED_RULE_REASONS),
    }
    prompt = json.dumps(payload, indent=2)
    if len(prompt) <= AI_REVIEW_MAX_INPUT_CHARS:
        return prompt

    payload["report"]["message_content"] = trim_for_ai(content, limit=max(300, per_field_limit // 2))
    payload["report"]["normalized_content"] = trim_for_ai(normalized_content, limit=max(300, per_field_limit // 2))
    payload["report"]["media_indicators"] = trim_for_ai(media, limit=max(300, per_field_limit // 2))
    return json.dumps(payload, indent=2)


def extract_first_json_object(text: str) -> str:
    text = text.strip()
    if text.startswith("{") and text.endswith("}"):
        return text

    depth = 0
    start = -1
    in_string = False
    escape = False
    for index, char in enumerate(text):
        if in_string:
            if escape:
                escape = False
            elif char == "\\":
                escape = True
            elif char == '"':
                in_string = False
            continue

        if char == '"':
            in_string = True
        elif char == "{":
            if depth == 0:
                start = index
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0 and start >= 0:
                return text[start:index + 1]

    raise ValueError("No JSON object was found in the model response.")


def normalize_rule_suggestion_payload(payload: dict, raw_payload: str, usage: Optional[Dict[str, int]] = None) -> RuleSuggestion:
    decision = str(payload.get("decision", "ignore")).strip().lower()
    target_type = str(payload.get("target_type", "")).strip().lower()
    target_name = str(payload.get("target_name", "")).strip().lower()
    reason = str(payload.get("reason", "")).strip()
    pattern = str(payload.get("pattern", "")).strip()
    custom_rule_id = str(payload.get("custom_rule_id", "")).strip()
    raw_exact_values = payload.get("exact_values", [])
    if isinstance(raw_exact_values, str):
        raw_exact_values = [raw_exact_values]

    exact_values = []
    for value in raw_exact_values:
        cleaned = str(value).strip()
        if not cleaned:
            continue
        if cleaned.lower().startswith("sha256:"):
            cleaned = "sha256:" + cleaned.split(":", 1)[1].strip().lower()
        exact_values.append(cleaned)

    if decision not in {"ignore", "propose"}:
        raise ValueError(f"Unsupported decision {decision!r} in model output")
    if decision == "ignore":
        return RuleSuggestion(
            decision=decision,
            description=str(payload.get("description", "")).strip(),
            rationale=str(payload.get("rationale", "")).strip(),
            confidence=str(payload.get("confidence", "")).strip(),
            enhancement_prompt=str(payload.get("enhancement_prompt", "")).strip(),
            raw_payload=raw_payload,
            usage=dict(usage or {}),
        )

    if reason not in MANAGED_RULE_REASONS:
        raise ValueError(f"Unsupported managed reason {reason!r} in model output")

    if target_type == "artifact":
        if not exact_values:
            raise ValueError("Artifact suggestions must include at least one exact value")
        for value in exact_values:
            if value.lower().startswith("sha256:"):
                digest = value.split(":", 1)[1].strip().lower()
                if not re.fullmatch(r"[a-f0-9]{64}", digest):
                    raise ValueError(f"Artifact sha256 value is invalid: {value!r}")
    elif target_type == "hook":
        if target_name not in MANAGED_RULE_HOOK_NAMES:
            raise ValueError(f"Unsupported managed hook {target_name!r} in model output")
        if not pattern:
            raise ValueError("Hook suggestions must include a regex pattern")
        compile_dynamic_regex(pattern, where=f"model_output.hook.{target_name}")
    elif target_type == "custom_rule":
        if not custom_rule_id:
            raise ValueError("Custom rule suggestions must include custom_rule_id")
        if not pattern:
            raise ValueError("Custom rule suggestions must include a regex pattern")
        compile_dynamic_regex(pattern, where=f"model_output.custom_rule.{custom_rule_id}")
    else:
        raise ValueError(f"Unsupported target_type {target_type!r} in model output")

    tests: List[Dict[str, object]] = []
    for item in payload.get("tests", []):
        if not isinstance(item, dict):
            continue
        tests.append(
            {
                "text": str(item.get("text", "")).strip(),
                "should_match": bool(item.get("should_match", False)),
                "note": str(item.get("note", "")).strip(),
            }
        )

    return RuleSuggestion(
        decision=decision,
        target_type=target_type,
        target_name=target_name,
        reason=reason,
        pattern=pattern,
        exact_values=exact_values,
        custom_rule_id=custom_rule_id,
        description=str(payload.get("description", "")).strip(),
        rationale=str(payload.get("rationale", "")).strip(),
        confidence=str(payload.get("confidence", "")).strip(),
        tests=tests,
        enhancement_prompt=str(payload.get("enhancement_prompt", "")).strip(),
        raw_payload=raw_payload,
        usage=dict(usage or {}),
    )


async def request_openai_rule_suggestion(
    report: RuleReportState,
    *,
    force_propose: bool = False,
    retry_feedback: str = "",
) -> RuleSuggestion:
    if not OPENAI_API_KEY:
        raise RuntimeError(
            "Missing OPENAI API key. Set SPAMFIGHTER_OPENAI_API_KEY or OPENAI_API_KEY, or mount a secret file via the matching *_FILE variable."
        )

    prompt_text = build_openai_rule_prompt(report)
    if force_propose:
        prompt_text += (
            "\n\nSTRICT REQUIREMENT:\n"
            "- decision must be \"propose\".\n"
            "- decision \"ignore\" is invalid for this request.\n"
            "- The proposal must make the full detector classify this report as matched.\n"
        )
    if retry_feedback.strip():
        prompt_text += (
            "\n\nRETRY FEEDBACK FROM VALIDATOR:\n"
            f"{retry_feedback.strip()}\n"
            "- Propose a different minimal safe rule that satisfies full-detector matching."
        )
    if len(prompt_text) > AI_REVIEW_MAX_INPUT_CHARS:
        raise RuntimeError("The AI proposal prompt is still too large after trimming. Shorten the report before sending it to OpenAI.")
    prompt_tokens_estimate = estimate_ai_input_tokens(OPENAI_RULE_SYSTEM_PROMPT) + estimate_ai_input_tokens(prompt_text)
    await ensure_ai_budget_available(prompt_tokens_estimate)

    payload = {
        "model": OPENAI_RULE_MODEL,
        "temperature": 0.1,
        "max_completion_tokens": AI_REVIEW_MAX_COMPLETION_TOKENS,
        "response_format": {
            "type": "json_schema",
            "json_schema": OPENAI_RULE_RESPONSE_SCHEMA,
        },
        "messages": [
            {
                "role": "system",
                "content": OPENAI_RULE_SYSTEM_PROMPT,
            },
            {
                "role": "user",
                "content": prompt_text,
            },
        ],
    }

    def _send_request() -> RuleSuggestion:
        request = urllib.request.Request(
            "https://api.openai.com/v1/chat/completions",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {OPENAI_API_KEY}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=OPENAI_API_TIMEOUT_SECONDS) as response:
            raw_response = json.loads(response.read().decode("utf-8"))

        usage_raw = raw_response.get("usage", {}) if isinstance(raw_response, dict) else {}
        usage = {
            "prompt_tokens": int(usage_raw.get("prompt_tokens", 0) or 0),
            "completion_tokens": int(usage_raw.get("completion_tokens", 0) or 0),
            "total_tokens": int(usage_raw.get("total_tokens", 0) or 0),
        }
        choices = raw_response.get("choices", [])
        if not choices:
            raise RuleSuggestionGenerationError("OpenAI returned no choices.", usage=usage)

        content = choices[0].get("message", {}).get("content", "")
        if isinstance(content, list):
            pieces: List[str] = []
            for item in content:
                if isinstance(item, dict):
                    text_value = item.get("text")
                    if text_value:
                        pieces.append(str(text_value))
            content = "\n".join(pieces)

        if not isinstance(content, str) or not content.strip():
            raise RuleSuggestionGenerationError("OpenAI returned an empty proposal.", usage=usage)

        try:
            normalized_payload = extract_first_json_object(content)
            parsed = json.loads(normalized_payload)
        except Exception as exc:
            raise RuleSuggestionGenerationError(
                f"OpenAI returned an invalid JSON proposal: {exc}",
                usage=usage,
            ) from exc
        return normalize_rule_suggestion_payload(parsed, normalized_payload, usage=usage)

    try:
        return await asyncio.to_thread(_send_request)
    except urllib.error.HTTPError as exc:
        details = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"OpenAI HTTP {exc.code}: {details}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"OpenAI connection error: {exc.reason}") from exc


def report_supports_hash_images(report: RuleReportState) -> bool:
    return bool(report.image_hashes or report.media_indicators.strip())


def reporter_summary(report: RuleReportState) -> str:
    if not report.reporter_ids:
        return "0"
    ordered = sorted(report.reporter_ids)
    preview = ", ".join(f"<@{user_id}>" for user_id in ordered[:5])
    if len(ordered) > 5:
        preview += f" +{len(ordered) - 5} more"
    return preview


# ============================================================
# Regression harness (TOML vs Postgres)
# ============================================================

REGRESSION_REASON_TO_ACTION: Dict[str, str] = {
    "known_spam_artifact": "delete_or_flag",
    "ticket_resale": "delete_or_flag",
    "giveaway_spam": "delete_or_flag",
    "job_spam": "delete_or_flag",
    "academic_spam": "delete_or_flag",
    "blocked_porn_domain": "delete_or_flag",
    "blocked_malicious_domain": "delete_or_flag",
    "blocked_custom_domain": "delete_or_flag",
}


def _parse_spam_rules_from_toml_path(path: Path) -> SpamRulesConfig:
    ensure_spam_rules_file(path)
    with path.open("rb") as handle:
        raw = tomllib.load(handle)
    raw = normalize_spam_rules_raw(raw)
    config = parse_spam_rules_from_raw(raw)
    validate_spam_rules(config)
    return config


def _load_spam_rules_from_postgres_for_regression(database_url: str) -> SpamRulesConfig:
    original = SPAM_RULES_DATABASE_URL
    try:
        globals()["SPAM_RULES_DATABASE_URL"] = database_url
        raw = _load_spam_rules_raw_from_postgres_sync()
        config = parse_spam_rules_from_raw(raw)
        validate_spam_rules(config)
        return config
    finally:
        globals()["SPAM_RULES_DATABASE_URL"] = original


def _stable_pattern_hash(pattern: str, flags: str = "") -> str:
    value = f"{flags}|{pattern}"
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def build_rules_snapshot(config: SpamRulesConfig, *, source: str) -> dict:
    entries: List[dict] = []
    for hook_name in sorted(config.hooks.keys()):
        for idx, pattern in enumerate(config.hooks.get(hook_name, tuple())):
            entries.append(
                {
                    "key": f"hook:{hook_name}:{idx}",
                    "scope": "global",
                    "target": hook_name,
                    "type": "hook",
                    "pattern": pattern,
                    "flags": "",
                    "enabled": True,
                    "action": "delete_or_flag",
                    "priority": idx,
                }
            )
    for idx, rule in enumerate(config.custom_rules):
        entries.append(
            {
                "key": f"custom:{rule.rule_id}",
                "scope": "global",
                "target": rule.rule_id,
                "type": "custom_rule",
                "pattern": rule.pattern,
                "flags": "",
                "enabled": bool(rule.enabled),
                "action": rule.reason or "delete_or_flag",
                "priority": idx,
            }
        )
    entries.sort(key=lambda item: item["key"])
    return {
        "source": source,
        "schema_version": int(config.schema_version),
        "artifact_values": sorted(config.artifact_values),
        "image_hashes": sorted(config.image_hashes),
        "entries": entries,
    }


def compare_rule_snapshots(toml_snapshot: dict, pg_snapshot: dict) -> List[str]:
    mismatches: List[str] = []
    if toml_snapshot["schema_version"] != pg_snapshot["schema_version"]:
        mismatches.append(
            f"schema_version changed: toml={toml_snapshot['schema_version']} postgres={pg_snapshot['schema_version']}"
        )
    if toml_snapshot["artifact_values"] != pg_snapshot["artifact_values"]:
        toml_set = set(toml_snapshot["artifact_values"])
        pg_set = set(pg_snapshot["artifact_values"])
        missing = sorted(toml_set - pg_set)
        extra = sorted(pg_set - toml_set)
        if missing:
            mismatches.append(f"artifact values missing in Postgres: {missing[:10]}")
        if extra:
            mismatches.append(f"artifact values extra in Postgres: {extra[:10]}")

    toml_entries = {item["key"]: item for item in toml_snapshot["entries"]}
    pg_entries = {item["key"]: item for item in pg_snapshot["entries"]}
    for key in sorted(set(toml_entries) - set(pg_entries)):
        mismatches.append(f"missing in Postgres: {key}")
    for key in sorted(set(pg_entries) - set(toml_entries)):
        mismatches.append(f"extra in Postgres: {key}")
    for key in sorted(set(toml_entries) & set(pg_entries)):
        left = toml_entries[key]
        right = pg_entries[key]
        for field in ("pattern", "flags", "enabled", "action", "priority", "scope", "type", "target"):
            if left.get(field) != right.get(field):
                mismatches.append(f"{key} {field} changed: toml={left.get(field)!r} postgres={right.get(field)!r}")
    return mismatches


def validate_regex_entries(snapshot: dict) -> List[dict]:
    results: List[dict] = []
    for item in snapshot.get("entries", []):
        pattern = str(item.get("pattern", ""))
        flags = str(item.get("flags", ""))
        success = True
        error = ""
        try:
            safe_regex.compile(pattern)
        except Exception as exc:
            success = False
            error = str(exc)
        results.append(
            {
                "key": item.get("key"),
                "pattern": pattern,
                "flags": flags,
                "pattern_hash": _stable_pattern_hash(pattern, flags),
                "compile_success": success,
                "compile_error": error,
            }
        )
    return results


def _evaluate_behavior_message(config: SpamRulesConfig, text: str, media_indicators: str = "", image_hashes: Optional[Sequence[str]] = None) -> dict:
    previous_rules = SPAM_RULES
    try:
        apply_spam_rules(config)
        matched, reason, normalized = classify_candidate_content_and_media(
            content=text,
            media_indicators=media_indicators,
            image_hashes=image_hashes or [],
        )
        return {
            "matched": bool(matched),
            "reason": reason or "",
            "action": REGRESSION_REASON_TO_ACTION.get(reason or "", "allow"),
            "normalized": normalized,
        }
    finally:
        apply_spam_rules(previous_rules)


def load_regression_corpus(path: Path) -> List[dict]:
    records: List[dict] = []
    with path.open("r", encoding="utf-8") as handle:
        for idx, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            payload = json.loads(stripped)
            records.append(
                {
                    "id": str(payload.get("id", f"line-{idx}")),
                    "text": str(payload.get("text", "")),
                    "media_indicators": str(payload.get("media_indicators", "")),
                    "image_hashes": [str(value).strip().lower() for value in payload.get("image_hashes", []) if str(value).strip()],
                }
            )
    return records


def run_behavior_regression(toml_config: SpamRulesConfig, pg_config: SpamRulesConfig, corpus: Sequence[dict]) -> Tuple[List[dict], List[dict]]:
    mismatches: List[dict] = []
    rows: List[dict] = []
    for item in corpus:
        toml_result = _evaluate_behavior_message(
            toml_config,
            item["text"],
            media_indicators=item.get("media_indicators", ""),
            image_hashes=item.get("image_hashes", []),
        )
        pg_result = _evaluate_behavior_message(
            pg_config,
            item["text"],
            media_indicators=item.get("media_indicators", ""),
            image_hashes=item.get("image_hashes", []),
        )
        row = {
            "id": item["id"],
            "toml": toml_result,
            "postgres": pg_result,
        }
        rows.append(row)
        if toml_result["matched"] != pg_result["matched"] or toml_result["reason"] != pg_result["reason"] or toml_result["action"] != pg_result["action"]:
            mismatches.append(row)
    return mismatches, rows


def run_regression_suite(
    *,
    toml_path: Path,
    database_url: str,
    corpus_path: Path,
    report_path: Optional[Path] = None,
    csv_path: Optional[Path] = None,
) -> dict:
    toml_config = _parse_spam_rules_from_toml_path(toml_path)
    pg_config = _load_spam_rules_from_postgres_for_regression(database_url)
    toml_snapshot = build_rules_snapshot(toml_config, source="toml")
    pg_snapshot = build_rules_snapshot(pg_config, source="postgres")
    equivalence_mismatches = compare_rule_snapshots(toml_snapshot, pg_snapshot)

    toml_regex_results = validate_regex_entries(toml_snapshot)
    pg_regex_results = validate_regex_entries(pg_snapshot)
    regex_failures = [
        {"source": "toml", **entry}
        for entry in toml_regex_results
        if not entry["compile_success"]
    ] + [
        {"source": "postgres", **entry}
        for entry in pg_regex_results
        if not entry["compile_success"]
    ]

    corpus = load_regression_corpus(corpus_path)
    behavior_mismatches, behavior_rows = run_behavior_regression(toml_config, pg_config, corpus)

    report = {
        "summary": {
            "equivalence_mismatch_count": len(equivalence_mismatches),
            "regex_failure_count": len(regex_failures),
            "behavior_mismatch_count": len(behavior_mismatches),
            "corpus_count": len(corpus),
        },
        "equivalence_mismatches": equivalence_mismatches,
        "regex_failures": regex_failures,
        "behavior_mismatches": behavior_mismatches,
    }
    if report_path is not None:
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    if csv_path is not None:
        csv_path.parent.mkdir(parents=True, exist_ok=True)
        with csv_path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(
                handle,
                fieldnames=[
                    "id",
                    "toml_matched",
                    "toml_reason",
                    "toml_action",
                    "postgres_matched",
                    "postgres_reason",
                    "postgres_action",
                    "mismatch",
                ],
            )
            writer.writeheader()
            for row in behavior_rows:
                mismatch = row in behavior_mismatches
                writer.writerow(
                    {
                        "id": row["id"],
                        "toml_matched": row["toml"]["matched"],
                        "toml_reason": row["toml"]["reason"],
                        "toml_action": row["toml"]["action"],
                        "postgres_matched": row["postgres"]["matched"],
                        "postgres_reason": row["postgres"]["reason"],
                        "postgres_action": row["postgres"]["action"],
                        "mismatch": mismatch,
                    }
                )
    return report


def print_regression_summary(report: dict) -> None:
    summary = report.get("summary", {})
    print("SpamFighter Regression Summary")
    print(f"- Equivalence mismatches: {summary.get('equivalence_mismatch_count', 0)}")
    print(f"- Regex compile failures: {summary.get('regex_failure_count', 0)}")
    print(f"- Behavior mismatches: {summary.get('behavior_mismatch_count', 0)}")
    print(f"- Corpus messages: {summary.get('corpus_count', 0)}")
    if report.get("equivalence_mismatches"):
        print("Equivalence mismatch examples:")
        for item in report["equivalence_mismatches"][:10]:
            print(f"  - {item}")
    if report.get("regex_failures"):
        print("Regex failure examples:")
        for item in report["regex_failures"][:10]:
            print(f"  - {item['source']} {item['key']}: {item['compile_error']}")
    if report.get("behavior_mismatches"):
        print("Behavior mismatch examples:")
        for item in report["behavior_mismatches"][:10]:
            print(
                f"  - {item['id']} toml=({item['toml']['matched']},{item['toml']['reason']}) "
                f"postgres=({item['postgres']['matched']},{item['postgres']['reason']})"
            )


def sync_postgres_from_toml_strict(
    *,
    toml_path: Path,
    database_url: str,
    corpus_path: Optional[Path] = None,
    backup_path: Optional[Path] = None,
) -> dict:
    if not database_url:
        raise RuntimeError("database_url is required for strict sync")

    original_url = SPAM_RULES_DATABASE_URL
    try:
        globals()["SPAM_RULES_DATABASE_URL"] = database_url
        current_pg_raw = _load_spam_rules_raw_from_postgres_sync()
        if backup_path is not None:
            backup_path.parent.mkdir(parents=True, exist_ok=True)
            backup_path.write_text(json.dumps(current_pg_raw, indent=2), encoding="utf-8")

        toml_config = _parse_spam_rules_from_toml_path(toml_path)
        toml_raw = normalize_spam_rules_raw(default_spam_rules_raw())
        with toml_path.open("rb") as handle:
            toml_raw = normalize_spam_rules_raw(tomllib.load(handle))
        validate_spam_rules(parse_spam_rules_from_raw(toml_raw))
        _save_spam_rules_raw_to_postgres_sync(toml_raw)

        verify_corpus = corpus_path if corpus_path is not None else Path("tests/fixtures/regression_messages.jsonl")
        if verify_corpus.exists():
            report = run_regression_suite(
                toml_path=toml_path,
                database_url=database_url,
                corpus_path=verify_corpus,
            )
        else:
            # Fallback parity check without behavior corpus
            pg_config = _load_spam_rules_from_postgres_for_regression(database_url)
            report = {
                "summary": {
                    "equivalence_mismatch_count": len(
                        compare_rule_snapshots(
                            build_rules_snapshot(toml_config, source="toml"),
                            build_rules_snapshot(pg_config, source="postgres"),
                        )
                    ),
                    "regex_failure_count": 0,
                    "behavior_mismatch_count": 0,
                    "corpus_count": 0,
                }
            }

        summary = report.get("summary", {})
        failed = any(
            int(summary.get(key, 0) or 0) > 0
            for key in ("equivalence_mismatch_count", "regex_failure_count", "behavior_mismatch_count")
        )
        if failed:
            raise RuntimeError(f"Strict sync verification failed: {summary}")
        return report
    finally:
        globals()["SPAM_RULES_DATABASE_URL"] = original_url


def suggestion_status_label(report: RuleReportState) -> str:
    if is_false_positive_report(report):
        if report.status == "approved":
            return "Actioned"
        if report.status == "denied":
            return "Closed"
        return "Reported"
    if report.status == "approved":
        return "Approved"
    if report.status == "denied":
        return "Rejected"
    if report.status == "proposal_ready":
        return "Draft Ready"
    if report.status == "proposal_error":
        return "Draft Error"
    if report.status == "analyzing":
        return "Drafting"
    return "Reported"


def suggestion_source_label(suggestion: RuleSuggestion) -> str:
    if suggestion.usage:
        return "AI"
    if suggestion.target_type == "artifact" and suggestion.exact_values and all(value.lower().startswith("sha256:") for value in suggestion.exact_values):
        return "Image Hashes"
    return "Manual"


def suggestion_target_label(suggestion: RuleSuggestion) -> str:
    target_value = suggestion.target_type or "none"
    if suggestion.target_name:
        target_value = f"{target_value}:{suggestion.target_name}"
    return target_value


def build_rule_draft_summary_text(report: RuleReportState, suggestion: RuleSuggestion) -> str:
    lines = [
        f"Source: {suggestion_source_label(suggestion)}",
        f"Decision: {suggestion.decision}",
        f"Reason: {suggestion.reason or 'none'}",
        f"Confidence: {suggestion.confidence or 'unknown'}",
        f"Target: {suggestion_target_label(suggestion)}",
    ]
    if report.proposal_generated_at is not None:
        lines.append(f"Generated: {pretty_ts(report.proposal_generated_at, 'F')}")
    return "\n".join(lines)


def build_rule_draft_notes_text(suggestion: RuleSuggestion) -> str:
    notes: List[str] = []
    if suggestion.description:
        notes.append(f"Description: {suggestion.description}")
    if suggestion.rationale:
        notes.append(f"Rationale: {suggestion.rationale}")
    return "\n".join(notes)


def build_rule_draft_usage_text(suggestion: RuleSuggestion) -> str:
    if not suggestion.usage:
        return ""
    return (
        f"prompt={suggestion.usage.get('prompt_tokens', 0)} | "
        f"completion={suggestion.usage.get('completion_tokens', 0)} | "
        f"total={suggestion.usage.get('total_tokens', 0)}"
    )


def build_rule_draft_estimated_cost_text(report: RuleReportState) -> str:
    estimated_prompt_tokens = estimate_rule_review_prompt_tokens(report)
    return (
        f"Prompt tokens: ~{estimated_prompt_tokens}\n"
        + "\n".join(build_ai_cost_estimate_lines(estimated_prompt_tokens))
    )


def build_rule_report_summary_embed(report: RuleReportState) -> discord.Embed:
    if report.status == "approved":
        color = discord.Color.green()
    elif report.status == "denied":
        color = discord.Color.orange()
    elif report.status == "proposal_error":
        color = discord.Color.red()
    elif report.status == "proposal_ready":
        color = discord.Color.blurple()
    else:
        color = discord.Color.gold()

    embed = base_embed(
        title="False Positive Review" if is_false_positive_report(report) else "Spam Rule Review",
        color=color,
        description=f"Status: **{suggestion_status_label(report)}**",
    )
    embed.add_field(
        name="Review Type",
        value="False Positive" if is_false_positive_report(report) else "Spam Pattern",
        inline=True,
    )
    embed.add_field(
        name="Report",
        value=(
            f"ID: `{report.report_id}`\n"
            f"Created: {pretty_ts(report.created_at, 'F')}\n"
            f"Last Reported: {pretty_ts(report.last_reported_at, 'R')}\n"
            f"Count: {report.report_count}"
        ),
        inline=False,
    )
    embed.add_field(name="Current Match", value=f"{report.current_matched} ({report.current_reason or 'none'})", inline=True)
    if report.ai_precheck_reason or report.status in {"analyzing", "proposal_ready", "proposal_error"}:
        embed.add_field(
            name="AI Precheck",
            value=f"{report.ai_precheck_matched} ({report.ai_precheck_reason or 'none'})",
            inline=True,
        )
    embed.add_field(name="Filed By" if is_false_positive_report(report) else "Reporters", value=reporter_summary(report), inline=False)
    if not is_false_positive_report(report):
        embed.add_field(name="Reporter Confidence", value=report.reporter_confidence.title(), inline=True)
        embed.add_field(
            name="Reporter History",
            value=format_embed_field_value(report.reporter_history_summary or "No reporter history available.", limit=500),
            inline=False,
        )
    embed.add_field(
        name="Source",
        value=(
            f"Guild: {report.source_guild_name} (`{report.source_guild_id}`)\n"
            f"Channel: {report.source_channel_label} (`{report.source_channel_id}`)\n"
            f"Author: {report.source_author_label} (`{report.source_author_id}`)"
        ),
        inline=False,
    )
    embed.add_field(name="Jump URL", value=report.source_jump_url or "Unavailable", inline=False)

    content_preview = report.message_content or "[no text]"
    embed.add_field(
        name="Message Preview",
        value=format_embed_field_value(content_preview, limit=500, codeblock=True),
        inline=False,
    )

    if report.media_indicators:
        embed.add_field(
            name="Media Preview",
            value=format_embed_field_value(report.media_indicators, limit=500),
            inline=False,
        )
    if report.image_hashes:
        embed.add_field(
            name="Image Hashes",
            value=format_embed_field_value("\n".join(report.image_hashes), limit=500, codeblock=True),
            inline=False,
        )
    if report.sample_jump_urls:
        embed.add_field(
            name="Sample Messages",
            value=format_embed_field_value("\n".join(report.sample_jump_urls[:5]), limit=500),
            inline=False,
        )
    if report.staff_notes:
        embed.add_field(
            name="Staff Notes",
            value=format_embed_field_value(report.staff_notes, limit=500, codeblock=True),
            inline=False,
        )

    if report.suggestion is not None:
        suggestion = report.suggestion
        embed.add_field(
            name="Rule Draft",
            value=format_embed_field_value(build_rule_draft_summary_text(report, suggestion), limit=500),
            inline=False,
        )
        detail_sections: List[str] = []
        if build_rule_draft_notes_text(suggestion):
            detail_sections.append("description and rationale")
        if suggestion.pattern:
            detail_sections.append("suggested regex")
        if suggestion.exact_values:
            detail_sections.append(f"{len(suggestion.exact_values)} exact value(s)")
        if suggestion.tests:
            detail_sections.append("suggested tests")
        if suggestion.enhancement_prompt:
            detail_sections.append("enhancement prompt")
        if detail_sections:
            embed.add_field(
                name="Draft Detail Embeds",
                value=(
                    "Full draft details are posted in dedicated embeds below this review.\n"
                    f"Included: {', '.join(detail_sections)}."
                ),
                inline=False,
            )
        usage_text = build_rule_draft_usage_text(suggestion)
        if usage_text:
            embed.add_field(name="AI Usage", value=usage_text, inline=False)
    elif report.suggestion_error:
        embed.add_field(
            name="Draft Error",
            value=format_embed_field_value(report.suggestion_error, limit=500, codeblock=True),
            inline=False,
        )
    elif is_false_positive_report(report):
        embed.add_field(
            name="Review Guidance",
            value=(
                "This is a staff-reported false positive. Review the linked context, then close the item "
                "or adjust the active rules manually if the match was incorrect."
            ),
            inline=False,
        )
    elif report.status == "reported":
        if report_supports_hash_images(report):
            proposal_hint = (
                "Not requested yet. Use `Create Exact Image Hash Rule` to prepare exact image-hash rules for approval, "
                "or use `Draft Rule with AI` to send this report to OpenAI."
            )
        else:
            proposal_hint = "Not requested yet. Use `Draft Rule with AI` to send this report to OpenAI."
        embed.add_field(
            name="Rule Draft",
            value=proposal_hint,
            inline=False,
        )

    if report.validation_status != "not_run":
        validation_value = report.validation_summary or report.validation_status.replace("_", " ").title()
        if report.validation_ran_at is not None:
            validation_value += f"\nLast run: {pretty_ts(report.validation_ran_at, 'F')}"
        if report.validation_bypassed_by is not None:
            validation_value += f"\nBypassed by <@{report.validation_bypassed_by}> (`{report.validation_bypassed_by}`)"
        embed.add_field(
            name="Validation Gate",
            value=format_embed_field_value(validation_value, limit=500),
            inline=False,
        )
        if report.validation_hit_lines:
            embed.add_field(
                name="Validation Hits",
                value=format_embed_field_value("\n".join(report.validation_hit_lines), limit=900),
                inline=False,
            )

    if not is_false_positive_report(report):
        ai_chars = len(build_openai_rule_prompt(report))
        embed.add_field(
            name="Estimated AI Cost",
            value=build_rule_draft_estimated_cost_text(report),
            inline=False,
        )
        if ai_chars >= AI_REVIEW_WARN_INPUT_CHARS:
            embed.add_field(
                name="AI Size Warning",
                value=f"The redacted AI prompt is about {ai_chars} characters. This report may cost more than usual.",
                inline=False,
            )

    if report.approved_by is not None:
        embed.add_field(name="Reviewed By", value=f"Approved by <@{report.approved_by}> (`{report.approved_by}`)", inline=False)
    elif report.denied_by is not None:
        label = "Closed by" if is_false_positive_report(report) else "Rejected by"
        embed.add_field(name="Reviewed By", value=f"{label} <@{report.denied_by}> (`{report.denied_by}`)", inline=False)

    return embed


def build_rule_report_detail_embeds(report: RuleReportState) -> List[discord.Embed]:
    embeds: List[discord.Embed] = []
    original_text, _ = limit_text(report.message_content or "[no text]")
    normalized_text, _ = limit_text(report.normalized_content or "[empty]")
    media_text, _ = limit_text(report.media_indicators or "[no media]")

    embeds.extend(build_text_embeds("Reported Message", original_text, discord.Color.red()))
    embeds.extend(build_text_embeds("Normalized Message", normalized_text, discord.Color.blurple()))
    if report.media_indicators:
        embeds.extend(build_text_embeds("Reported Media", media_text, discord.Color.gold()))
    if report.image_hashes:
        embeds.extend(build_text_embeds("Image Hashes", "\n".join(report.image_hashes), discord.Color.green()))
    if report.suggestion is not None:
        suggestion = report.suggestion
        draft_embed = base_embed(
            title="Rule Draft Details",
            color=discord.Color.blurple() if suggestion.usage else discord.Color.green(),
            description="Expanded rule-draft details for this review.",
        )
        draft_embed.add_field(
            name="Rule Draft",
            value=format_embed_field_value(build_rule_draft_summary_text(report, suggestion), limit=1000),
            inline=False,
        )
        notes_text = build_rule_draft_notes_text(suggestion)
        if notes_text:
            draft_embed.add_field(
                name="Proposal Notes",
                value=format_embed_field_value(notes_text, limit=1000),
                inline=False,
            )
        usage_text = build_rule_draft_usage_text(suggestion)
        if usage_text:
            draft_embed.add_field(name="AI Usage", value=usage_text, inline=False)
        draft_embed.add_field(
            name="Estimated AI Cost",
            value=build_rule_draft_estimated_cost_text(report),
            inline=False,
        )
        embeds.append(draft_embed)
        if suggestion.pattern:
            embeds.extend(build_text_embeds("Suggested Regex", suggestion.pattern, discord.Color.blurple()))
        if suggestion.exact_values:
            embeds.extend(build_text_embeds("Exact Values", "\n".join(suggestion.exact_values), discord.Color.green()))
        if suggestion.tests:
            embeds.extend(build_text_embeds("Suggested Tests", serialize_rule_tests(suggestion.tests), discord.Color.gold()))
        if suggestion.enhancement_prompt:
            embeds.extend(build_text_embeds("Enhancement Prompt", suggestion.enhancement_prompt, discord.Color.blurple()))
    elif report.suggestion_error:
        embeds.extend(build_text_embeds("Draft Error", report.suggestion_error, discord.Color.red()))
    return embeds


async def sync_rule_report_detail_messages(channel: discord.abc.Messageable, report: RuleReportState) -> None:
    detail_embeds = build_rule_report_detail_embeds(report)
    if not detail_embeds:
        return

    fetch_message = getattr(channel, "fetch_message", None)
    batches = batch_embeds(detail_embeds)
    existing_ids = list(report.detail_message_ids)
    new_ids: List[int] = []

    for index, batch in enumerate(batches):
        detail_message = None
        if index < len(existing_ids) and fetch_message is not None:
            try:
                detail_message = await fetch_message(existing_ids[index])
            except (discord.NotFound, discord.Forbidden, discord.HTTPException):
                detail_message = None

        if detail_message is not None:
            try:
                await detail_message.edit(
                    embeds=batch,
                    allowed_mentions=discord.AllowedMentions.none(),
                )
                new_ids.append(detail_message.id)
                continue
            except discord.HTTPException:
                detail_message = None

        sent_message = await channel.send(
            embeds=batch,
            allowed_mentions=discord.AllowedMentions.none(),
        )
        new_ids.append(sent_message.id)

    if fetch_message is not None:
        for extra_id in existing_ids[len(batches):]:
            try:
                extra_message = await fetch_message(extra_id)
            except (discord.NotFound, discord.Forbidden, discord.HTTPException):
                continue
            try:
                await extra_message.delete()
            except (discord.NotFound, discord.Forbidden, discord.HTTPException):
                continue

    if new_ids != report.detail_message_ids:
        report.detail_message_ids = new_ids
        await persist_rule_report_state(report)


async def fetch_rule_report_source_message(report: RuleReportState) -> Optional[discord.Message]:
    if not report.source_channel_id or not report.source_message_id:
        return None

    channel = await fetch_messageable_channel(report.source_channel_id)
    fetch_message = getattr(channel, "fetch_message", None)
    if channel is None or fetch_message is None:
        return None

    try:
        message = await fetch_message(report.source_message_id)
    except (discord.NotFound, discord.Forbidden, discord.HTTPException):
        return None

    return message


async def refresh_rule_report_image_hashes(report: RuleReportState) -> List[str]:
    hashes = trim_unique_list(report.image_hashes, limit=8)
    if hashes:
        return hashes

    message = await fetch_rule_report_source_message(report)
    if message is None:
        return hashes

    hashes = await compute_message_image_hashes(message)
    if hashes:
        report.image_hashes = trim_unique_list([*hashes, *report.image_hashes], limit=8)
    if not report.media_indicators:
        report.media_indicators = render_message_media_indicators(message)
    if not report.message_content and message.content:
        report.message_content = message.content
    if not report.normalized_content:
        report.normalized_content = normalize_for_scan(message.content or report.media_indicators or "")
    return trim_unique_list(report.image_hashes, limit=8)


def suggestion_requires_image_hash_validation(suggestion: Optional[RuleSuggestion]) -> bool:
    if suggestion is None or suggestion.decision != "propose" or suggestion.target_type != "artifact":
        return False
    return any(str(value).strip().lower().startswith("sha256:") for value in suggestion.exact_values)


def build_validation_hit_line(message: discord.Message, reason: str) -> str:
    preview = build_message_match_preview(message)
    jump_url = getattr(message, "jump_url", "")
    if jump_url:
        return f"{format_channel_scan_label(message.channel)} | {reason} | {jump_url} | {preview}"
    return f"{format_channel_scan_label(message.channel)} | {reason} | {preview}"


async def run_rule_validation_gate(report: RuleReportState) -> Tuple[bool, str, List[str]]:
    if report.suggestion is None or report.suggestion.decision != "propose":
        report.validation_status = "blocked"
        report.validation_summary = "There is no deployable rule draft to validate."
        report.validation_hit_lines = []
        report.validation_ran_at = utcnow()
        report.validation_bypassed_by = None
        return False, "There is no deployable rule draft to validate.", []

    validation_guild_id = get_effective_validation_guild_id(report.source_guild_id)
    validation_scope = describe_validation_scope(report.source_guild_id)
    guild = bot.get_guild(validation_guild_id)
    if guild is None:
        report.validation_status = "blocked"
        report.validation_summary = f"The {validation_scope} is not available to validate right now."
        report.validation_hit_lines = []
        report.validation_ran_at = utcnow()
        report.validation_bypassed_by = None
        return False, report.validation_summary, []

    months, channel_ids = await get_validation_channel_config(validation_guild_id)
    if not channel_ids:
        command_hint = (
            "Ask an admin to run `/spamfighter reviews set-validation-channels` in the validation master guild first."
            if REPORT_VALIDATION_MASTER_GUILD_ID
            else "Ask an admin to run `/spamfighter reviews set-validation-channels` first."
        )
        report.validation_status = "blocked"
        report.validation_summary = f"No validation channels are configured for the {validation_scope}. {command_hint}"
        report.validation_hit_lines = []
        report.validation_ran_at = utcnow()
        report.validation_bypassed_by = None
        return False, report.validation_summary, []

    channels: List[MessageHistoryChannel] = []
    for channel_id in channel_ids:
        channel = get_message_history_channel(guild, channel_id)
        if channel is not None:
            channels.append(channel)

    if not channels:
        report.validation_status = "blocked"
        report.validation_summary = f"None of the configured validation channels were available in the {validation_scope}."
        report.validation_hit_lines = []
        report.validation_ran_at = utcnow()
        report.validation_bypassed_by = None
        return False, report.validation_summary, []

    cutoff = utcnow() - timedelta(days=30 * months)
    scanned_messages = 0
    baseline_matches = 0
    hit_lines: List[str] = []
    needs_image_hashes = suggestion_requires_image_hash_validation(report.suggestion)
    compiled_suggestion = compile_suggestion_matchers(report.suggestion)

    for channel in channels:
        try:
            async for message in channel.history(limit=None, after=cutoff, oldest_first=False):
                if is_exempt_message(message):
                    continue
                scanned_messages += 1
                baseline_match, _, _ = await classify_message_for_moderation_async(
                    message,
                    allow_image_hashes=True,
                    force_image_hashes=True,
                )
                if baseline_match:
                    baseline_matches += 1
                    continue
                image_hashes = await compute_message_image_hashes(message) if needs_image_hashes else []
                candidate_match, candidate_reason, _ = classify_candidate_content_and_media(
                    content=message.content or "",
                    media_indicators=render_message_media_indicators(message),
                    image_hashes=image_hashes,
                    suggestion=report.suggestion,
                    compiled_suggestion=compiled_suggestion,
                )
                if candidate_match:
                    hit_lines.append(build_validation_hit_line(message, candidate_reason or report.suggestion.reason or "match"))
                    if len(hit_lines) >= 5:
                        break
            if len(hit_lines) >= 5:
                break
        except discord.Forbidden:
            continue
        except discord.HTTPException:
            continue

    scanned_channel_ids = [channel.id for channel in channels]
    report.validation_ran_at = utcnow()
    report.validation_months = months
    report.validation_channel_ids = scanned_channel_ids
    report.validation_bypassed_by = None

    if hit_lines:
        report.validation_status = "failed"
        report.validation_hit_lines = hit_lines
        report.validation_summary = (
            f"Candidate rule produced {len(hit_lines)} new hit(s) in configured clean channels in {describe_guild_for_logs(validation_guild_id)} over the last {months} month(s). "
            "Review the links below. If one of these is real spam that slipped through, use `Bypass Validation` before approving."
        )
        return False, report.validation_summary, hit_lines

    report.validation_status = "passed"
    report.validation_hit_lines = []
    report.validation_summary = (
        f"Validation passed across {len(channels)} configured clean channel(s) in {describe_guild_for_logs(validation_guild_id)} over the last {months} month(s). "
        f"Baseline existing matches skipped: {baseline_matches}. Messages scanned: {scanned_messages}."
    )
    return True, report.validation_summary, []


def build_image_hash_rule_suggestion(report: RuleReportState, digests: Sequence[str]) -> RuleSuggestion:
    exact_values = [f"sha256:{digest}" for digest in digests]
    payload = {
        "decision": "propose",
        "target_type": "artifact",
        "reason": "known_spam_artifact",
        "exact_values": exact_values,
        "description": f"Add {len(exact_values)} exact image hash value(s) from the reported spam media.",
        "rationale": "Exact SHA-256 image hashes only match identical files, making this a low-risk way to catch repeated spam images without broadening text rules.",
        "confidence": "high",
        "tests": [
            {
                "text": value,
                "should_match": True,
                "note": "Exact known spam image hash from the reported message.",
            }
            for value in exact_values[:4]
        ],
    }
    return RuleSuggestion(
        decision="propose",
        target_type="artifact",
        reason="known_spam_artifact",
        exact_values=exact_values,
        description=str(payload["description"]),
        rationale=str(payload["rationale"]),
        confidence="high",
        tests=list(payload["tests"]),
        raw_payload=json.dumps(payload, indent=2),
    )


def build_rule_review_view(report: RuleReportState) -> Optional[discord.ui.View]:
    if report.status in {"approved", "denied"}:
        return None
    return RuleReviewView(report.report_id)


async def refresh_rule_review_message(report: RuleReportState) -> None:
    if report.review_channel_id is None or report.review_message_id is None:
        return

    channel = await fetch_messageable_channel(report.review_channel_id)
    fetch_message = getattr(channel, "fetch_message", None)
    if channel is None or fetch_message is None:
        return

    try:
        review_message = await fetch_message(report.review_message_id)
    except discord.NotFound:
        return
    except discord.Forbidden:
        return
    except discord.HTTPException:
        return

    try:
        await review_message.edit(
            embed=build_rule_report_summary_embed(report),
            view=build_rule_review_view(report),
            allowed_mentions=discord.AllowedMentions.none(),
        )
    except discord.HTTPException:
        pass


def serialize_rule_tests(tests: Sequence[Dict[str, object]]) -> str:
    lines: List[str] = []
    for item in tests[:8]:
        text = str(item.get("text", "")).strip() or "[empty]"
        should_match = bool(item.get("should_match", False))
        note = str(item.get("note", "")).strip()
        label = "match" if should_match else "no-match"
        line = f"[{label}] {text}"
        if note:
            line += f" | {note}"
        lines.append(line)
    return "\n".join(lines) or "None"


async def log_rule_review_action(
    report: RuleReportState,
    *,
    action: str,
    actor_id: int,
    details: str,
) -> None:
    guild = bot.get_guild(report.source_guild_id)
    is_false_positive = is_false_positive_report(report)
    action_title = "Closed" if is_false_positive and action == "denied" else action.title()
    embed = base_embed(
        title=f"{'False Positive Review' if is_false_positive else 'Spam Rule'} {action_title}",
        color=(
            discord.Color.green()
            if action == "approved"
            else discord.Color.blurple()
            if action == "generated"
            else discord.Color.orange()
        ),
        description=details,
    )
    embed.add_field(name="Report ID", value=report.report_id, inline=True)
    embed.add_field(name="Actor", value=f"<@{actor_id}> (`{actor_id}`)", inline=True)
    embed.add_field(name="Review Type", value="False Positive" if is_false_positive else "Spam Pattern", inline=True)
    embed.add_field(name="Source Guild", value=f"{report.source_guild_name} (`{report.source_guild_id}`)", inline=False)
    embed.add_field(name="Jump URL", value=report.source_jump_url or "Unavailable", inline=False)
    if report.suggestion is not None:
        embed.add_field(name="Reason", value=report.suggestion.reason or "none", inline=True)
        target_value = report.suggestion.target_type or "none"
        if report.suggestion.target_name:
            target_value = f"{target_value}:{report.suggestion.target_name}"
        embed.add_field(name="Target", value=target_value, inline=True)
        if report.suggestion.pattern:
            embed.add_field(
                name="Suggested Regex",
                value=format_embed_field_value(report.suggestion.pattern, limit=500, codeblock=True),
                inline=False,
            )
        if report.suggestion.exact_values:
            embed.add_field(
                name="Exact Values",
                value=format_embed_field_value("\n".join(report.suggestion.exact_values), limit=500),
                inline=False,
            )
    if report.validation_status and report.validation_status != "not_run":
        embed.add_field(name="Validation", value=report.validation_status.replace("_", " ").title(), inline=True)
    await send_audit_embeds(guild, [embed])


def suggestion_to_mutation_summary(suggestion: RuleSuggestion) -> str:
    if suggestion.target_type == "artifact":
        return f"artifact values={len(suggestion.exact_values)}"
    if suggestion.target_type == "hook":
        return f"hook {suggestion.target_name}"
    if suggestion.target_type == "custom_rule":
        return f"custom_rule {suggestion.custom_rule_id}"
    return "no-op"


async def apply_suggestion_to_spam_rules(report: RuleReportState, approver_id: int) -> str:
    if report.suggestion is None:
        raise ValueError("There is no rule suggestion to approve.")
    if report.suggestion.decision != "propose":
        raise ValueError("This report does not contain an approvable rule proposal.")
    if not is_current_leader():
        raise RuntimeError("Managed rule deployment is only allowed on the leader instance.")

    suggestion = report.suggestion

    def mutator(raw: dict) -> None:
        meta = raw.setdefault("meta", {})
        meta["schema_version"] = int(meta.get("schema_version", 1) or 1)
        hooks = raw.setdefault("hooks", {})
        for hook_name in MANAGED_RULE_HOOK_NAMES:
            hooks.setdefault(hook_name, [])
        artifacts = raw.setdefault("artifacts", {})
        artifacts.setdefault("values", [])
        image_hashes = raw.setdefault("image_hashes", {})
        image_hashes.setdefault("sha256", [])
        custom_rules = raw.setdefault("custom_rules", [])

        if suggestion.target_type == "artifact":
            existing = {str(value).strip() for value in artifacts.get("values", [])}
            existing_hashes = {str(value).strip().lower() for value in image_hashes.get("sha256", [])}
            for value in suggestion.exact_values:
                if value.lower().startswith("sha256:"):
                    digest = value.split(":", 1)[1].strip().lower()
                    if re.fullmatch(r"[a-f0-9]{64}", digest) and digest not in existing_hashes:
                        image_hashes["sha256"].append(digest)
                        existing_hashes.add(digest)
                    continue
                if value not in existing:
                    artifacts["values"].append(value)
                    existing.add(value)
            return

        if suggestion.target_type == "hook":
            target = hooks.setdefault(suggestion.target_name, [])
            if suggestion.pattern not in target:
                target.append(suggestion.pattern)
            return

        if suggestion.target_type == "custom_rule":
            existing_ids = {str(item.get("id", "")).strip() for item in custom_rules if isinstance(item, dict)}
            rule_id = suggestion.custom_rule_id
            if rule_id in existing_ids:
                return
            custom_rules.append(
                {
                    "id": rule_id,
                    "enabled": True,
                    "reason": suggestion.reason,
                    "pattern": suggestion.pattern,
                    "description": suggestion.description,
                    "source": "openai-approved",
                    "created_at": utcnow().isoformat(),
                    "approved_by": str(approver_id),
                    "report_id": report.report_id,
                }
            )

    await mutate_spam_rules(mutator)
    return suggestion_to_mutation_summary(suggestion)


async def finalize_rule_approval(report: RuleReportState, approver_id: int) -> str:
    validate_rule_deployment_approval(report, approver_id)
    summary = await apply_suggestion_to_spam_rules(report, approver_id)
    report.status = "approved"
    report.approved_by = approver_id
    update_rule_report_cluster_map(report)
    for reporter_id in sorted(report.reporter_ids):
        await record_reporter_event(report.source_guild_id, reporter_id, report.report_id, "approved")
    await refresh_rule_reporter_snapshot(report)
    await persist_rule_report_state(report)
    await refresh_rule_review_message(report)
    await log_rule_review_action(
        report,
        action="approved",
        actor_id=approver_id,
        details=f"Approved rule proposal and reloaded spam rules ({summary}).",
    )
    return summary


async def finalize_rule_denial(report: RuleReportState, denier_id: int) -> None:
    report.status = "denied"
    report.denied_by = denier_id
    update_rule_report_cluster_map(report)
    if not is_false_positive_report(report):
        penalize = not report.current_matched and report.report_count <= 1
        for reporter_id in sorted(report.reporter_ids):
            await record_reporter_event(
                report.source_guild_id,
                reporter_id,
                report.report_id,
                "denied",
                counts_for_cooldown=penalize,
            )
    await refresh_rule_reporter_snapshot(report)
    await persist_rule_report_state(report)
    await refresh_rule_review_message(report)
    await log_rule_review_action(
        report,
        action="denied",
        actor_id=denier_id,
        details=(
            "Closed the false-positive review."
            if is_false_positive_report(report)
            else "Rejected the pending rule draft."
        ),
    )


class RuleDeploymentConfirmView(discord.ui.View):
    def __init__(self, report_id: str, actor_id: int):
        super().__init__(timeout=300)
        self.report_id = report_id
        self.actor_id = actor_id

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if interaction.user.id != self.actor_id:
            await respond_ephemeral(interaction, content="Only the administrator who opened this confirmation can deploy the rule.")
            return False
        report = RULE_REPORTS.get(self.report_id)
        if report is None:
            await respond_ephemeral(interaction, content="That report is no longer available.")
            return False
        if not user_can_deploy_rule_changes_for_report(report, user_id=interaction.user.id):
            await respond_ephemeral(
                interaction,
                content="Only configured SpamFighter deployers can publish global rule changes. Ask a control operator or deploy-role member to continue.",
            )
            return False
        return True

    @discord.ui.button(label="Confirm Approve and Deploy", style=discord.ButtonStyle.success, custom_id="spamfighter:rule-review:confirm-approve")
    async def confirm(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        report = RULE_REPORTS.get(self.report_id)
        if report is None:
            await respond_ephemeral(interaction, content="That report is no longer available.")
            return
        if report.status in {"approved", "denied"}:
            await respond_ephemeral(interaction, content="That review is already closed.")
            return
        if report.suggestion is None or report.suggestion.decision != "propose":
            await respond_ephemeral(interaction, content="There is no deployable rule draft on this review.")
            return
        try:
            validate_rule_deployment_approval(report, interaction.user.id)
        except PermissionError as exc:
            await respond_ephemeral(interaction, content=str(exc))
            return

        await interaction.response.defer(ephemeral=True)
        if report.validation_status not in {"passed", "bypassed"}:
            ok, summary, _ = await run_rule_validation_gate(report)
            await persist_rule_report_state(report)
            await refresh_rule_review_message(report)
            if not ok:
                await interaction.followup.send(summary or "Validation must pass or be bypassed before deployment.", ephemeral=True)
                return
        await interaction.followup.send(
            "Deploying approved rule now. This may take a few seconds if the rules file is busy.",
            ephemeral=True,
        )
        try:
            await finalize_rule_approval(report, interaction.user.id)
        except Exception as exc:
            await interaction.followup.send(f"Failed to deploy the approved rule: {exc}", ephemeral=True)
            return

        rules_backend = "Postgres" if is_spam_rules_postgres_enabled() else "spam_rules.toml"
        await interaction.followup.send(f"Rule change approved, deployed, and written to {rules_backend}.", ephemeral=True)


def build_exact_text_fallback_suggestion(report: RuleReportState, usage: Dict[str, int]) -> Optional[RuleSuggestion]:
    normalized = (
        report.ai_precheck_normalized
        or report.normalized_content
        or normalize_for_scan(report.message_content or "")
    )
    normalized = re.sub(r"\s+", " ", normalized).strip()
    if not normalized:
        return None

    exact_value = re.sub(PHONE, " ", normalized, flags=re.IGNORECASE)
    exact_value = re.sub(r"(?<!\d)\d{10}(?!\d)", " ", exact_value)
    exact_value = re.sub(EMAIL, " ", exact_value, flags=re.IGNORECASE)
    exact_value = re.sub(r"\s+", " ", exact_value).strip(" .")
    if len(exact_value) > MAX_DYNAMIC_REGEX_PATTERN_LEN:
        exact_value = exact_value[:MAX_DYNAMIC_REGEX_PATTERN_LEN].rsplit(" ", 1)[0].strip(" .")
    if len(exact_value) < 20 or exact_value not in normalized:
        return None

    raw_payload = {
        "decision": "propose",
        "target_type": "artifact",
        "reason": "known_spam_artifact",
        "exact_values": [exact_value],
        "description": "Add an exact text artifact from the reported unmatched spam sample.",
        "rationale": (
            "The AI proposals did not pass the deterministic candidate matcher. "
            "An exact normalized-text artifact is narrow and still requires manual approval."
        ),
        "confidence": "medium",
        "tests": [
            {
                "text": normalized,
                "should_match": True,
                "note": "Reported sample should match the exact artifact candidate.",
            }
        ],
    }
    return RuleSuggestion(
        decision="propose",
        target_type="artifact",
        reason="known_spam_artifact",
        exact_values=[exact_value],
        description=str(raw_payload["description"]),
        rationale=str(raw_payload["rationale"]),
        confidence="medium",
        tests=list(raw_payload["tests"]),
        raw_payload=json.dumps(raw_payload, indent=2),
        usage=dict(usage),
    )


async def run_rule_suggestion(report_id: str) -> None:
    report = RULE_REPORTS.get(report_id)
    if report is None:
        return

    report.status = "analyzing"
    await refresh_rule_review_message(report)
    try:
        precheck_matched, precheck_reason, precheck_normalized = classify_rule_report_against_current_matcher(report)
        report.ai_precheck_matched = precheck_matched
        report.ai_precheck_reason = precheck_reason
        report.ai_precheck_normalized = precheck_normalized
        report.current_matched = precheck_matched
        report.current_reason = precheck_reason

        retry_feedback = ""
        final_suggestion: Optional[RuleSuggestion] = None
        last_failed_candidate = ""
        combined_usage: Dict[str, int] = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
        for attempt in range(2):
            suggestion = await request_openai_rule_suggestion(
                report,
                force_propose=True,
                retry_feedback=retry_feedback,
            )
            for key in ("prompt_tokens", "completion_tokens", "total_tokens"):
                combined_usage[key] += int(suggestion.usage.get(key, 0) or 0)
            suggestion.usage = dict(combined_usage)
            if suggestion.decision != "propose":
                retry_feedback = "Previous draft returned decision=ignore. This is invalid."
                if attempt == 0:
                    continue
                raise RuleSuggestionGenerationError(
                    "AI returned `ignore` when a proposal was required.",
                    usage=suggestion.usage,
                )

            compiled_suggestion = compile_suggestion_matchers(suggestion)
            candidate_match, candidate_reason, _ = classify_candidate_content_and_media(
                content=report.message_content,
                media_indicators=report.media_indicators,
                image_hashes=report.image_hashes,
                suggestion=suggestion,
                compiled_suggestion=compiled_suggestion,
            )
            if precheck_matched or candidate_match:
                final_suggestion = suggestion
                break
            last_failed_candidate = suggestion_to_mutation_summary(suggestion)
            if candidate_reason:
                last_failed_candidate = f"{last_failed_candidate} produced reason={candidate_reason}"
            retry_feedback = (
                "Previous proposal failed full-detector validation for this report. "
                f"It tried {last_failed_candidate or 'an unknown target'} and did not produce a matched decision through the current candidate matcher path. "
                "If the sample does not fit an existing managed detector family, return target_type=custom_rule with a regex that directly matches report.normalized_content."
            )
            if attempt == 0:
                continue
            fallback_suggestion = build_exact_text_fallback_suggestion(report, suggestion.usage)
            fallback_match = False
            if fallback_suggestion is not None:
                fallback_compiled = compile_suggestion_matchers(fallback_suggestion)
                fallback_match, _, _ = classify_candidate_content_and_media(
                    content=report.message_content,
                    media_indicators=report.media_indicators,
                    image_hashes=report.image_hashes,
                    suggestion=fallback_suggestion,
                    compiled_suggestion=fallback_compiled,
                )
            if fallback_suggestion is not None and fallback_match:
                final_suggestion = fallback_suggestion
                break
            detail = f" Last failed target: {last_failed_candidate}." if last_failed_candidate else ""
            raise RuleSuggestionGenerationError(
                "AI proposed drafts that did not match this report through the full candidate matcher path." + detail,
                usage=suggestion.usage,
            )

        if final_suggestion is None:
            raise RuleSuggestionGenerationError("AI did not produce a valid proposal.", usage=combined_usage)
        report.suggestion = final_suggestion
        report.suggestion_error = None
        report.proposal_generated_at = utcnow()
        report.status = "proposal_ready"
        if report.suggestion.usage:
            await record_ai_usage(report.suggestion.usage)
            if report.last_generated_by is not None:
                await log_ai_usage(report, report.suggestion.usage, report.last_generated_by)
    except asyncio.CancelledError:
        report.suggestion = None
        report.suggestion_error = "Draft generation was cancelled before completion."
        report.status = "reported"
        raise
    except Exception as exc:
        usage = getattr(exc, "usage", {})
        if usage:
            await record_ai_usage(usage)
            if report.last_generated_by is not None:
                await log_ai_usage(report, usage, report.last_generated_by)
        report.suggestion = None
        report.suggestion_error = str(exc) or type(exc).__name__
        report.status = "proposal_error"
    finally:
        report.task = None
        await persist_rule_report_state(report)
        await refresh_rule_review_message(report)
        if report.review_channel_id is not None:
            channel = await fetch_messageable_channel(report.review_channel_id)
            if channel is not None:
                try:
                    await sync_rule_report_detail_messages(channel, report)
                except discord.Forbidden:
                    pass
                except discord.HTTPException:
                    pass


async def run_rule_suggestion_with_notification(report_id: str, interaction: discord.Interaction) -> None:
    await run_rule_suggestion(report_id)
    report = RULE_REPORTS.get(report_id)
    if report is None:
        return

    try:
        if report.status == "proposal_ready" and report.suggestion is not None:
            suggestion = report.suggestion
            if suggestion.decision == "propose":
                completion_text = (
                    f"AI rule drafting completed for `{report.report_id}`. "
                    f"It proposed `{suggestion_target_label(suggestion)}` for `{suggestion.reason or 'none'}`. "
                    "The full parsed draft now appears in dedicated detail embeds below the review entry."
                )
            else:
                completion_text = (
                    f"AI rule drafting completed for `{report.report_id}`. "
                    f"Decision: `{suggestion.decision}`. "
                    "The full parsed draft now appears in dedicated detail embeds below the review entry."
                )
            await interaction.followup.send(completion_text, ephemeral=True)
        elif report.status == "proposal_error":
            error_text = report.suggestion_error or "Unknown error"
            if len(error_text) > 700:
                error_text = error_text[:700].rstrip() + "..."
            await interaction.followup.send(
                f"AI rule drafting failed for `{report.report_id}`: {error_text}",
                ephemeral=True,
            )
    except (discord.NotFound, discord.Forbidden, discord.HTTPException):
        pass


async def prepare_rule_report_candidate(message: discord.Message) -> PreparedRuleReportCandidate:
    media_indicators = render_message_media_indicators(message)
    matched, reason, normalized = await classify_message_for_moderation_async(
        message,
        allow_image_hashes=True,
        force_image_hashes=True,
    )
    normalized = normalized or normalize_for_scan(message.content or media_indicators)
    image_hashes = await compute_message_image_hashes(message)
    cluster_key = build_report_cluster_key(normalized, media_indicators, image_hashes)
    return PreparedRuleReportCandidate(
        matched=matched,
        reason=reason,
        normalized=normalized,
        media_indicators=media_indicators,
        image_hashes=image_hashes,
        cluster_key=cluster_key,
    )


async def fetch_message_from_ref(message_ref: str) -> discord.Message:
    parsed = resolve_discord_message_ref(message_ref)
    if parsed is None:
        raise ValueError("Provide a full Discord message link like `https://discord.com/channels/<guild>/<channel>/<message>`.")

    _, channel_id, message_id = parsed
    channel = await fetch_messageable_channel(channel_id)
    fetch_message = getattr(channel, "fetch_message", None)
    if channel is None or fetch_message is None:
        raise ValueError("I could not access the channel from that message link.")

    try:
        message = await fetch_message(message_id)
    except discord.NotFound as exc:
        raise ValueError("That message could not be found. If it was deleted already, paste the message text into the command instead.") from exc
    except discord.Forbidden as exc:
        raise ValueError("I do not have permission to read that message.") from exc
    except discord.HTTPException as exc:
        raise ValueError(f"Discord could not fetch that message right now: {exc}") from exc

    if not isinstance(message, discord.Message):
        raise ValueError("That message could not be resolved into a Discord message object.")
    return message


def classify_manual_false_positive_content(
    *,
    guild_id: int,
    message_text: str,
    media_indicators: str = "",
) -> Tuple[bool, str, str]:
    matched, reason, normalized = classify_candidate_content_and_media(
        content=message_text,
        media_indicators=media_indicators,
    )
    domain_matched, domain_reason, domain_normalized, _ = classify_text_for_guild_domain_blocklists(
        "\n".join(part for part in (message_text, media_indicators) if part),
        guild_id,
    )
    if domain_matched and not matched:
        return True, domain_reason, domain_normalized
    return matched, reason, normalized


def classify_rule_report_against_current_matcher(report: RuleReportState) -> Tuple[bool, str, str]:
    matched, reason, normalized = classify_candidate_content_and_media(
        content=report.message_content,
        media_indicators=report.media_indicators,
        image_hashes=report.image_hashes,
    )
    if matched:
        return matched, reason, normalized

    blocklist_source_text = "\n".join(part for part in (report.message_content, report.media_indicators) if part)
    domain_matched, domain_reason, domain_normalized, _ = classify_text_for_guild_domain_blocklists(
        blocklist_source_text,
        report.source_guild_id,
    )
    if domain_matched:
        return True, domain_reason, domain_normalized
    return False, "", normalized


def classify_manual_spam_report_content(
    *,
    guild_id: int,
    message_text: str,
    media_indicators: str = "",
    image_hashes: Optional[Sequence[str]] = None,
) -> Tuple[bool, str, str]:
    matched, reason, normalized = classify_candidate_content_and_media(
        content=message_text,
        media_indicators=media_indicators,
        image_hashes=image_hashes,
    )
    domain_text = "\n".join(part for part in (message_text, media_indicators) if str(part).strip())
    if domain_text:
        domain_matched, domain_reason, domain_normalized, _ = classify_text_for_guild_domain_blocklists(domain_text, guild_id)
        if domain_matched and not matched:
            return True, domain_reason, domain_normalized
    return matched, reason, normalized


async def create_or_update_manual_rule_report(
    interaction: discord.Interaction,
    *,
    message_text: str,
    media_indicators: str = "",
    image_hashes: Optional[Sequence[str]] = None,
    prepared: Optional[Tuple[bool, str, str]] = None,
) -> Tuple[RuleReportState, bool]:
    assert interaction.guild is not None

    now = utcnow()
    parsed_hashes = trim_unique_list(
        [str(value).strip().lower() for value in (image_hashes or []) if str(value).strip()],
        limit=8,
    )
    matched, reason, normalized = prepared or classify_manual_spam_report_content(
        guild_id=interaction.guild.id,
        message_text=message_text,
        media_indicators=media_indicators,
        image_hashes=parsed_hashes,
    )
    cluster_key = build_report_cluster_key(normalized, media_indicators, parsed_hashes)
    source_channel_label = format_channel_scan_label(interaction.channel) if interaction.channel else "manual external sample"
    submitter_label = format_known_user(interaction.guild.id, interaction.user.id)
    source_author_label = f"External sample submitted by {submitter_label}"
    staff_notes = (
        "Manual sample submitted via `/spamfighter reviews report-new`.\n"
        "No Discord message was actioned. This review was seeded from administrator-provided text."
    )

    async with RULE_REPORTS_LOCK:
        clustered_id = RULE_REPORTS_BY_CLUSTER.get(
            rule_report_cluster_map_key(interaction.guild.id, cluster_key)
        )
        if clustered_id is not None and clustered_id in RULE_REPORTS:
            report = RULE_REPORTS[clustered_id]
            if report.status not in {"approved", "denied"}:
                report.reporter_ids.add(interaction.user.id)
                report.report_count += 1
                report.last_reported_at = now
                if not report.message_content or len(message_text) > len(report.message_content):
                    report.message_content = message_text
                if normalized:
                    report.normalized_content = normalized
                if media_indicators and (not report.media_indicators or len(media_indicators) > len(report.media_indicators)):
                    report.media_indicators = media_indicators
                if parsed_hashes:
                    report.image_hashes = trim_unique_list([*parsed_hashes, *report.image_hashes], limit=8)
                report.current_matched = report.current_matched or matched
                if reason:
                    report.current_reason = reason
                if not report.staff_notes:
                    report.staff_notes = staff_notes
                report.validation_status = "not_run"
                report.validation_summary = ""
                report.validation_hit_lines = []
                report.validation_ran_at = None
                report.validation_bypassed_by = None
                report.validation_months = 0
                report.validation_channel_ids = []
                await persist_rule_report_state(report)
                return report, False

        report = RuleReportState(
            report_id=f"manual-{now.strftime('%Y%m%d%H%M%S%f')}",
            cluster_key=cluster_key,
            source_guild_id=interaction.guild.id,
            source_guild_name=interaction.guild.name,
            source_channel_id=interaction.channel_id or 0,
            source_channel_label=source_channel_label,
            source_message_id=0,
            source_author_id=interaction.user.id,
            source_author_label=source_author_label,
            source_jump_url="",
            message_content=message_text,
            normalized_content=normalized,
            media_indicators=media_indicators,
            image_hashes=list(parsed_hashes),
            reporter_ids={interaction.user.id},
            current_matched=matched,
            current_reason=reason,
            review_channel_id=REPORT_REVIEW_CHANNEL_ID,
            last_reported_at=now,
            report_count=1,
            validation_status="not_run",
            staff_notes=staff_notes,
        )
        RULE_REPORTS[report.report_id] = report
        update_rule_report_cluster_map(report)
        await persist_rule_report_state(report)
        return report, True


async def create_false_positive_rule_report(
    interaction: discord.Interaction,
    *,
    message_text: str,
    source_author_id: int,
    source_author_label: str,
    notes: str = "",
    message_link: str = "",
    source_message: Optional[discord.Message] = None,
) -> RuleReportState:
    assert interaction.guild is not None

    now = utcnow()
    cleaned_notes = str(notes or "").strip()
    cleaned_link = str(message_link or "").strip()

    if source_message is not None:
        prepared = await prepare_rule_report_candidate(source_message)
        resolved_message_text = source_message.content or message_text
        normalized_content = prepared.normalized
        media_indicators = prepared.media_indicators
        image_hashes = prepared.image_hashes
        current_matched = prepared.matched
        current_reason = prepared.reason
        source_channel_id = source_message.channel.id
        source_channel_label = format_channel_scan_label(source_message.channel)
        source_message_id = source_message.id
        source_jump_url = getattr(source_message, "jump_url", "") or cleaned_link
    else:
        current_matched, current_reason, normalized_content = classify_manual_false_positive_content(
            guild_id=interaction.guild.id,
            message_text=message_text,
        )
        resolved_message_text = message_text
        media_indicators = ""
        image_hashes = []
        source_channel_id = interaction.channel_id or 0
        source_channel_label = format_channel_scan_label(interaction.channel) if interaction.channel else "manual false-positive report"
        source_message_id = 0
        source_jump_url = cleaned_link

    report_id = f"fp-{now.strftime('%Y%m%d%H%M%S%f')}"
    return RuleReportState(
        report_id=report_id,
        cluster_key="",
        source_guild_id=interaction.guild.id,
        source_guild_name=interaction.guild.name,
        source_channel_id=source_channel_id,
        source_channel_label=source_channel_label,
        source_message_id=source_message_id,
        source_author_id=source_author_id,
        source_author_label=source_author_label,
        source_jump_url=source_jump_url,
        report_kind="false_positive",
        message_content=resolved_message_text,
        normalized_content=normalized_content,
        media_indicators=media_indicators,
        image_hashes=image_hashes,
        reporter_ids={interaction.user.id},
        current_matched=current_matched,
        current_reason=current_reason,
        review_channel_id=REPORT_REVIEW_CHANNEL_ID,
        last_reported_at=now,
        report_count=1,
        staff_notes=cleaned_notes,
    )


async def create_or_update_rule_report(
    interaction: discord.Interaction,
    message: discord.Message,
    prepared: Optional[PreparedRuleReportCandidate] = None,
) -> Tuple[RuleReportState, bool]:
    assert interaction.guild is not None

    prepared = prepared or await prepare_rule_report_candidate(message)
    media_indicators = prepared.media_indicators
    matched = prepared.matched
    reason = prepared.reason
    normalized = prepared.normalized
    image_hashes = prepared.image_hashes
    now = datetime.now(timezone.utc)

    async with RULE_REPORTS_LOCK:
        existing_id = RULE_REPORTS_BY_MESSAGE_ID.get(message.id)
        if existing_id is not None and existing_id in RULE_REPORTS:
            report = RULE_REPORTS[existing_id]
            report.reporter_ids.add(interaction.user.id)
            report.report_count += 1
            report.last_reported_at = now
            report.sample_message_ids = trim_unique_int_list([message.id, *report.sample_message_ids], limit=8)
            report.sample_jump_urls = trim_unique_list([getattr(message, "jump_url", ""), *report.sample_jump_urls], limit=8)
            report.message_content = message.content or report.message_content
            report.normalized_content = normalized or report.normalized_content
            report.media_indicators = media_indicators or report.media_indicators
            if image_hashes:
                report.image_hashes = trim_unique_list([*image_hashes, *report.image_hashes], limit=8)
            report.current_matched = matched
            report.current_reason = reason
            report.validation_status = "not_run"
            report.validation_summary = ""
            report.validation_hit_lines = []
            report.validation_ran_at = None
            report.validation_bypassed_by = None
            report.validation_months = 0
            report.validation_channel_ids = []
            await persist_rule_report_state(report)
            return report, False

        cluster_key = prepared.cluster_key

        clustered_id = RULE_REPORTS_BY_CLUSTER.get(
            rule_report_cluster_map_key(interaction.guild.id, cluster_key)
        )
        if clustered_id is not None and clustered_id in RULE_REPORTS:
            report = RULE_REPORTS[clustered_id]
            if report.status not in {"approved", "denied"}:
                report.reporter_ids.add(interaction.user.id)
                report.report_count += 1
                report.last_reported_at = now
                report.sample_message_ids = trim_unique_int_list([message.id, *report.sample_message_ids], limit=8)
                report.sample_jump_urls = trim_unique_list([getattr(message, "jump_url", ""), *report.sample_jump_urls], limit=8)
                if not report.message_content and message.content:
                    report.message_content = message.content
                if not report.normalized_content and normalized:
                    report.normalized_content = normalized
                if not report.media_indicators and media_indicators:
                    report.media_indicators = media_indicators
                if image_hashes:
                    report.image_hashes = trim_unique_list([*image_hashes, *report.image_hashes], limit=8)
                report.current_matched = report.current_matched or matched
                if reason:
                    report.current_reason = reason
                report.validation_status = "not_run"
                report.validation_summary = ""
                report.validation_hit_lines = []
                report.validation_ran_at = None
                report.validation_bypassed_by = None
                report.validation_months = 0
                report.validation_channel_ids = []
                RULE_REPORTS_BY_MESSAGE_ID[message.id] = report.report_id
                await persist_rule_report_state(report)
                return report, False

        report = RuleReportState(
            report_id=str(message.id),
            cluster_key=cluster_key,
            source_guild_id=interaction.guild.id,
            source_guild_name=interaction.guild.name,
            source_channel_id=message.channel.id,
            source_channel_label=format_channel_scan_label(message.channel),
            source_message_id=message.id,
            source_author_id=message.author.id,
            source_author_label=format_known_user(interaction.guild.id, message.author.id),
            source_jump_url=getattr(message, "jump_url", ""),
            message_content=message.content or "",
            normalized_content=normalized,
            media_indicators=media_indicators,
            image_hashes=image_hashes,
            reporter_ids={interaction.user.id},
            last_reported_at=now,
            report_count=1,
            sample_message_ids=[message.id],
            sample_jump_urls=trim_unique_list([getattr(message, "jump_url", "")], limit=8),
            current_matched=matched,
            current_reason=reason,
            review_channel_id=REPORT_REVIEW_CHANNEL_ID,
            validation_status="not_run",
        )
        RULE_REPORTS[report.report_id] = report
        RULE_REPORTS_BY_MESSAGE_ID[message.id] = report.report_id
        update_rule_report_cluster_map(report)
        await persist_rule_report_state(report)
        return report, True


async def post_rule_report(report: RuleReportState) -> None:
    if REPORT_REVIEW_CHANNEL_ID is None:
        raise RuntimeError("No review channel is configured. Set reports.review_channel_id or use /spamfighter set-review-channel.")

    channel = await fetch_messageable_channel(REPORT_REVIEW_CHANNEL_ID)
    if channel is None:
        raise RuntimeError(f"Could not resolve the configured review channel {REPORT_REVIEW_CHANNEL_ID}.")

    try:
        summary_message = await channel.send(
            embed=build_rule_report_summary_embed(report),
            view=build_rule_review_view(report),
            allowed_mentions=discord.AllowedMentions.none(),
        )
        review_guild = getattr(channel, "guild", None)
        report.review_guild_id = getattr(review_guild, "id", None)
        report.review_channel_id = REPORT_REVIEW_CHANNEL_ID
        report.review_message_id = summary_message.id
        await persist_rule_report_state(report)
    except discord.Forbidden as exc:
        raise RuntimeError(f"Forbidden from sending to the review channel: {exc}") from exc
    except discord.HTTPException as exc:
        raise RuntimeError(f"Discord HTTP error sending the report: {exc}") from exc

    try:
        await sync_rule_report_detail_messages(channel, report)
    except discord.Forbidden as exc:
        log.warning("Forbidden sending rule-review detail embeds for %s: %s", report.report_id, exc)
    except discord.HTTPException as exc:
        log.warning("HTTP error sending rule-review detail embeds for %s: %s", report.report_id, exc)


class RuleReviewView(discord.ui.View):
    def __init__(self, report_id: str):
        super().__init__(timeout=None)
        self.report_id = report_id
        report = RULE_REPORTS.get(report_id)
        if report is None or is_false_positive_report(report) or not report_supports_hash_images(report):
            self.remove_item(self.hash_images)
        if report is None or is_false_positive_report(report) or report.validation_status != "failed":
            self.remove_item(self.bypass_validation)
        if report is not None and is_false_positive_report(report):
            self.remove_item(self.generate_rule)
            self.remove_item(self.approve_rule)
            self.deny_rule.label = "Close Review"
            self.deny_rule.style = discord.ButtonStyle.secondary

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        report = RULE_REPORTS.get(self.report_id)
        if report is None:
            await respond_ephemeral(interaction, content="That report is no longer available.")
            return False
        if not user_can_review_rule_changes_for_report(report, user_id=interaction.user.id):
            await respond_ephemeral(
                interaction,
                content="Only source-guild admins, master-review-guild admins, or configured control operators can use these review actions.",
            )
            await audit_unauthorized_component_interaction(
                interaction,
                title="Unauthorized Rule Review Button Attempt",
                where="RuleReviewView.interaction_check",
                details="Only source-guild admins, master-review-guild admins, or configured control operators can use rule review buttons.",
                extra={
                    "Report ID": self.report_id,
                    "Source Guild": f"{report.source_guild_name} ({report.source_guild_id})",
                },
            )
            return False
        return True

    async def on_error(self, interaction: discord.Interaction, error: Exception, item: discord.ui.Item) -> None:
        try:
            await respond_ephemeral(interaction, content="That rule review action failed.")
        except Exception:
            pass
        await audit_error(
            interaction.guild,
            "Rule Review Interaction Failed",
            f"RuleReviewView.on_error:{getattr(item, 'custom_id', None) or type(item).__name__}",
            error,
            extra={
                "User": f"{interaction.user} ({interaction.user.id})",
                "Report ID": self.report_id,
                "Component": interaction_component_id(interaction) or getattr(item, "custom_id", "") or "unknown",
            },
        )

    @discord.ui.button(label="Draft Rule with AI", style=discord.ButtonStyle.primary, custom_id="spamfighter:rule-review:generate")
    async def generate_rule(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        report = RULE_REPORTS.get(self.report_id)
        if report is None:
            await respond_ephemeral(interaction, content="That report is no longer available.")
            return
        if is_false_positive_report(report):
            await respond_ephemeral(interaction, content="False-positive reviews are reviewed manually. They do not generate deployable AI rule drafts.")
            return
        if report.status == "approved":
            await respond_ephemeral(interaction, content="That rule draft has already been approved.")
            return
        if report.status == "denied":
            await respond_ephemeral(interaction, content="That review has already been rejected.")
            return
        if (
            report.status == "proposal_ready"
            and report.suggestion is not None
            and report.suggestion.decision == "propose"
        ):
            await respond_ephemeral(interaction, content="That review already has a draft ready.")
            return
        if report.task is not None or report.status == "analyzing":
            await respond_ephemeral(interaction, content="An AI draft is already being generated for this review.")
            return
        if not OPENAI_API_KEY:
            await respond_ephemeral(interaction, content="OpenAI is not configured for this bot yet.")
            return

        await interaction.response.defer(ephemeral=True)
        report.status = "reported"
        report.suggestion = None
        report.suggestion_error = None
        report.proposal_generated_at = None
        report.validation_status = "not_run"
        report.validation_summary = ""
        report.validation_hit_lines = []
        report.validation_ran_at = None
        report.validation_bypassed_by = None
        report.validation_months = 0
        report.validation_channel_ids = []
        report.ai_precheck_matched = False
        report.ai_precheck_reason = ""
        report.ai_precheck_normalized = ""
        report.ai_ignore_approved_by = None
        report.last_generated_by = interaction.user.id
        update_rule_report_cluster_map(report)
        await persist_rule_report_state(report)
        await refresh_rule_review_message(report)
        report.task = asyncio.create_task(
            run_rule_suggestion_with_notification(report.report_id, interaction),
            name=f"spamfighter-rule-review-{report.report_id}",
        )
        await interaction.followup.send(
            "AI rule drafting started for this review. I will send another update here when the draft is completed.",
            ephemeral=True,
        )
        await log_rule_review_action(
            report,
            action="generated",
            actor_id=interaction.user.id,
            details="Started AI rule drafting for the reported message.",
        )

    @discord.ui.button(label="Create Exact Image Hash Rule", style=discord.ButtonStyle.secondary, custom_id="spamfighter:rule-review:hash-images")
    async def hash_images(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        report = RULE_REPORTS.get(self.report_id)
        if report is None:
            await respond_ephemeral(interaction, content="That report is no longer available.")
            return
        if is_false_positive_report(report):
            await respond_ephemeral(interaction, content="False-positive reviews do not create new image-hash rule drafts.")
            return
        if report.status == "approved":
            await respond_ephemeral(interaction, content="That rule draft has already been approved.")
            return
        if report.status == "denied":
            await respond_ephemeral(interaction, content="That review has already been rejected.")
            return
        # Allow hash-rule generation to replace an existing draft on this review.
        if report.task is not None or report.status == "analyzing":
            await respond_ephemeral(interaction, content="An AI draft is already being generated for this review.")
            return
        previous_suggestion = report.suggestion

        await interaction.response.defer(ephemeral=True)
        hashes = await refresh_rule_report_image_hashes(report)
        if not hashes:
            await persist_rule_report_state(report)
            await refresh_rule_review_message(report)
            channel = await fetch_messageable_channel(report.review_channel_id) if report.review_channel_id else None
            if channel is not None:
                await sync_rule_report_detail_messages(channel, report)
            max_mb = max(1, KNOWN_IMAGE_HASH_MAX_BYTES // (1024 * 1024))
            await interaction.followup.send(
                f"No hashable image attachments were found on this report. Only supported image attachments up to about {max_mb} MB can be hashed.",
                ephemeral=True,
            )
            return

        new_hashes = [digest for digest in hashes if digest.lower() not in MANAGED_KNOWN_IMAGE_HASHES]
        channel = await fetch_messageable_channel(report.review_channel_id) if report.review_channel_id else None
        if channel is not None:
            await sync_rule_report_detail_messages(channel, report)

        if not new_hashes:
            await persist_rule_report_state(report)
            await refresh_rule_review_message(report)
            await interaction.followup.send("These image hashes are already stored as known spam hashes.", ephemeral=True)
            return

        report.status = "proposal_ready"
        report.suggestion = build_image_hash_rule_suggestion(report, new_hashes)
        report.suggestion_error = None
        report.proposal_generated_at = utcnow()
        report.validation_status = "not_run"
        report.validation_summary = ""
        report.validation_hit_lines = []
        report.validation_ran_at = None
        report.validation_bypassed_by = None
        report.validation_months = 0
        report.validation_channel_ids = []
        report.ai_ignore_approved_by = None
        report.last_generated_by = interaction.user.id
        update_rule_report_cluster_map(report)
        await persist_rule_report_state(report)
        await refresh_rule_review_message(report)
        replacement_note = ""
        if previous_suggestion is not None:
            replacement_note = (
                f" Replaced previous draft source `{suggestion_source_label(previous_suggestion)}` "
                f"target `{suggestion_target_label(previous_suggestion)}`."
            )
        await interaction.followup.send(
            f"Prepared an exact image-hash rule draft with {len(new_hashes)} new hash(es). Review it and deploy when ready.{replacement_note}",
            ephemeral=True,
        )
        await log_rule_review_action(
            report,
            action="generated",
            actor_id=interaction.user.id,
            details=f"Prepared exact image-hash rule draft without AI ({len(new_hashes)} new hash(es)).",
        )

    @discord.ui.button(label="Approve Ignore", style=discord.ButtonStyle.secondary, custom_id="spamfighter:rule-review:approve-ignore")
    async def approve_ignore(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        report = RULE_REPORTS.get(self.report_id)
        if report is None:
            await respond_ephemeral(interaction, content="That report is no longer available.")
            return
        if is_false_positive_report(report):
            await respond_ephemeral(interaction, content="False-positive reviews are closed manually instead.")
            return
        if report.status in {"approved", "denied"}:
            await respond_ephemeral(interaction, content="That review is already closed.")
            return
        if report.suggestion is None or report.suggestion.decision != "ignore":
            await respond_ephemeral(interaction, content="There is no pending ignore decision on this review.")
            return
        if report.ai_precheck_matched:
            await respond_ephemeral(interaction, content="This review currently matches the detector, so use the normal approval path.")
            return

        report.ai_ignore_approved_by = interaction.user.id
        report.status = "denied"
        report.denied_by = interaction.user.id
        report.task = None
        update_rule_report_cluster_map(report)
        await persist_rule_report_state(report)
        await refresh_rule_review_message(report)
        await respond_ephemeral(interaction, content="Ignore decision approved and review closed.")
        await log_rule_review_action(
            report,
            action="denied",
            actor_id=interaction.user.id,
            details="Approved unmatched ignore decision and closed the review.",
        )

    @discord.ui.button(label="Approve and Deploy", style=discord.ButtonStyle.success, custom_id="spamfighter:rule-review:approve")
    async def approve_rule(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        report = RULE_REPORTS.get(self.report_id)
        if report is None:
            await respond_ephemeral(interaction, content="That report is no longer available.")
            return
        if is_false_positive_report(report):
            await respond_ephemeral(interaction, content="False-positive reviews are closed manually instead of being approved and deployed.")
            return
        if report.status == "approved":
            await respond_ephemeral(interaction, content="That rule draft has already been approved.")
            return
        if report.status == "denied":
            await respond_ephemeral(interaction, content="That review has already been rejected.")
            return
        if report.suggestion is None:
            await respond_ephemeral(interaction, content="There is no rule draft to approve yet.")
            return
        if report.suggestion.decision != "propose":
            await respond_ephemeral(interaction, content="The current draft did not recommend a rule change.")
            return
        if not user_can_deploy_rule_changes_for_report(report, user_id=interaction.user.id):
            await respond_ephemeral(
                interaction,
                content="You can review this draft, but only configured SpamFighter deployers can publish global rule changes.",
            )
            return
        try:
            validate_rule_deployment_approval(report, interaction.user.id)
        except PermissionError as exc:
            await respond_ephemeral(interaction, content=str(exc))
            return

        await interaction.response.defer(ephemeral=True)
        needs_validation = (
            report.validation_status not in {"passed", "bypassed"}
            or report.validation_ran_at is None
            or (
                report.proposal_generated_at is not None
                and report.validation_ran_at < report.proposal_generated_at
            )
        )
        if needs_validation:
            ok, summary, _ = await run_rule_validation_gate(report)
            await persist_rule_report_state(report)
            await refresh_rule_review_message(report)
            if not ok:
                await interaction.followup.send(summary, ephemeral=True)
                await log_rule_review_action(
                    report,
                    action="validated",
                    actor_id=interaction.user.id,
                    details=f"Validation blocked deployment: {summary}",
                )
                return

        confirm_view = RuleDeploymentConfirmView(report.report_id, interaction.user.id)
        active_source = suggestion_source_label(report.suggestion)
        active_target = suggestion_target_label(report.suggestion)
        active_reason = report.suggestion.reason or "none"
        await interaction.followup.send(
            (
                "Validation passed. "
                f"Active draft: source `{active_source}`, target `{active_target}`, reason `{active_reason}`. "
                "Confirm approve/deploy will publish this active draft."
            ),
            ephemeral=True,
            view=confirm_view,
        )

    @discord.ui.button(label="Bypass Validation", style=discord.ButtonStyle.secondary, custom_id="spamfighter:rule-review:bypass-validation")
    async def bypass_validation(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        report = RULE_REPORTS.get(self.report_id)
        if report is None:
            await respond_ephemeral(interaction, content="That report is no longer available.")
            return
        if report.validation_status != "failed":
            await respond_ephemeral(interaction, content="This review does not currently need a validation bypass.")
            return

        report.validation_status = "bypassed"
        report.validation_summary = "Validation was manually bypassed after staff review of the linked clean-channel hits."
        report.validation_bypassed_by = interaction.user.id
        await persist_rule_report_state(report)
        await refresh_rule_review_message(report)
        await respond_ephemeral(interaction, content="Validation bypass recorded. You can now approve and deploy this rule if needed.")
        await log_rule_review_action(
            report,
            action="validated",
            actor_id=interaction.user.id,
            details="Validation was manually bypassed after reviewing linked false-positive hits.",
        )

    @discord.ui.button(label="Reject Review", style=discord.ButtonStyle.danger, custom_id="spamfighter:rule-review:deny")
    async def deny_rule(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        report = RULE_REPORTS.get(self.report_id)
        if report is None:
            await respond_ephemeral(interaction, content="That report is no longer available.")
            return
        if report.status == "approved":
            await respond_ephemeral(interaction, content="That rule draft has already been approved.")
            return
        if report.status == "denied":
            await respond_ephemeral(interaction, content="That review has already been rejected.")
            return

        await finalize_rule_denial(report, interaction.user.id)
        await respond_ephemeral(
            interaction,
            content="False-positive review closed." if is_false_positive_report(report) else "Rule draft rejected.",
        )

# ============================================================
# Setup UI
# ============================================================

class ThresholdModal(discord.ui.Modal, title="SpamFighter Thresholds"):
    warn_threshold = discord.ui.TextInput(label="Warn threshold", default="1", max_length=3)
    timeout_threshold = discord.ui.TextInput(label="Timeout threshold", default="2", max_length=3)
    kick_threshold = discord.ui.TextInput(label="Kick threshold", default="3", max_length=3)
    ban_threshold = discord.ui.TextInput(label="Ban threshold", default="4", max_length=3)
    timeout_minutes = discord.ui.TextInput(label="Timeout minutes", default="60", max_length=4)

    def __init__(self, guild_id: int, actor_id: int):
        super().__init__(timeout=300)
        self.guild_id = guild_id
        self.actor_id = actor_id
        current = resolve_moderation_settings(guild_id)
        self.warn_threshold.default = str(current.warn_threshold)
        self.timeout_threshold.default = str(current.timeout_threshold)
        self.kick_threshold.default = str(current.kick_threshold)
        self.ban_threshold.default = str(current.ban_threshold)
        self.timeout_minutes.default = str(current.timeout_minutes)

    async def on_submit(self, interaction: discord.Interaction) -> None:
        if interaction.user.id != self.actor_id:
            await respond_ephemeral(interaction, content="Only the person who opened setup can submit this thresholds form.")
            await audit_unauthorized_component_interaction(
                interaction,
                title="Unauthorized Threshold Modal Submit",
                where="ThresholdModal.on_submit",
                details="Only the setup initiator can submit the thresholds modal.",
                extra={
                    "Guild ID": str(self.guild_id),
                    "Setup Actor": str(self.actor_id),
                },
            )
            return
        if not user_can_manage_guild_settings(interaction):
            await respond_ephemeral(interaction, content="You no longer have permission to update this guild's setup settings.")
            await audit_unauthorized_component_interaction(
                interaction,
                title="Threshold Modal Permission Revoked",
                where="ThresholdModal.on_submit",
                details="The setup initiator no longer has Administrator, Manage Server, or configured control-operator access.",
                extra={
                    "Guild ID": str(self.guild_id),
                    "Setup Actor": str(self.actor_id),
                },
            )
            return
        try:
            warn = int(str(self.warn_threshold))
            timeout = int(str(self.timeout_threshold))
            kick = int(str(self.kick_threshold))
            ban = int(str(self.ban_threshold))
            timeout_minutes = int(str(self.timeout_minutes))
        except ValueError:
            await respond_ephemeral(interaction, content="All threshold values must be integers.")
            return

        try:
            await write_guild_moderation_overrides(
                self.guild_id,
                warn_threshold=warn,
                timeout_threshold=timeout,
                kick_threshold=kick,
                ban_threshold=ban,
                timeout_minutes=timeout_minutes,
            )
        except Exception as exc:
            await respond_ephemeral(interaction, content=f"Failed to save thresholds: {exc}")
            await audit_error(interaction.guild, "Setup Threshold Save Failed", "ThresholdModal.on_submit", exc)
            return

        embed = build_guild_settings_embed(interaction.guild)
        await respond_ephemeral(interaction, content="Thresholds updated.", embed=embed)
        await audit_control_action(interaction, "setup-thresholds", f"Updated thresholds for guild {self.guild_id}")

    async def on_error(self, interaction: discord.Interaction, error: Exception) -> None:
        try:
            await respond_ephemeral(interaction, content="The thresholds form failed.")
        except Exception:
            pass
        await audit_error(
            interaction.guild,
            "Threshold Modal Failed",
            "ThresholdModal.on_error",
            error,
            extra={
                "User": f"{interaction.user} ({interaction.user.id})",
                "Guild ID": str(self.guild_id),
                "Setup Actor": str(self.actor_id),
                "Component": interaction_component_id(interaction) or "modal",
            },
        )


class SetupDashboardView(discord.ui.View):
    def __init__(self, actor_id: int, guild_id: int):
        super().__init__(timeout=900)
        self.actor_id = actor_id
        self.guild_id = guild_id
        self._refresh_blocklist_buttons()

    def _refresh_blocklist_buttons(self) -> None:
        enabled = get_enabled_domain_blocklists_for_guild(self.guild_id)
        button_specs = (
            (self.toggle_porn_blocklist, "porn"),
            (self.toggle_malicious_blocklist, "malicious"),
            (self.toggle_custom_blocklist, "custom"),
        )
        for button, blocklist_key in button_specs:
            is_enabled = blocklist_key in enabled
            button.label = f"{format_domain_blocklist_label(blocklist_key)}: {'On' if is_enabled else 'Off'}"
            button.style = discord.ButtonStyle.success if is_enabled else discord.ButtonStyle.secondary

    async def _edit_dashboard(
        self,
        interaction: discord.Interaction,
        *,
        description: Optional[str] = None,
    ) -> None:
        assert interaction.guild is not None
        self._refresh_blocklist_buttons()
        embed = build_guild_settings_embed(interaction.guild)
        if description is not None:
            embed.description = description
        await interaction.response.edit_message(embed=embed, view=self)

    async def _toggle_blocklist(self, interaction: discord.Interaction, blocklist_key: str) -> None:
        assert interaction.guild is not None
        currently_enabled = blocklist_key in get_enabled_domain_blocklists_for_guild(interaction.guild.id)
        new_value = not currently_enabled

        try:
            await set_guild_domain_blocklist_enabled(interaction.guild.id, blocklist_key, enabled=new_value)
        except Exception as exc:
            await respond_ephemeral(interaction, content=f"Failed to update blocklist: {exc}")
            await audit_error(
                interaction.guild,
                "Setup Blocklist Toggle Failed",
                f"SetupDashboardView.toggle_blocklist:{blocklist_key}",
                exc,
            )
            return

        await self._edit_dashboard(
            interaction,
            description=(
                f"{format_domain_blocklist_label(blocklist_key)} is now "
                f"{'enabled' if new_value else 'disabled'} for this guild."
            ),
        )
        await audit_control_action(
            interaction,
            "setup-toggle-blocklist",
            f"Set {blocklist_key} blocklist enabled={new_value} for guild {interaction.guild.id}",
        )

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if interaction.user.id != self.actor_id:
            await respond_ephemeral(interaction, content="Only the person who started setup can use this setup panel.")
            await audit_unauthorized_component_interaction(
                interaction,
                title="Unauthorized Setup Button Attempt",
                where="SetupDashboardView.interaction_check",
                details="Only the setup initiator can use this setup panel.",
                extra={
                    "Guild ID": str(self.guild_id),
                    "Setup Actor": str(self.actor_id),
                },
            )
            return False
        if not user_can_manage_guild_settings(interaction):
            await respond_ephemeral(interaction, content="You no longer have permission to use this setup panel.")
            await audit_unauthorized_component_interaction(
                interaction,
                title="Setup Permission Revoked",
                where="SetupDashboardView.interaction_check",
                details="The setup initiator no longer has Administrator, Manage Server, or configured control-operator access.",
                extra={
                    "Guild ID": str(self.guild_id),
                    "Setup Actor": str(self.actor_id),
                },
            )
            return False
        return True

    async def on_error(self, interaction: discord.Interaction, error: Exception, item: discord.ui.Item) -> None:
        try:
            await respond_ephemeral(interaction, content="That setup action failed.")
        except Exception:
            pass
        await audit_error(
            interaction.guild,
            "Setup Dashboard Interaction Failed",
            f"SetupDashboardView.on_error:{getattr(item, 'custom_id', None) or type(item).__name__}",
            error,
            extra={
                "User": f"{interaction.user} ({interaction.user.id})",
                "Guild ID": str(self.guild_id),
                "Setup Actor": str(self.actor_id),
                "Component": interaction_component_id(interaction) or getattr(item, "custom_id", "") or "unknown",
            },
        )

    @discord.ui.button(label="Create log channels", style=discord.ButtonStyle.primary, row=0)
    async def create_log_channels(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        assert interaction.guild is not None
        try:
            audit_channel, enforcement_channel = await ensure_guild_log_channels(interaction.guild)
        except Exception as exc:
            await respond_ephemeral(interaction, content=f"Failed to create channels: {exc}")
            await audit_error(interaction.guild, "Setup Channel Creation Failed", "SetupDashboardView.create_log_channels", exc)
            return

        await self._edit_dashboard(
            interaction,
            description=(
                f"Created or re-used {audit_channel.mention} and {enforcement_channel.mention}. "
                "This configuration has already been written to config.toml."
            ),
        )
        await audit_control_action(
            interaction,
            "setup-create-log-channels",
            f"Configured audit={audit_channel.id}, enforcement={enforcement_channel.id}",
        )

    @discord.ui.button(label="Toggle escalation", style=discord.ButtonStyle.secondary, row=0)
    async def toggle_escalation(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        assert interaction.guild is not None
        current = resolve_moderation_settings(interaction.guild.id)
        new_value = not current.enable_escalation

        try:
            await write_guild_moderation_overrides(interaction.guild.id, enable_escalation=new_value)
        except Exception as exc:
            await respond_ephemeral(interaction, content=f"Failed to update escalation: {exc}")
            await audit_error(interaction.guild, "Setup Escalation Toggle Failed", "SetupDashboardView.toggle_escalation", exc)
            return

        await self._edit_dashboard(interaction)
        await audit_control_action(
            interaction,
            "setup-toggle-escalation",
            f"Set enable_escalation={new_value} for guild {interaction.guild.id}",
        )

    @discord.ui.button(label="Toggle deletion", style=discord.ButtonStyle.secondary, row=4)
    async def toggle_deletion(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        assert interaction.guild is not None
        current = resolve_moderation_settings(interaction.guild.id)
        new_value = not current.enable_deletion

        try:
            await write_guild_moderation_overrides(interaction.guild.id, enable_deletion=new_value)
        except Exception as exc:
            await respond_ephemeral(interaction, content=f"Failed to update deletion setting: {exc}")
            await audit_error(interaction.guild, "Setup Deletion Toggle Failed", "SetupDashboardView.toggle_deletion", exc)
            return

        await self._edit_dashboard(interaction)
        await audit_control_action(
            interaction,
            "setup-toggle-deletion",
            f"Set enable_deletion={new_value} for guild {interaction.guild.id}",
        )

    @discord.ui.button(label="Open threshold modal", style=discord.ButtonStyle.secondary, row=0)
    async def open_threshold_modal(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        await interaction.response.send_modal(ThresholdModal(self.guild_id, self.actor_id))

    @discord.ui.button(label="Permissions check", style=discord.ButtonStyle.secondary, row=0)
    async def permissions_check(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        assert interaction.guild is not None
        try:
            bot_member = await get_bot_member(interaction.guild)
        except Exception as exc:
            await respond_ephemeral(interaction, content=f"Could not resolve bot member: {exc}")
            await audit_error(interaction.guild, "Setup Permissions Check Failed", "SetupDashboardView.permissions_check", exc)
            return

        embed = build_permission_embed(guild=interaction.guild, channel=None, member=bot_member)
        await respond_ephemeral(interaction, embed=embed)

    @discord.ui.select(
        cls=discord.ui.ChannelSelect,
        channel_types=[discord.ChannelType.text],
        placeholder="Select an existing audit channel",
        min_values=1,
        max_values=1,
        row=1,
    )
    async def select_audit_channel(self, interaction: discord.Interaction, select: discord.ui.ChannelSelect) -> None:
        assert interaction.guild is not None
        selected = select.values[0]
        try:
            await write_guild_channels(interaction.guild.id, audit_channel_id=selected.id)
        except Exception as exc:
            await respond_ephemeral(interaction, content=f"Failed to set audit channel: {exc}")
            await audit_error(interaction.guild, "Setup Audit Channel Select Failed", "SetupDashboardView.select_audit_channel", exc)
            return

        await self._edit_dashboard(interaction)
        await audit_control_action(
            interaction,
            "setup-select-audit-channel",
            f"Set audit channel for guild {interaction.guild.id} to {selected.id}",
        )

    @discord.ui.select(
        cls=discord.ui.ChannelSelect,
        channel_types=[discord.ChannelType.text],
        placeholder="Select an existing enforcement channel",
        min_values=1,
        max_values=1,
        row=2,
    )
    async def select_enforcement_channel(self, interaction: discord.Interaction, select: discord.ui.ChannelSelect) -> None:
        assert interaction.guild is not None
        selected = select.values[0]
        try:
            await write_guild_channels(interaction.guild.id, enforcement_channel_id=selected.id)
        except Exception as exc:
            await respond_ephemeral(interaction, content=f"Failed to set enforcement channel: {exc}")
            await audit_error(interaction.guild, "Setup Enforcement Channel Select Failed", "SetupDashboardView.select_enforcement_channel", exc)
            return

        await self._edit_dashboard(interaction)
        await audit_control_action(
            interaction,
            "setup-select-enforcement-channel",
            f"Set enforcement channel for guild {interaction.guild.id} to {selected.id}",
        )

    @discord.ui.button(label="Porn Sites: Off", style=discord.ButtonStyle.secondary, row=3)
    async def toggle_porn_blocklist(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        await self._toggle_blocklist(interaction, "porn")

    @discord.ui.button(label="Malicious Sites: Off", style=discord.ButtonStyle.secondary, row=3)
    async def toggle_malicious_blocklist(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        await self._toggle_blocklist(interaction, "malicious")

    @discord.ui.button(label="Custom Sites: Off", style=discord.ButtonStyle.secondary, row=3)
    async def toggle_custom_blocklist(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        await self._toggle_blocklist(interaction, "custom")

    @discord.ui.button(label="Done", style=discord.ButtonStyle.success, row=4)
    async def done(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        assert interaction.guild is not None
        embed = build_guild_settings_embed(interaction.guild)
        embed.description = "Setup is complete. The current guild configuration is shown below."
        for child in self.children:
            child.disabled = True
        await interaction.response.edit_message(embed=embed, view=self)
        self.stop()


# ============================================================
# Moderation
# ============================================================

async def maybe_warn_member(member: discord.Member, guild: discord.Guild, violation_count: int) -> None:
    warning = base_embed(
        title="Spam Warning",
        color=discord.Color.orange(),
        description="Your message was flagged as spam by SpamFighter.",
    )
    warning.add_field(name="Guild", value=f"{guild.name} (`{guild.id}`)", inline=False)
    warning.add_field(name="Violation Count", value=str(violation_count), inline=True)
    warning.add_field(name="What happened", value="Your message was removed because it matched a spam rule.", inline=False)

    try:
        await member.send(embed=warning)
    except discord.Forbidden:
        pass
    except discord.HTTPException:
        pass

    action = base_embed(
        title="Spam Escalation Action",
        color=discord.Color.orange(),
        description="A user warning was issued for repeated spam behavior.",
    )
    action.add_field(name="Guild", value=f"{guild.name} (`{guild.id}`)", inline=False)
    action.add_field(name="User", value=f"{member.mention} (`{member.id}`)", inline=False)
    action.add_field(name="Violation Count", value=str(violation_count), inline=True)
    action.add_field(name="Action", value="warn", inline=True)
    await send_enforcement_embeds(guild, [action])


async def maybe_escalate_member(message: discord.Message, violation_count: int) -> None:
    guild = message.guild
    if guild is None:
        return
    if not isinstance(message.author, discord.Member):
        return

    settings = resolve_moderation_settings(guild.id)
    if not settings.enable_escalation:
        return

    member = message.author
    remember_user_identity(guild.id, member)
    action = await apply_escalation_action(guild, member, violation_count)
    if action is None or action == "warn":
        return

    embed = base_embed(
        title="Spam Escalation Action",
        color=discord.Color.dark_red(),
        description=f"Automatic {action} applied for repeated spam violations.",
    )
    embed.add_field(name="Guild", value=f"{guild.name} (`{guild.id}`)", inline=False)
    embed.add_field(name="User", value=f"{member.mention} (`{member.id}`)", inline=False)
    embed.add_field(name="Violation Count", value=str(violation_count), inline=True)
    embed.add_field(name="Action", value=action, inline=True)
    if action == "timeout":
        embed.add_field(name="Duration", value=f"{settings.timeout_minutes} minutes", inline=True)

    await send_enforcement_embeds(guild, [embed])


# ============================================================
# Commands
# ============================================================


class RetroExecuteConfirmView(discord.ui.View):
    def __init__(self, *, actor_id: int, target_guild_id: int, months: int, deep_image_hash_scan: bool):
        super().__init__(timeout=300)
        self.actor_id = actor_id
        self.target_guild_id = target_guild_id
        self.months = months
        self.deep_image_hash_scan = deep_image_hash_scan

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if interaction.user.id != self.actor_id:
            await respond_ephemeral(interaction, content="Only the administrator who requested this retro execute can confirm it.")
            return False
        if not user_can_manage_guild_settings(interaction):
            await respond_ephemeral(interaction, content="You no longer have permission to run retro execute.")
            return False
        return True

    @discord.ui.button(label="Confirm Retro Execute", style=discord.ButtonStyle.danger, custom_id="spamfighter:retro:confirm-execute")
    async def confirm(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        target_guild = bot.get_guild(self.target_guild_id)
        if target_guild is None:
            await respond_ephemeral(interaction, content="I could not find that guild in this bot session anymore.")
            return
        if RETRO_SCAN.running:
            embed = build_retro_scan_embed(RETRO_SCAN)
            await respond_ephemeral(
                interaction,
                content="A retro scan is already running. Use `/spamfighter retro status` to follow it or `/spamfighter retro cancel` to stop it.",
                embed=embed,
            )
            return

        await interaction.response.defer(ephemeral=True)
        try:
            scan = await start_retro_scan_request(
                target_guild=target_guild,
                requested_by=interaction.user.id,
                months=self.months,
                execute=True,
                deep_image_hash_scan=self.deep_image_hash_scan,
            )
        except RuntimeError as exc:
            await interaction.followup.send(str(exc), ephemeral=True)
            return
        embed = build_retro_scan_embed(scan)
        embed.description = (
            "Retro execute confirmed. It will delete matched messages when possible and apply retroactive moderation. "
            "Use `/spamfighter retro status` to check progress."
        )
        if self.deep_image_hash_scan:
            embed.description += " Exact known image hashes will also be checked during this scan."
        await interaction.followup.send(embed=embed, ephemeral=True)
        await audit_control_action(
            interaction,
            "retro-scan",
            f"Confirmed retro execute for target guild {target_guild.id} months={self.months} deep_image_hash_scan={self.deep_image_hash_scan}",
        )


class RollbackConfirmView(discord.ui.View):
    def __init__(self, *, actor_id: int, backup_name: str):
        super().__init__(timeout=300)
        self.actor_id = actor_id
        self.backup_name = backup_name

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if interaction.user.id != self.actor_id:
            await respond_ephemeral(interaction, content="Only the administrator who requested this rollback can confirm it.")
            return False
        if interaction.user.id not in CONTROL_ADMIN_USER_IDS:
            await respond_ephemeral(interaction, content="You are no longer authorized to restore spam rule backups.")
            return False
        return True

    @discord.ui.button(label="Confirm Rollback", style=discord.ButtonStyle.danger, custom_id="spamfighter:rules:confirm-rollback")
    async def confirm(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        await interaction.response.defer(ephemeral=True)
        try:
            restored = await restore_spam_rules_backup(self.backup_name)
        except Exception as exc:
            await interaction.followup.send(f"Failed to restore that backup: {exc}", ephemeral=True)
            await audit_error(interaction.guild, "Rollback Rule Failed", "rollback_rule.confirm", exc)
            return

        embed = base_embed(
            title="spam_rules.toml Restored",
            color=discord.Color.green(),
            description="The selected backup was restored and reloaded.",
        )
        embed.add_field(name="Backup", value=self.backup_name, inline=False)
        embed.add_field(name="Artifacts", value=str(len(restored.artifact_values)), inline=True)
        embed.add_field(name="Image Hashes", value=str(len(restored.image_hashes)), inline=True)
        embed.add_field(name="Custom Rules", value=str(len(restored.custom_rules)), inline=True)
        await interaction.followup.send(embed=embed, ephemeral=True)
        await audit_control_action(interaction, "rollback-rule", f"Restored spam rules from backup {self.backup_name}")

class ReportCog(commands.Cog):
    def __init__(self, bot_client: SpamGuardBot) -> None:
        self.bot = bot_client
        self.report_context_menu = app_commands.ContextMenu(
            name="SpamFighter AI Report",
            callback=self.report_to_spamfighter,
        )

    async def cog_load(self) -> None:
        try:
            self.bot.tree.add_command(self.report_context_menu)
        except app_commands.CommandAlreadyRegistered:
            pass

    async def cog_unload(self) -> None:
        self.bot.tree.remove_command(self.report_context_menu.name, type=self.report_context_menu.type)

    async def report_to_spamfighter(self, interaction: discord.Interaction, message: discord.Message) -> None:
        if interaction.guild is None:
            await respond_ephemeral(interaction, content="This report action can only be used inside a server.")
            return
        if REPORT_REVIEW_CHANNEL_ID is None:
            await respond_ephemeral(interaction, content="SpamFighter review is not configured yet. Ask an admin to set the review channel first.")
            return

        await interaction.response.defer(ephemeral=True)
        remember_user_identity(interaction.guild.id, interaction.user)
        remember_user_identity(interaction.guild.id, message.author)
        prepared = await prepare_rule_report_candidate(message)

        if prepared.matched:
            await record_reporter_event(interaction.guild.id, interaction.user.id, str(message.id), "matched_existing")
            await interaction.followup.send(
                (
                    "That message already matches SpamFighter's current rules, so I didn't open a new AI review. "
                    f"Current match: `{prepared.reason or 'unknown'}`."
                ),
                ephemeral=True,
            )
            return

        allow_existing_review = False
        async with RULE_REPORTS_LOCK:
            existing_id = RULE_REPORTS_BY_MESSAGE_ID.get(message.id)
            cluster_id = RULE_REPORTS_BY_CLUSTER.get(
                rule_report_cluster_map_key(interaction.guild.id, prepared.cluster_key)
            )
            for candidate_id in (existing_id, cluster_id):
                report = RULE_REPORTS.get(candidate_id or "")
                if report is not None and report.status not in {"approved", "denied"}:
                    allow_existing_review = True
                    break

        if not allow_existing_review:
            cooldown_until = await get_reporter_cooldown_until(interaction.guild.id, interaction.user.id)
            if cooldown_until is not None:
                await interaction.followup.send(
                    (
                        "Your recent reports were denied multiple times, so new AI reviews are temporarily paused for you. "
                        f"You can report again {pretty_ts(cooldown_until, 'R')}."
                    ),
                    ephemeral=True,
                )
                return

        report, created = await create_or_update_rule_report(interaction, message, prepared=prepared)
        if created:
            try:
                await post_rule_report(report)
            except Exception as exc:
                async with RULE_REPORTS_LOCK:
                    RULE_REPORTS.pop(report.report_id, None)
                    RULE_REPORTS_BY_MESSAGE_ID.pop(message.id, None)
                    if report.cluster_key:
                        RULE_REPORTS_BY_CLUSTER.pop(
                            rule_report_cluster_map_key(report.source_guild_id, report.cluster_key),
                            None,
                        )
                await remove_rule_report_state(report.report_id)
                await interaction.followup.send(f"Failed to forward the report to the review channel: {exc}", ephemeral=True)
                return

            await record_reporter_event(interaction.guild.id, interaction.user.id, report.report_id, "submitted")
            await refresh_rule_reporter_snapshot(report)
            await persist_rule_report_state(report)
            await refresh_rule_review_message(report)
            await interaction.followup.send(
                "Thanks. The message was forwarded to the SpamFighter AI review channel for moderator review. No rule is changed automatically.",
                ephemeral=True,
            )
            return

        await record_reporter_event(interaction.guild.id, interaction.user.id, report.report_id, "merged")
        await refresh_rule_reporter_snapshot(report)
        await persist_rule_report_state(report)
        await refresh_rule_review_message(report)
        if report.review_channel_id is not None:
            channel = await fetch_messageable_channel(report.review_channel_id)
            if channel is not None:
                try:
                    await sync_rule_report_detail_messages(channel, report)
                except discord.Forbidden:
                    pass
                except discord.HTTPException:
                    pass
        await interaction.followup.send(
            "That message was already under review. I added your report to the existing SpamFighter AI review entry.",
            ephemeral=True,
        )


@app_commands.guild_only()
class AdminCog(commands.GroupCog, group_name="spamfighter", group_description="SpamFighter administration"):
    rules = app_commands.Group(name="rules", description="Manage spam rules and backups.")
    reviews = app_commands.Group(name="reviews", description="Manage AI review workflow settings and testing.")
    control = app_commands.Group(name="control", description="Manage global SpamFighter control operators and review routing.")
    violations = app_commands.Group(name="violations", description="Manage tracked spam violations.")
    commands_cfg = app_commands.Group(name="commands", description="Manage per-guild command availability.")
    allowlist = app_commands.Group(name="allowlist", description="Manage guild allowlist entries.")
    blocklists = app_commands.Group(name="blocklists", description="Manage optional domain blocklists.")
    retro = app_commands.Group(name="retro", description="Run and manage retroactive spam scans.")
    scanning = app_commands.Group(name="scanning", description="Control live message scanning.")

    def __init__(self, bot_client: SpamGuardBot) -> None:
        self.bot = bot_client

    def _available_command_names(self) -> List[str]:
        names: Set[str] = set()
        for command in self.bot.tree.walk_commands():
            qualified_name = normalize_command_name(getattr(command, "qualified_name", "") or getattr(command, "name", ""))
            if not qualified_name:
                continue
            for prefix in command_name_prefixes(qualified_name):
                names.add(prefix)
        return sorted(names)

    def _autocomplete_known_users(self, guild_id: Optional[int], current: str) -> List[app_commands.Choice[str]]:
        if guild_id is None:
            return []

        lowered = current.lower().strip()
        choices: List[app_commands.Choice[str]] = []
        for user_id, labels in LAST_KNOWN_USER_LABELS.get(guild_id, {}).items():
            labels_list = sorted(labels)
            if lowered and not any(lowered in label for label in labels_list):
                continue
            label = next((label for label in labels_list if not label.isdigit()), str(user_id))
            display = f"{label} ({user_id})"
            choices.append(app_commands.Choice(name=display[:100], value=str(user_id)))
            if len(choices) >= 25:
                break
        return choices

    @app_commands.command(name="help", description="Show what SpamFighter does and the most useful commands to start with.")
    @guild_only_check()
    async def help(self, interaction: discord.Interaction) -> None:
        assert interaction.guild is not None

        disabled_commands = sorted(get_disabled_commands_for_guild(interaction.guild.id))
        embed = base_embed(
            title="SpamFighter Help",
            color=discord.Color.blurple(),
            description=(
                "SpamFighter deletes matched spam, tracks repeat offenders, and gives staff a gated workflow for reviewing new spam patterns.\n\n"
                "Start here:\n"
                "`/spamfighter status` to check health and runtime state\n"
                "`/spamfighter reviews show-validation-channels` to review the clean-channel validation corpus\n"
                "`/spamfighter retro scan` to preview older spam before taking action\n"
                "`SpamFighter AI Report` on a message to open a staff review entry"
            ),
        )
        embed.add_field(name="Live Scanning", value="`/spamfighter scanning pause` and `/spamfighter scanning resume`", inline=False)
        embed.add_field(name="Domain Blocklists", value="`/spamfighter blocklists status`, `/spamfighter blocklists enable`, `/spamfighter blocklists disable`", inline=False)
        embed.add_field(name="Rule Management", value="`/spamfighter rules list`, `/spamfighter rules disable`, `/spamfighter rules rollback`", inline=False)
        embed.add_field(name="Validation Workflow", value="Deployments validate drafts against configured known-clean channels before publishing.", inline=False)
        embed.add_field(name="False Positives", value="`/spamfighter reviews report-false-positive` to send an incorrect match to the master review queue.", inline=False)
        embed.add_field(name="External Samples", value="`/spamfighter reviews report-new` to seed the review pipeline with spam text that was never posted in a monitored server.", inline=False)
        embed.add_field(name="Per-Guild Command Flags", value="`/spamfighter commands list`, `/spamfighter commands disable`, `/spamfighter commands enable`", inline=False)
        if disabled_commands:
            embed.add_field(
                name="Disabled In This Guild",
                value=format_embed_field_value("\n".join(disabled_commands), limit=700, codeblock=True),
                inline=False,
            )
        await respond_ephemeral(interaction, embed=embed)

    @app_commands.command(name="status", description="Show runtime status.")
    @guild_only_check()
    @control_admin_only()
    async def status(self, interaction: discord.Interaction) -> None:
        now = utcnow()
        day_bucket = current_usage_bucket("daily", now.strftime("%Y-%m-%d"))
        month_bucket = current_usage_bucket("monthly", now.strftime("%Y-%m"))
        open_rule_reviews = sum(1 for report in RULE_REPORTS.values() if report.status not in {"approved", "denied"})
        gateway_latency = f"{bot.latency * 1000:.1f}ms" if bot.latency == bot.latency and bot.latency >= 0 else "Unknown"
        sync_mode = f"dev_guild:{DEV_GUILD_ID}" if USE_GUILD_SYNC_FOR_DEV and DEV_GUILD_ID else "global"
        last_match_summary = (
            f"Reason: {STATE.last_match_reason}\n"
            f"Time: {pretty_ts(STATE.last_match_at, 'F')}"
            if STATE.last_match_reason and STATE.last_match_at
            else "No recent match recorded."
        )
        embed = base_embed(
            title="Bot Status",
            color=discord.Color.green() if not STATE.paused else discord.Color.yellow(),
            description=(
                f"Paused: `{STATE.paused}`\n"
                f"Environment: `{APP_ENV}`\n"
                f"Instance Role: `{current_instance_role()}`\n"
                f"Dry Run: `{SPAM_DRY_RUN}`"
            ),
        )
        embed.add_field(
            name="Lifecycle",
            value=(
                f"Started: {pretty_ts(STATE.started_at, 'F')}\n"
                f"Uptime: {pretty_ts(STATE.started_at, 'R')}\n"
                f"Pause Changed: {pretty_ts(STATE.pause_changed_at, 'F')}"
            ),
            inline=False,
        )
        embed.add_field(
            name="Activity",
            value=(
                f"Guild Count: {len(self.bot.guilds)}\n"
                f"Scanned Messages: {STATE.scanned_messages}\n"
                f"Matched Messages: {STATE.matched_messages}\n"
                f"Deleted Messages: {STATE.deleted_messages}\n"
                f"Open Rule Reviews: {open_rule_reviews}"
            ),
            inline=False,
        )
        embed.add_field(
            name="Gateway",
            value=(
                f"Last Seen: {pretty_ts(STATE.last_gateway_event_at, 'R') if STATE.last_gateway_event_at else 'None'}\n"
                f"Latency: {gateway_latency}\n"
                f"Startup Sync: {self.bot.startup_command_sync_performed}\n"
                f"Command Sync Mode: {sync_mode}"
            ),
            inline=False,
        )
        embed.add_field(name="Last Match", value=last_match_summary, inline=False)
        embed.add_field(
            name="Configuration",
            value=(
                f"Guild Allowlist Enabled: {GUILD_ALLOWLIST_ENABLED}\n"
                f"Review Channel: {f'<#{REPORT_REVIEW_CHANNEL_ID}>' if REPORT_REVIEW_CHANNEL_ID else 'Not configured'}\n"
                f"Validation Master Guild: {describe_guild_for_logs(REPORT_VALIDATION_MASTER_GUILD_ID) if REPORT_VALIDATION_MASTER_GUILD_ID else 'Per-source guild'}\n"
                f"State DB: `{STATE_DB_PATH}`\n"
                f"Healthcheck: {f'http://{HEALTHCHECK_HOST}:{HEALTHCHECK_PORT}/readyz' if HEALTHCHECK_PORT > 0 else 'Disabled'}"
            ),
            inline=False,
        )
        embed.add_field(
            name="Domain Blocklists",
            value=build_loaded_domain_blocklist_summary(),
            inline=False,
        )
        embed.add_field(
            name="AI Configuration",
            value=(
                f"Model: `{OPENAI_RULE_MODEL}`\n"
                f"Key Configured: `{bool(OPENAI_API_KEY)}`\n"
                f"Output Cap: `{AI_REVIEW_MAX_COMPLETION_TOKENS}`"
            ),
            inline=False,
        )
        embed.add_field(
            name="AI Daily Usage",
            value=(
                f"Requests: {day_bucket['requests']}/{AI_REVIEW_DAILY_REQUEST_LIMIT}\n"
                f"Prompt Tokens: {day_bucket['prompt_tokens']}/{AI_REVIEW_DAILY_INPUT_TOKEN_LIMIT}\n"
                f"Completion Tokens: {day_bucket['completion_tokens']}/{AI_REVIEW_DAILY_OUTPUT_TOKEN_LIMIT}"
            ),
            inline=False,
        )
        embed.add_field(
            name="AI Monthly Usage",
            value=(
                f"Requests: {month_bucket['requests']}/{AI_REVIEW_MONTHLY_REQUEST_LIMIT}\n"
                f"Prompt Tokens: {month_bucket['prompt_tokens']}/{AI_REVIEW_MONTHLY_INPUT_TOKEN_LIMIT}\n"
                f"Completion Tokens: {month_bucket['completion_tokens']}/{AI_REVIEW_MONTHLY_OUTPUT_TOKEN_LIMIT}"
            ),
            inline=False,
        )

        await respond_ephemeral(interaction, embed=embed)
        await audit_control_action(interaction, "status", "Viewed runtime status")

    @reviews.command(name="report-new", description="Submit external spam text into the review pipeline without moderating a user.")
    @app_commands.describe(
        text="Paste the external spam text or test message to review",
        draft_with_ai="Whether SpamFighter should immediately request an AI rule draft",
    )
    @guild_only_check()
    @guild_admin_or_super_user_only()
    async def report_new(
        self,
        interaction: discord.Interaction,
        text: app_commands.Range[str, 1, 4000],
        draft_with_ai: bool = True,
    ) -> None:
        assert interaction.guild is not None

        if REPORT_REVIEW_CHANNEL_ID is None:
            await respond_ephemeral(
                interaction,
                content="SpamFighter review is not configured yet. Ask a control admin to set the review channel first.",
            )
            return

        message_text = str(text).strip()
        if not message_text:
            await respond_ephemeral(interaction, content="Provide the external spam text you want reviewed.")
            return

        remember_user_identity(interaction.guild.id, interaction.user)
        prepared = classify_manual_spam_report_content(
            guild_id=interaction.guild.id,
            message_text=message_text,
        )
        matched, reason, normalized = prepared
        if matched:
            embed = base_embed(
                title="Sample Already Covered",
                color=discord.Color.blurple(),
                description="That text already matches SpamFighter's current rules, so I did not open a new review.",
            )
            embed.add_field(name="Current Match", value=reason or "unknown", inline=True)
            embed.add_field(
                name="Normalized Preview",
                value=format_embed_field_value(normalized or "[empty]", limit=700, codeblock=True),
                inline=False,
            )
            await respond_ephemeral(interaction, embed=embed)
            await audit_control_action(
                interaction,
                "report-new",
                f"Skipped manual sample because it already matched current rules ({reason or 'unknown'}).",
            )
            return

        created = False
        await interaction.response.defer(ephemeral=True)
        try:
            report, created = await create_or_update_manual_rule_report(
                interaction,
                message_text=message_text,
                prepared=prepared,
            )
            await refresh_rule_reporter_snapshot(report)
            await persist_rule_report_state(report)
            if created:
                await post_rule_report(report)
            else:
                await refresh_rule_review_message(report)
                if report.review_channel_id is not None:
                    channel = await fetch_messageable_channel(report.review_channel_id)
                    if channel is not None:
                        try:
                            await sync_rule_report_detail_messages(channel, report)
                        except discord.Forbidden:
                            pass
                        except discord.HTTPException:
                            pass
        except Exception as exc:
            if "report" in locals() and created:
                async with RULE_REPORTS_LOCK:
                    RULE_REPORTS.pop(report.report_id, None)
                    if report.cluster_key:
                        RULE_REPORTS_BY_CLUSTER.pop(
                            rule_report_cluster_map_key(report.source_guild_id, report.cluster_key),
                            None,
                        )
                await remove_rule_report_state(report.report_id)
            await interaction.followup.send(f"Failed to submit the manual spam sample: {exc}", ephemeral=True)
            await audit_error(interaction.guild, "Manual Spam Sample Failed", "report_new", exc)
            return

        ai_status = "Not requested."
        if draft_with_ai:
            if not OPENAI_API_KEY:
                ai_status = "OpenAI is not configured, so the review was created without starting a draft."
            elif (
                report.status == "proposal_ready"
                and report.suggestion is not None
                and report.suggestion.decision == "propose"
            ):
                ai_status = "A draft was already ready on this review."
            elif report.task is not None or report.status == "analyzing":
                ai_status = "An AI draft was already running for this review."
            elif report.status in {"approved", "denied"}:
                ai_status = f"The existing review is already {report.status}, so no new draft was started."
            else:
                report.status = "reported"
                report.suggestion = None
                report.suggestion_error = None
                report.proposal_generated_at = None
                report.validation_status = "not_run"
                report.validation_summary = ""
                report.validation_hit_lines = []
                report.validation_ran_at = None
                report.validation_bypassed_by = None
                report.validation_months = 0
                report.validation_channel_ids = []
                report.ai_precheck_matched = False
                report.ai_precheck_reason = ""
                report.ai_precheck_normalized = ""
                report.ai_ignore_approved_by = None
                report.last_generated_by = interaction.user.id
                update_rule_report_cluster_map(report)
                await persist_rule_report_state(report)
                await refresh_rule_review_message(report)
                report.task = asyncio.create_task(
                    run_rule_suggestion_with_notification(report.report_id, interaction),
                    name=f"spamfighter-rule-review-{report.report_id}",
                )
                await log_rule_review_action(
                    report,
                    action="generated",
                    actor_id=interaction.user.id,
                    details="Started AI rule drafting from `/spamfighter reviews report-new`.",
                )
                ai_status = "AI rule drafting started. A follow-up message will be sent when the draft finishes."

        embed = base_embed(
            title="External Spam Sample Submitted" if created else "External Spam Sample Merged",
            color=discord.Color.green() if created else discord.Color.blurple(),
            description="The text was sent into the SpamFighter review pipeline. No user was warned, muted, kicked, or banned.",
        )
        embed.add_field(name="Report ID", value=report.report_id, inline=True)
        embed.add_field(name="Review Entry", value="Created" if created else "Merged into existing review", inline=True)
        embed.add_field(name="Current Match", value=f"{report.current_matched} ({report.current_reason or 'none'})", inline=True)
        embed.add_field(name="AI Draft", value=format_embed_field_value(ai_status, limit=700), inline=False)
        embed.add_field(name="Review Channel", value=f"<#{REPORT_REVIEW_CHANNEL_ID}>", inline=False)
        await interaction.followup.send(embed=embed, ephemeral=True)
        await audit_control_action(
            interaction,
            "report-new",
            (
                f"Submitted manual spam sample report {report.report_id} created={created} "
                f"auto_draft={draft_with_ai} current_match={report.current_matched} "
                f"reason={report.current_reason or 'none'}"
            ),
        )

    @control.command(name="add-admin", description="Add a global SpamFighter control admin user ID to config.toml.")
    @app_commands.describe(user_ref="Mention, raw user ID, or a remembered username/display name")
    @guild_only_check()
    @control_admin_only()
    async def add_admin(self, interaction: discord.Interaction, user_ref: str) -> None:
        assert interaction.guild is not None

        user_id = resolve_user_id_from_ref(interaction.guild.id, user_ref)
        if user_id is None:
            await respond_ephemeral(
                interaction,
                content="Could not resolve that user. Use a mention, raw user ID, or pick a suggested autocomplete value.",
            )
            return

        member = interaction.guild.get_member(user_id)
        if member is not None:
            remember_user_identity(interaction.guild.id, member)

        already_present = user_id in CONTROL_ADMIN_USER_IDS
        await interaction.response.defer(ephemeral=True)
        try:
            await add_control_admin_user(user_id)
        except Exception as exc:
            await interaction.followup.send(f"Failed to add that control admin: {exc}", ephemeral=True)
            await audit_error(interaction.guild, "Add Control Admin Failed", "add_admin", exc)
            return

        embed = base_embed(
            title="Control Admin Updated",
            color=discord.Color.green() if not already_present else discord.Color.blurple(),
            description=(
                "The user was added to `control.admin_user_ids` and applied immediately."
                if not already_present
                else "That user was already present in `control.admin_user_ids`."
            ),
        )
        embed.add_field(name="User", value=format_known_user(interaction.guild.id, user_id), inline=False)
        embed.add_field(name="User ID", value=f"`{user_id}`", inline=True)
        embed.add_field(name="Total Control Admins", value=str(len(CONTROL_ADMIN_USER_IDS)), inline=True)
        await interaction.followup.send(embed=embed, ephemeral=True)
        await audit_control_action(interaction, "add-admin", f"Added control admin user {user_id} already_present={already_present}")

    @add_admin.autocomplete("user_ref")
    async def add_admin_autocomplete(
        self,
        interaction: discord.Interaction,
        current: str,
    ) -> List[app_commands.Choice[str]]:
        return self._autocomplete_known_users(interaction.guild.id if interaction.guild else None, current)

    @control.command(name="add-super-user", description="Add a global SpamFighter super-user ID to config.toml.")
    @app_commands.describe(user_ref="Mention, raw user ID, or a remembered username/display name")
    @guild_only_check()
    @control_admin_only()
    async def add_super_user(self, interaction: discord.Interaction, user_ref: str) -> None:
        assert interaction.guild is not None

        user_id = resolve_user_id_from_ref(interaction.guild.id, user_ref)
        if user_id is None:
            await respond_ephemeral(
                interaction,
                content="Could not resolve that user. Use a mention, raw user ID, or pick a suggested autocomplete value.",
            )
            return

        member = interaction.guild.get_member(user_id)
        if member is not None:
            remember_user_identity(interaction.guild.id, member)

        already_present = user_id in CONTROL_SUPER_USER_IDS
        await interaction.response.defer(ephemeral=True)
        try:
            await add_control_super_user(user_id)
        except Exception as exc:
            await interaction.followup.send(f"Failed to add that super-user: {exc}", ephemeral=True)
            await audit_error(interaction.guild, "Add Super User Failed", "add_super_user", exc)
            return

        embed = base_embed(
            title="Super User Updated",
            color=discord.Color.green() if not already_present else discord.Color.blurple(),
            description=(
                "The user was added to `control.super_user_ids` and applied immediately."
                if not already_present
                else "That user was already present in `control.super_user_ids`."
            ),
        )
        embed.add_field(name="User", value=format_known_user(interaction.guild.id, user_id), inline=False)
        embed.add_field(name="User ID", value=f"`{user_id}`", inline=True)
        embed.add_field(name="Total Super Users", value=str(len(CONTROL_SUPER_USER_IDS)), inline=True)
        await interaction.followup.send(embed=embed, ephemeral=True)
        await audit_control_action(interaction, "add-super-user", f"Added super user {user_id} already_present={already_present}")

    @add_super_user.autocomplete("user_ref")
    async def add_super_user_autocomplete(
        self,
        interaction: discord.Interaction,
        current: str,
    ) -> List[app_commands.Choice[str]]:
        return self._autocomplete_known_users(interaction.guild.id if interaction.guild else None, current)

    @reviews.command(name="report-false-positive", description="Forward a false-positive moderation case to the master review channel.")
    @app_commands.describe(
        message_text="Paste the message text that was incorrectly matched or deleted",
        user_ref="Optional author mention or raw user ID when the original message is already gone",
        message_link="Optional Discord message link if the original message still exists",
        notes="Optional staff notes explaining why this was a false positive",
    )
    @guild_only_check()
    @guild_admin_or_super_user_only()
    async def report_false_positive(
        self,
        interaction: discord.Interaction,
        message_text: str,
        user_ref: Optional[str] = None,
        message_link: Optional[str] = None,
        notes: Optional[str] = None,
    ) -> None:
        assert interaction.guild is not None

        if REPORT_REVIEW_CHANNEL_ID is None:
            await respond_ephemeral(interaction, content="SpamFighter review is not configured yet. Ask a control admin to set the review channel first.")
            return

        source_message: Optional[discord.Message] = None
        source_author_id: Optional[int] = None
        source_author_label = ""

        if message_link:
            try:
                source_message = await fetch_message_from_ref(message_link)
            except ValueError as exc:
                await respond_ephemeral(interaction, content=str(exc))
                return

            source_guild = getattr(source_message, "guild", None)
            if source_guild is None or source_guild.id != interaction.guild.id:
                await respond_ephemeral(
                    interaction,
                    content="For safety, false-positive reports must point to a message in this same guild. If the original message is gone, use `user_ref` plus the pasted message text instead.",
                )
                return

            remember_user_identity(interaction.guild.id, source_message.author)
            source_author_id = source_message.author.id
            source_author_label = format_known_user(interaction.guild.id, source_author_id)

        if source_author_id is None and user_ref:
            resolved_user_id = resolve_user_id_from_ref(interaction.guild.id, user_ref)
            if resolved_user_id is None:
                await respond_ephemeral(
                    interaction,
                    content="Could not resolve `user_ref`. Use a mention, raw user ID, or pick a suggested autocomplete value.",
                )
                return
            source_author_id = resolved_user_id
            source_author_label = format_known_user(interaction.guild.id, source_author_id)

        if source_author_id is None:
            await respond_ephemeral(
                interaction,
                content="Provide either a valid `message_link` from this guild or a `user_ref` so the review can identify who was affected.",
            )
            return

        await interaction.response.defer(ephemeral=True)
        try:
            report = await create_false_positive_rule_report(
                interaction,
                message_text=message_text,
                source_author_id=source_author_id,
                source_author_label=source_author_label,
                notes=notes or "",
                message_link=message_link or "",
                source_message=source_message,
            )
            await refresh_rule_reporter_snapshot(report)
            async with RULE_REPORTS_LOCK:
                RULE_REPORTS[report.report_id] = report
            await persist_rule_report_state(report)
            await post_rule_report(report)
        except Exception as exc:
            async with RULE_REPORTS_LOCK:
                RULE_REPORTS.pop(getattr(report, "report_id", ""), None)
            if "report" in locals():
                await remove_rule_report_state(report.report_id)
            await interaction.followup.send(f"Failed to submit the false-positive review: {exc}", ephemeral=True)
            await audit_error(interaction.guild, "False Positive Report Failed", "report_false_positive", exc)
            return

        embed = base_embed(
            title="False Positive Submitted",
            color=discord.Color.green(),
            description="The case was forwarded to the SpamFighter master review channel for staff review.",
        )
        embed.add_field(name="Report ID", value=report.report_id, inline=True)
        embed.add_field(name="Source Guild", value=f"{interaction.guild.name} (`{interaction.guild.id}`)", inline=False)
        embed.add_field(name="Reported User", value=format_known_user(interaction.guild.id, source_author_id), inline=False)
        embed.add_field(name="Matched Current Rules", value=f"{report.current_matched} ({report.current_reason or 'none'})", inline=True)
        embed.add_field(name="Review Channel", value=f"<#{REPORT_REVIEW_CHANNEL_ID}>", inline=False)
        await interaction.followup.send(embed=embed, ephemeral=True)
        await audit_control_action(
            interaction,
            "report-false-positive",
            (
                f"Submitted false-positive review {report.report_id} for guild {interaction.guild.id} "
                f"user={source_author_id} matched={report.current_matched} reason={report.current_reason or 'none'}"
            ),
        )

    @report_false_positive.autocomplete("user_ref")
    async def report_false_positive_autocomplete(
        self,
        interaction: discord.Interaction,
        current: str,
    ) -> List[app_commands.Choice[str]]:
        return self._autocomplete_known_users(interaction.guild.id if interaction.guild else None, current)

    @commands_cfg.command(name="list", description="Show which slash commands are disabled for this guild.")
    @guild_only_check()
    @guild_admin_or_super_user_only()
    async def list_disabled_commands(self, interaction: discord.Interaction) -> None:
        assert interaction.guild is not None

        disabled_commands = sorted(get_disabled_commands_for_guild(interaction.guild.id))
        embed = base_embed(
            title="Disabled Commands",
            color=discord.Color.blurple(),
            description="These command flags apply only to this guild.",
        )
        embed.add_field(name="Guild", value=f"{interaction.guild.name} (`{interaction.guild.id}`)", inline=False)
        embed.add_field(
            name="Disabled",
            value=format_embed_field_value("\n".join(disabled_commands) or "None", limit=700, codeblock=True),
            inline=False,
        )
        await respond_ephemeral(interaction, embed=embed)

    @commands_cfg.command(name="disable", description="Disable a SpamFighter command or command group for this guild.")
    @app_commands.describe(command_name="Example: spamfighter retro scan, spamfighter retro, or spamfighter reviews")
    @guild_only_check()
    @guild_admin_or_super_user_only()
    async def disable_command(self, interaction: discord.Interaction, command_name: str) -> None:
        assert interaction.guild is not None

        normalized_name = normalize_command_name(command_name)
        if not normalized_name:
            await respond_ephemeral(interaction, content="Provide a command name such as `spamfighter retro scan` or `spamfighter reviews`.")
            return
        if normalized_name == "spamfighter" or normalized_name.startswith("spamfighter commands"):
            await respond_ephemeral(interaction, content="The SpamFighter command-management commands cannot be disabled from within the guild.")
            return
        if normalized_name not in self._available_command_names():
            await respond_ephemeral(interaction, content="I could not find that command name. Use autocomplete or `/spamfighter commands list` to review what is already disabled.")
            return

        await set_disabled_guild_command(interaction.guild.id, normalized_name, disabled=True)
        await respond_ephemeral(interaction, content=f"`/{normalized_name}` is now disabled for this guild.")
        await audit_control_action(interaction, "commands-disable", f"Disabled command `{normalized_name}` for guild {interaction.guild.id}")

    @commands_cfg.command(name="enable", description="Re-enable a previously disabled SpamFighter command for this guild.")
    @app_commands.describe(command_name="The exact command or command group to re-enable")
    @guild_only_check()
    @guild_admin_or_super_user_only()
    async def enable_command(self, interaction: discord.Interaction, command_name: str) -> None:
        assert interaction.guild is not None

        normalized_name = normalize_command_name(command_name)
        if not normalized_name:
            await respond_ephemeral(interaction, content="Provide the exact command name you want to re-enable.")
            return

        await set_disabled_guild_command(interaction.guild.id, normalized_name, disabled=False)
        await respond_ephemeral(interaction, content=f"`/{normalized_name}` is enabled again for this guild.")
        await audit_control_action(interaction, "commands-enable", f"Enabled command `{normalized_name}` for guild {interaction.guild.id}")

    @disable_command.autocomplete("command_name")
    async def disable_command_autocomplete(
        self,
        interaction: discord.Interaction,
        current: str,
    ) -> List[app_commands.Choice[str]]:
        current = normalize_command_name(current)
        choices: List[app_commands.Choice[str]] = []
        for command_name in self._available_command_names():
            if command_name == "spamfighter" or command_name.startswith("spamfighter commands"):
                continue
            if current and current not in command_name:
                continue
            choices.append(app_commands.Choice(name=command_name[:100], value=command_name))
            if len(choices) >= 25:
                break
        return choices

    @enable_command.autocomplete("command_name")
    async def enable_command_autocomplete(
        self,
        interaction: discord.Interaction,
        current: str,
    ) -> List[app_commands.Choice[str]]:
        guild_id = interaction.guild.id if interaction.guild else None
        if guild_id is None:
            return []
        current = normalize_command_name(current)
        disabled_commands = sorted(get_disabled_commands_for_guild(guild_id))
        choices: List[app_commands.Choice[str]] = []
        for command_name in disabled_commands:
            if current and current not in command_name:
                continue
            choices.append(app_commands.Choice(name=command_name[:100], value=command_name))
            if len(choices) >= 25:
                break
        return choices

    @app_commands.command(name="open-reviews", description="Show pending spam rule reviews.")
    @app_commands.describe(
        limit="How many open reviews to show (1-10)",
        server="Optional target guild ID. Leave empty to use this server.",
    )
    @guild_only_check()
    @guild_admin_or_super_user_only()
    async def open_reviews(
        self,
        interaction: discord.Interaction,
        limit: app_commands.Range[int, 1, 10] = 5,
        server: Optional[str] = None,
    ) -> None:
        assert interaction.guild is not None

        is_global_control = is_control_operator(interaction.user.id)
        target_guild_id = resolve_guild_id_from_ref(server)
        if target_guild_id is None:
            target_guild = interaction.guild
        else:
            target_guild = self.bot.get_guild(target_guild_id)
            if target_guild is None:
                await respond_ephemeral(interaction, content="I could not find a guild with that ID in this bot session.")
                return
            if target_guild.id != interaction.guild.id and not is_global_control:
                await respond_ephemeral(
                    interaction,
                    content="You can only view another guild's review queue if you are a configured control admin or super-user.",
                )
                return

        reports = [
            report
            for report in RULE_REPORTS.values()
            if report.status not in {"approved", "denied"} and report.source_guild_id == target_guild.id
        ]
        reports.sort(key=lambda item: (item.last_reported_at, item.created_at), reverse=True)

        if not reports:
            await respond_ephemeral(
                interaction,
                content=f"No open rule reviews are currently queued for `{target_guild.name}`.",
            )
            return

        status_counts: Dict[str, int] = defaultdict(int)
        for report in reports:
            status_counts[report.status] += 1

        lines: List[str] = []
        for report in reports[:limit]:
            review_guild_id = report.review_guild_id
            if review_guild_id is None and report.review_channel_id:
                review_channel = self.bot.get_channel(report.review_channel_id)
                review_guild = getattr(review_channel, "guild", None)
                review_guild_id = getattr(review_guild, "id", None)
            review_url = build_discord_message_url(
                review_guild_id or report.source_guild_id,
                report.review_channel_id or 0,
                report.review_message_id or 0,
            )
            review_link = f"[review]({review_url})" if review_url else "review:n/a"
            source_url = report.sample_jump_urls[0] if report.sample_jump_urls else report.source_jump_url
            source_link = f"[source]({source_url})" if source_url else "source:n/a"
            lines.append(
                f"`{report.report_id}` | {suggestion_status_label(report)} | reports={report.report_count} | "
                f"reason={report.current_reason or 'none'} | {review_link} | {source_link}"
            )

        embed = base_embed(
            title="Open Spam Rule Reviews",
            color=discord.Color.blurple(),
            description="\n".join(lines),
        )
        embed.add_field(name="Guild", value=f"{target_guild.name} (`{target_guild.id}`)", inline=False)
        embed.add_field(name="Open Reviews", value=str(len(reports)), inline=True)
        embed.add_field(
            name="Status Breakdown",
            value=", ".join(f"{key}={value}" for key, value in sorted(status_counts.items())) or "None",
            inline=False,
        )
        if len(reports) > limit:
            embed.set_footer(text=f"Showing {limit} of {len(reports)} open reviews.")

        await respond_ephemeral(interaction, embed=embed)
        await audit_control_action(
            interaction,
            "open-reviews",
            f"Viewed {len(reports)} open reviews for guild {target_guild.id} (limit={limit})",
        )

    @app_commands.command(name="preview-ai-prompt", description="Preview the exact redacted AI prompt for a rule review without calling OpenAI.")
    @app_commands.describe(report_id="The reported message ID / review ID to preview")
    @guild_only_check()
    @guild_admin_or_super_user_only()
    async def preview_ai_prompt(self, interaction: discord.Interaction, report_id: str) -> None:
        assert interaction.guild is not None

        report = RULE_REPORTS.get(report_id.strip())
        if report is None:
            await respond_ephemeral(interaction, content="That review report ID was not found.")
            return
        if is_false_positive_report(report):
            await respond_ephemeral(interaction, content="False-positive reviews do not currently generate an AI deployment prompt.")
            return

        if not user_can_review_rule_changes_for_report(report, user_id=interaction.user.id):
            await respond_ephemeral(
                interaction,
                content="You can only preview this AI prompt if you can manage the source guild, the master review guild, or you are a configured control operator.",
            )
            return

        system_prompt = OPENAI_RULE_SYSTEM_PROMPT
        user_prompt = build_openai_rule_prompt(report)
        system_chars = len(system_prompt)
        user_chars = len(user_prompt)
        total_chars = system_chars + user_chars
        estimated_tokens = estimate_ai_input_tokens(system_prompt) + estimate_ai_input_tokens(user_prompt)
        estimated_cost_lines = build_ai_cost_estimate_lines(estimated_tokens)

        summary = base_embed(
            title="AI Prompt Preview",
            color=discord.Color.blurple(),
            description="This is the exact redacted prompt currently generated locally. No OpenAI request was made.",
        )
        summary.add_field(name="Report ID", value=report.report_id, inline=True)
        summary.add_field(name="Model", value=OPENAI_RULE_MODEL, inline=True)
        summary.add_field(name="Status", value=suggestion_status_label(report), inline=True)
        summary.add_field(name="System Prompt Chars", value=str(system_chars), inline=True)
        summary.add_field(name="User Prompt Chars", value=str(user_chars), inline=True)
        summary.add_field(name="Estimated Input Tokens", value=str(estimated_tokens), inline=True)
        summary.add_field(name="Estimated AI Cost", value="\n".join(estimated_cost_lines), inline=False)
        summary.add_field(name="Source Guild", value=f"{report.source_guild_name} (`{report.source_guild_id}`)", inline=False)
        summary.add_field(name="Current Match", value=f"{report.current_matched} ({report.current_reason or 'none'})", inline=False)
        summary.set_footer(text=f"Approx total chars: {total_chars}")

        preview_embeds: List[discord.Embed] = [summary]
        preview_embeds.extend(build_text_embeds("AI System Prompt", system_prompt, discord.Color.gold()))
        preview_embeds.extend(build_text_embeds("AI User Prompt", user_prompt, discord.Color.blurple()))

        await interaction.response.defer(ephemeral=True)
        for batch in batch_embeds(preview_embeds):
            await interaction.followup.send(
                embeds=batch,
                ephemeral=True,
                allowed_mentions=discord.AllowedMentions.none(),
            )

        await audit_control_action(
            interaction,
            "preview-ai-prompt",
            f"Previewed AI prompt for report {report.report_id} in guild {report.source_guild_id}",
        )

    @app_commands.command(name="test-message", description="Test text against the spam detector.")
    @app_commands.describe(text="Paste the message text to test")
    @guild_only_check()
    @control_admin_only()
    async def test_message(self, interaction: discord.Interaction, text: str) -> None:
        matched, reason, normalized = classify_spam(text)
        domain_match: Optional[DomainBlocklistMatch] = None
        if not matched and interaction.guild is not None:
            matched, reason, normalized, domain_match = classify_text_for_guild_domain_blocklists(text, interaction.guild.id)

        embed = base_embed(
            title="Spam Test Result",
            color=discord.Color.red() if matched else discord.Color.green(),
        )
        embed.add_field(name="Matched", value=str(matched), inline=True)
        embed.add_field(name="Reason", value=reason or "none", inline=True)
        embed.add_field(name="Length", value=str(len(text)), inline=True)
        if domain_match is not None:
            embed.add_field(name="Blocklist", value=format_domain_blocklist_label(domain_match.blocklist_key), inline=True)
            embed.add_field(name="Matched Host", value=domain_match.matched_host, inline=True)
            embed.add_field(name="Blocked Host", value=domain_match.blocked_host, inline=True)
        embed.add_field(name="Original", value=f"```{escape_codeblock(limit_text(text, 900)[0])}```", inline=False)
        embed.add_field(name="Normalized", value=f"```{escape_codeblock(limit_text(normalized, 900)[0])}```", inline=False)

        await respond_ephemeral(interaction, embed=embed)
        await audit_control_action(interaction, "test-message", f"Matched={matched}, reason={reason or 'none'}")

    @reviews.command(name="regression-check", description="Run a dry-run regression check on recent messages in this guild.")
    @app_commands.describe(
        per_channel="Max recent messages to sample per readable channel",
        max_channels="Max channels to sample in this guild",
        compare_toml="Also compare TOML-vs-Postgres behavior if Postgres rules backend is enabled",
        show_matches="Include matched message details in this private response",
        max_match_details="Maximum number of matched message detail lines",
        show_message_preview="Send separate private preview messages for matched items",
        check_image_hashes="Also compute and evaluate known image hashes for attachments (slower)",
    )
    @guild_only_check()
    @control_admin_only()
    async def regression_check(
        self,
        interaction: discord.Interaction,
        per_channel: app_commands.Range[int, 5, 200] = 25,
        max_channels: app_commands.Range[int, 1, 100] = 8,
        compare_toml: bool = True,
        show_matches: bool = False,
        max_match_details: app_commands.Range[int, 1, 25] = 10,
        show_message_preview: bool = False,
        check_image_hashes: bool = False,
    ) -> None:
        assert interaction.guild is not None
        await interaction.response.defer(ephemeral=True)

        channels_scanned = 0
        messages_scanned = 0
        matches = 0
        skipped_channels: List[str] = []
        errors: List[str] = []
        behavior_mismatches = 0
        match_details: List[str] = []
        match_previews: List[Tuple[str, str, str, str, str]] = []
        hash_scans = 0
        toml_config: Optional[SpamRulesConfig] = None
        if compare_toml and is_spam_rules_postgres_enabled():
            try:
                toml_config = _parse_spam_rules_from_toml_path(SPAM_RULES_PATH)
            except Exception as exc:
                errors.append(f"TOML parse failed: {exc}")

        for channel in iter_message_history_channels(interaction.guild):
            if channels_scanned >= max_channels:
                break
            perms = channel.permissions_for(interaction.guild.me) if interaction.guild.me else None
            if not perms or not perms.view_channel or not perms.read_message_history:
                skipped_channels.append(f"{channel.id}:no_permission")
                continue
            channels_scanned += 1
            try:
                count = 0
                async for message in channel.history(limit=per_channel, oldest_first=False):
                    if is_exempt_message(message):
                        continue
                    messages_scanned += 1
                    count += 1
                    image_hashes_for_msg = (
                        await compute_message_image_hashes(message)
                        if check_image_hashes
                        else []
                    )
                    matched_pg, reason_pg, normalized_pg = classify_candidate_content_and_media(
                        content=message.content or "",
                        media_indicators=render_message_media_indicators(message),
                        image_hashes=image_hashes_for_msg,
                    )
                    if check_image_hashes:
                        hash_scans += 1
                    if matched_pg:
                        matches += 1
                        if show_matches and len(match_details) < max_match_details:
                            jump_url = getattr(message, "jump_url", "")
                            line = f"{format_channel_scan_label(channel)} | {reason_pg or 'unknown'}"
                            if jump_url:
                                line = f"{line} | {jump_url}"
                            match_details.append(line)
                        if show_message_preview and len(match_previews) < max_match_details:
                            jump_url = getattr(message, "jump_url", "")
                            snippet = (message.content or "").strip()
                            normalized_snippet = (normalized_pg or "").strip()
                            if len(snippet) > 3500:
                                snippet = snippet[:3500].rstrip() + "..."
                            if len(normalized_snippet) > 3500:
                                normalized_snippet = normalized_snippet[:3500].rstrip() + "..."
                            match_previews.append(
                                (
                                    format_channel_scan_label(channel),
                                    reason_pg or "unknown",
                                    jump_url,
                                    snippet or "(no text content)",
                                    normalized_snippet or "(no normalized content)",
                                )
                            )
                    if toml_config is not None:
                        pg_config = SPAM_RULES
                        toml_result = _evaluate_behavior_message(
                            toml_config,
                            message.content or "",
                            media_indicators=render_message_media_indicators(message),
                            image_hashes=image_hashes_for_msg,
                        )
                        pg_result = _evaluate_behavior_message(
                            pg_config,
                            message.content or "",
                            media_indicators=render_message_media_indicators(message),
                            image_hashes=image_hashes_for_msg,
                        )
                        if (
                            toml_result["matched"] != pg_result["matched"]
                            or toml_result["reason"] != pg_result["reason"]
                            or toml_result["action"] != pg_result["action"]
                        ):
                            behavior_mismatches += 1
                    if count >= per_channel:
                        break
            except discord.Forbidden:
                skipped_channels.append(f"{channel.id}:forbidden")
            except discord.HTTPException as exc:
                skipped_channels.append(f"{channel.id}:http_error")
                errors.append(f"channel {channel.id} history failed: {exc}")

        embed = base_embed(
            title="Regression Check (Dry Run)",
            color=discord.Color.blurple(),
            description="Compared current rule behavior on recent messages without taking moderation actions.",
        )
        embed.add_field(name="Guild", value=f"{interaction.guild.name} (`{interaction.guild.id}`)", inline=False)
        embed.add_field(name="Channels Scanned", value=str(channels_scanned), inline=True)
        embed.add_field(name="Messages Scanned", value=str(messages_scanned), inline=True)
        embed.add_field(name="Postgres Matches", value=str(matches), inline=True)
        embed.add_field(name="TOML vs Postgres Mismatches", value=str(behavior_mismatches), inline=True)
        embed.add_field(name="Skipped Channels", value=str(len(skipped_channels)), inline=True)
        embed.add_field(name="Errors", value=str(len(errors)), inline=True)
        embed.add_field(name="Image Hash Scan", value=f"{check_image_hashes} ({hash_scans} messages hashed)", inline=True)
        requested_scan = int(per_channel) * int(max_channels)
        if requested_scan >= 3000:
            embed.add_field(
                name="Scan Load Warning",
                value=f"Requested scan window is {requested_scan} messages. This may run longer and increase rate-limit pressure.",
                inline=False,
            )
        if skipped_channels:
            embed.add_field(
                name="Skipped Detail",
                value=format_embed_field_value("\n".join(skipped_channels[:15]), limit=700, codeblock=True),
                inline=False,
            )
        if errors:
            embed.add_field(
                name="Error Detail",
                value=format_embed_field_value("\n".join(errors[:10]), limit=700, codeblock=True),
                inline=False,
            )
        if show_matches:
            if not match_details:
                embed.add_field(name="Matched Message Details", value="No matches captured in detail window.", inline=False)
            else:
                chunks: List[str] = []
                current = ""
                for line in match_details:
                    candidate = f"{current}\n{line}" if current else line
                    if len(candidate) > 950:
                        chunks.append(current)
                        current = line
                    else:
                        current = candidate
                if current:
                    chunks.append(current)
                for idx, chunk in enumerate(chunks, start=1):
                    label = "Matched Message Details" if len(chunks) == 1 else f"Matched Message Details ({idx}/{len(chunks)})"
                    embed.add_field(name=label, value=chunk, inline=False)
        if show_message_preview:
            embed.add_field(
                name="Message Preview",
                value=f"Enabled. Sent {len(match_previews)} private preview message(s).",
                inline=False,
            )
        await interaction.followup.send(embed=embed, ephemeral=True)
        if show_message_preview and match_previews:
            for idx, (channel_label, reason_label, jump_url, snippet, normalized_snippet) in enumerate(match_previews, start=1):
                preview = base_embed(
                    title=f"Regression Match Preview {idx}/{len(match_previews)}",
                    color=discord.Color.orange(),
                    description="Private dry-run preview of a matched message.",
                )
                preview.add_field(name="Channel", value=channel_label, inline=False)
                preview.add_field(name="Reason", value=reason_label, inline=True)
                preview.add_field(name="Jump URL", value=jump_url or "Unavailable", inline=False)
                preview.add_field(
                    name="Message (Original)",
                    value=format_embed_field_value(snippet, limit=1000, codeblock=True),
                    inline=False,
                )
                preview.add_field(
                    name="Message (Normalized)",
                    value=format_embed_field_value(normalized_snippet, limit=1000, codeblock=True),
                    inline=False,
                )
                await interaction.followup.send(embed=preview, ephemeral=True)
        await audit_control_action(
            interaction,
            "regression-check",
            (
                f"guild={interaction.guild.id} channels={channels_scanned} "
                f"messages={messages_scanned} pg_matches={matches} mismatches={behavior_mismatches}"
            ),
        )

    @app_commands.command(name="permissions-check", description="Check bot permissions for this guild or a specific channel.")
    @app_commands.describe(channel="Optional channel to check per-channel permissions")
    @guild_only_check()
    @control_admin_only()
    async def permissions_check(self, interaction: discord.Interaction, channel: Optional[discord.abc.GuildChannel] = None) -> None:
        assert interaction.guild is not None

        try:
            bot_member = await get_bot_member(interaction.guild)
        except discord.NotFound as exc:
            await respond_ephemeral(interaction, content="Could not resolve the bot as a guild member.")
            await audit_error(interaction.guild, "Permissions Check Failed", "permissions_check.get_bot_member", exc)
            return
        except discord.Forbidden as exc:
            await respond_ephemeral(interaction, content="Forbidden from fetching the bot member in this guild.")
            await audit_error(interaction.guild, "Permissions Check Failed", "permissions_check.get_bot_member", exc)
            return
        except discord.HTTPException as exc:
            await respond_ephemeral(interaction, content="Discord returned an HTTP error while resolving bot permissions.")
            await audit_error(interaction.guild, "Permissions Check Failed", "permissions_check.get_bot_member", exc)
            return

        embed = build_permission_embed(guild=interaction.guild, channel=channel, member=bot_member)
        await respond_ephemeral(interaction, embed=embed)
        target = f"channel {channel.id}" if channel is not None else "guild"
        await audit_control_action(interaction, "permissions-check", f"Checked permissions for {target}")

    @app_commands.command(name="setup", description="Open the guided setup dashboard for this guild.")
    @guild_only_check()
    @guild_admin_or_super_user_only()
    async def setup(self, interaction: discord.Interaction) -> None:
        assert interaction.guild is not None
        embed = build_guild_settings_embed(interaction.guild)
        embed.description = (
            "Use the controls below to create/select audit and enforcement channels, "
            "toggle deletion/escalation, set thresholds, and optionally enable domain blocklists. "
            "Every change is saved immediately."
        )
        view = SetupDashboardView(actor_id=interaction.user.id, guild_id=interaction.guild.id)
        await respond_ephemeral(interaction, embed=embed, view=view)
        await audit_control_action(interaction, "setup-open", f"Opened setup dashboard for guild {interaction.guild.id}")

    @app_commands.command(name="guild-config", description="Show the effective configuration for this guild.")
    @guild_only_check()
    @guild_admin_or_super_user_only()
    async def guild_config(self, interaction: discord.Interaction) -> None:
        assert interaction.guild is not None
        embed = build_guild_settings_embed(interaction.guild)
        await respond_ephemeral(interaction, embed=embed)

    @app_commands.command(name="set-enforcement-channel", description="Set the enforcement log channel for this guild.")
    @app_commands.describe(channel="The text channel to use for enforcement logs")
    @guild_only_check()
    @guild_admin_or_super_user_only()
    async def set_enforcement_channel(self, interaction: discord.Interaction, channel: discord.TextChannel) -> None:
        assert interaction.guild is not None
        await interaction.response.defer(ephemeral=True)

        try:
            await write_guild_channels(interaction.guild.id, enforcement_channel_id=channel.id)
        except Exception as exc:
            await interaction.followup.send(f"Failed to update config.toml: {exc}", ephemeral=True)
            await audit_error(interaction.guild, "Set Enforcement Channel Failed", "set_enforcement_channel", exc)
            return

        embed = base_embed(
            title="Enforcement Channel Updated",
            color=discord.Color.green(),
            description="The enforcement log channel was updated in config.toml and reloaded.",
        )
        embed.add_field(name="Guild", value=f"{interaction.guild.name} (`{interaction.guild.id}`)", inline=False)
        embed.add_field(name="Channel", value=f"{channel.mention} (`{channel.id}`)", inline=False)
        embed.add_field(name="Updated By", value=f"{interaction.user.mention} (`{interaction.user.id}`)", inline=False)

        await interaction.followup.send(embed=embed, ephemeral=True)
        await audit_control_action(
            interaction,
            "set-enforcement-channel",
            f"Set enforcement channel for guild {interaction.guild.id} to {channel.id}",
        )

    @app_commands.command(name="set-audit-channel", description="Set the audit log channel for this guild.")
    @app_commands.describe(channel="The text channel to use for audit logs")
    @guild_only_check()
    @guild_admin_or_super_user_only()
    async def set_audit_channel(self, interaction: discord.Interaction, channel: discord.TextChannel) -> None:
        assert interaction.guild is not None
        await interaction.response.defer(ephemeral=True)

        try:
            await write_guild_channels(interaction.guild.id, audit_channel_id=channel.id)
        except Exception as exc:
            await interaction.followup.send(f"Failed to update config.toml: {exc}", ephemeral=True)
            await audit_error(interaction.guild, "Set Audit Channel Failed", "set_audit_channel", exc)
            return

        embed = base_embed(
            title="Audit Channel Updated",
            color=discord.Color.green(),
            description="The audit log channel was updated in config.toml and reloaded.",
        )
        embed.add_field(name="Guild", value=f"{interaction.guild.name} (`{interaction.guild.id}`)", inline=False)
        embed.add_field(name="Channel", value=f"{channel.mention} (`{channel.id}`)", inline=False)
        embed.add_field(name="Updated By", value=f"{interaction.user.mention} (`{interaction.user.id}`)", inline=False)

        await interaction.followup.send(embed=embed, ephemeral=True)
        await audit_control_action(
            interaction,
            "set-audit-channel",
            f"Set audit channel for guild {interaction.guild.id} to {channel.id}",
        )

    @app_commands.command(name="set-escalation", description="Enable or disable escalation for this guild.")
    @app_commands.describe(enabled="Whether escalation should be enabled")
    @guild_only_check()
    @guild_admin_or_super_user_only()
    async def set_escalation(self, interaction: discord.Interaction, enabled: bool) -> None:
        assert interaction.guild is not None
        await interaction.response.defer(ephemeral=True)

        try:
            await write_guild_moderation_overrides(interaction.guild.id, enable_escalation=enabled)
        except Exception as exc:
            await interaction.followup.send(f"Failed to update escalation: {exc}", ephemeral=True)
            await audit_error(interaction.guild, "Set Escalation Failed", "set_escalation", exc)
            return

        moderation = resolve_moderation_settings(interaction.guild.id)
        embed = base_embed(
            title="Escalation Updated",
            color=discord.Color.green(),
            description="Guild-specific escalation settings were updated.",
        )
        embed.add_field(name="Guild", value=f"{interaction.guild.name} (`{interaction.guild.id}`)", inline=False)
        embed.add_field(name="Escalation Enabled", value=str(moderation.enable_escalation), inline=True)
        embed.add_field(name="Updated By", value=f"{interaction.user.mention} (`{interaction.user.id}`)", inline=False)

        await interaction.followup.send(embed=embed, ephemeral=True)
        await audit_control_action(
            interaction,
            "set-escalation",
            f"Set enable_escalation={enabled} for guild {interaction.guild.id}",
        )

    @scanning.command(name="set-deletion", description="Enable or disable spam message deletion for this guild.")
    @app_commands.describe(enabled="Whether matched spam messages should be deleted in this guild")
    @guild_only_check()
    @guild_admin_or_super_user_only()
    async def set_deletion(self, interaction: discord.Interaction, enabled: bool) -> None:
        assert interaction.guild is not None
        await interaction.response.defer(ephemeral=True)

        try:
            await write_guild_moderation_overrides(interaction.guild.id, enable_deletion=enabled)
        except Exception as exc:
            await interaction.followup.send(f"Failed to update deletion setting: {exc}", ephemeral=True)
            await audit_error(interaction.guild, "Set Deletion Failed", "set_deletion", exc)
            return

        moderation = resolve_moderation_settings(interaction.guild.id)
        embed = base_embed(
            title="Deletion Setting Updated",
            color=discord.Color.green(),
            description="Guild-specific message deletion behavior was updated.",
        )
        embed.add_field(name="Guild", value=f"{interaction.guild.name} (`{interaction.guild.id}`)", inline=False)
        embed.add_field(name="Deletion Enabled", value=str(moderation.enable_deletion), inline=True)
        embed.add_field(name="Updated By", value=f"{interaction.user.mention} (`{interaction.user.id}`)", inline=False)

        await interaction.followup.send(embed=embed, ephemeral=True)
        await audit_control_action(
            interaction,
            "set-deletion",
            f"Set enable_deletion={enabled} for guild {interaction.guild.id}",
        )

    @app_commands.command(name="set-thresholds", description="Set guild-specific moderation thresholds.")
    @app_commands.describe(
        warn_threshold="Warn threshold",
        timeout_threshold="Timeout threshold",
        kick_threshold="Kick threshold",
        ban_threshold="Ban threshold",
        timeout_minutes="Timeout length in minutes",
    )
    @guild_only_check()
    @guild_admin_or_super_user_only()
    async def set_thresholds(
        self,
        interaction: discord.Interaction,
        warn_threshold: int,
        timeout_threshold: int,
        kick_threshold: int,
        ban_threshold: int,
        timeout_minutes: int = 60,
    ) -> None:
        assert interaction.guild is not None
        await interaction.response.defer(ephemeral=True)

        try:
            await write_guild_moderation_overrides(
                interaction.guild.id,
                warn_threshold=warn_threshold,
                timeout_threshold=timeout_threshold,
                kick_threshold=kick_threshold,
                ban_threshold=ban_threshold,
                timeout_minutes=timeout_minutes,
            )
        except Exception as exc:
            await interaction.followup.send(f"Failed to update thresholds: {exc}", ephemeral=True)
            await audit_error(interaction.guild, "Set Thresholds Failed", "set_thresholds", exc)
            return

        moderation = resolve_moderation_settings(interaction.guild.id)
        embed = base_embed(
            title="Thresholds Updated",
            color=discord.Color.green(),
            description="Guild-specific moderation thresholds were updated.",
        )
        embed.add_field(name="Warn", value=str(moderation.warn_threshold), inline=True)
        embed.add_field(name="Timeout", value=str(moderation.timeout_threshold), inline=True)
        embed.add_field(name="Kick", value=str(moderation.kick_threshold), inline=True)
        embed.add_field(name="Ban", value=str(moderation.ban_threshold), inline=True)
        embed.add_field(name="Timeout Minutes", value=str(moderation.timeout_minutes), inline=True)
        embed.add_field(name="Updated By", value=f"{interaction.user.mention} (`{interaction.user.id}`)", inline=False)

        await interaction.followup.send(embed=embed, ephemeral=True)
        await audit_control_action(
            interaction,
            "set-thresholds",
            f"Updated thresholds for guild {interaction.guild.id}",
        )

    @app_commands.command(name="set-global-allowlist", description="Enable or disable the guild allowlist globally.")
    @app_commands.describe(enabled="Whether the bot should enforce allowed_guild_ids")
    @guild_only_check()
    @control_admin_only()
    async def set_global_allowlist(self, interaction: discord.Interaction, enabled: bool) -> None:
        await interaction.response.defer(ephemeral=True)

        try:
            await set_global_guild_allowlist_enabled(enabled)
        except Exception as exc:
            await interaction.followup.send(f"Failed to update allowlist mode: {exc}", ephemeral=True)
            await audit_error(interaction.guild, "Set Global Allowlist Failed", "set_global_allowlist", exc)
            return

        embed = base_embed(
            title="Global Guild Allowlist Updated",
            color=discord.Color.green(),
            description="The global guild allowlist mode was updated in config.toml and reloaded.",
        )
        embed.add_field(name="Enabled", value=str(GUILD_ALLOWLIST_ENABLED), inline=True)
        embed.add_field(name="Allowed Guild Count", value=str(len(ALLOWED_GUILD_IDS)), inline=True)
        await interaction.followup.send(embed=embed, ephemeral=True)
        await audit_control_action(interaction, "set-global-allowlist", f"Set guild allowlist enabled={enabled}")

    @allowlist.command(name="add", description="Add a guild ID to allowed_guild_ids and reload config.toml.")
    @app_commands.describe(guild_id="Guild ID to add to the allowlist")
    @guild_only_check()
    @control_admin_only()
    async def allowlist_add(self, interaction: discord.Interaction, guild_id: int) -> None:
        await interaction.response.defer(ephemeral=True)

        if guild_id <= 0:
            await interaction.followup.send("Guild ID must be a positive integer.", ephemeral=True)
            return

        if guild_id in ALLOWED_GUILD_IDS:
            await interaction.followup.send(f"`{guild_id}` is already in `allowed_guild_ids`.", ephemeral=True)
            return

        try:
            await add_allowed_guild_id(guild_id)
        except Exception as exc:
            await interaction.followup.send(f"Failed to add guild to allowlist: {exc}", ephemeral=True)
            await audit_error(interaction.guild, "Allowlist Add Failed", "allowlist_add", exc)
            return

        embed = base_embed(
            title="Guild Allowlisted",
            color=discord.Color.green(),
            description="The guild was added to config.toml and applied without restarting the bot.",
        )
        embed.add_field(name="Guild ID", value=f"`{guild_id}`", inline=True)
        embed.add_field(name="Allowlist Enabled", value=str(GUILD_ALLOWLIST_ENABLED), inline=True)
        embed.add_field(name="Allowed Guild Count", value=str(len(ALLOWED_GUILD_IDS)), inline=True)
        await interaction.followup.send(embed=embed, ephemeral=True)
        await audit_control_action(interaction, "allowlist-add", f"Added guild {guild_id} to allowed_guild_ids")

    @blocklists.command(name="status", description="Show loaded domain blocklists and which ones are enabled for this guild.")
    @guild_only_check()
    @guild_admin_or_super_user_only()
    async def blocklists_status(self, interaction: discord.Interaction) -> None:
        assert interaction.guild is not None

        await refresh_domain_blocklists()
        enabled_for_guild = get_enabled_domain_blocklists_for_guild(interaction.guild.id)
        embed = base_embed(
            title="Domain Blocklists",
            color=discord.Color.blurple(),
            description=(
                "Large site lists are preloaded into memory and only checked against extracted URLs, "
                "so they stay cheap on the message hot path."
            ),
        )
        embed.add_field(name="Guild", value=f"{interaction.guild.name} (`{interaction.guild.id}`)", inline=False)
        embed.add_field(name="Enabled In This Guild", value=format_enabled_domain_blocklists(interaction.guild.id), inline=False)

        for key in DOMAIN_BLOCKLIST_KEYS:
            count = len(LOADED_DOMAIN_BLOCKLISTS.get(key, frozenset()))
            loaded_at = DOMAIN_BLOCKLIST_LAST_LOADED_AT.get(key)
            value = (
                f"Enabled Here: `{key in enabled_for_guild}`\n"
                f"Loaded Domains: `{count}`\n"
                f"Last Loaded: {pretty_ts(loaded_at, 'R') if loaded_at else 'never'}"
            )
            embed.add_field(name=format_domain_blocklist_label(key), value=value, inline=False)

        await respond_ephemeral(interaction, embed=embed)

    @blocklists.command(name="enable", description="Enable one optional domain blocklist for this guild.")
    @app_commands.describe(blocklist="Which domain blocklist to enable for this guild")
    @app_commands.choices(blocklist=[
        app_commands.Choice(name="Porn Sites", value="porn"),
        app_commands.Choice(name="Malicious Sites", value="malicious"),
        app_commands.Choice(name="Custom Sites", value="custom"),
    ])
    @guild_only_check()
    @guild_admin_or_super_user_only()
    async def blocklists_enable(self, interaction: discord.Interaction, blocklist: str) -> None:
        assert interaction.guild is not None

        blocklist_key = normalize_domain_blocklist_key(blocklist)
        await refresh_domain_blocklists()
        await set_guild_domain_blocklist_enabled(interaction.guild.id, blocklist_key, enabled=True)

        embed = base_embed(
            title="Domain Blocklist Enabled",
            color=discord.Color.green(),
            description="The selected blocklist is now active for this guild.",
        )
        embed.add_field(name="Guild", value=f"{interaction.guild.name} (`{interaction.guild.id}`)", inline=False)
        embed.add_field(name="Blocklist", value=format_domain_blocklist_label(blocklist_key), inline=True)
        embed.add_field(
            name="Loaded Domains",
            value=str(len(LOADED_DOMAIN_BLOCKLISTS.get(blocklist_key, frozenset()))),
            inline=True,
        )
        embed.add_field(name="Enabled In This Guild", value=format_enabled_domain_blocklists(interaction.guild.id), inline=False)
        await respond_ephemeral(interaction, embed=embed)
        await audit_control_action(
            interaction,
            "blocklists-enable",
            f"Enabled {blocklist_key} domain blocklist for guild {interaction.guild.id}",
        )

    @blocklists.command(name="disable", description="Disable one optional domain blocklist for this guild.")
    @app_commands.describe(blocklist="Which domain blocklist to disable for this guild")
    @app_commands.choices(blocklist=[
        app_commands.Choice(name="Porn Sites", value="porn"),
        app_commands.Choice(name="Malicious Sites", value="malicious"),
        app_commands.Choice(name="Custom Sites", value="custom"),
    ])
    @guild_only_check()
    @guild_admin_or_super_user_only()
    async def blocklists_disable(self, interaction: discord.Interaction, blocklist: str) -> None:
        assert interaction.guild is not None

        blocklist_key = normalize_domain_blocklist_key(blocklist)
        await refresh_domain_blocklists()
        await set_guild_domain_blocklist_enabled(interaction.guild.id, blocklist_key, enabled=False)

        embed = base_embed(
            title="Domain Blocklist Disabled",
            color=discord.Color.orange(),
            description="The selected blocklist is no longer active for this guild.",
        )
        embed.add_field(name="Guild", value=f"{interaction.guild.name} (`{interaction.guild.id}`)", inline=False)
        embed.add_field(name="Blocklist", value=format_domain_blocklist_label(blocklist_key), inline=True)
        embed.add_field(name="Enabled In This Guild", value=format_enabled_domain_blocklists(interaction.guild.id), inline=False)
        await respond_ephemeral(interaction, embed=embed)
        await audit_control_action(
            interaction,
            "blocklists-disable",
            f"Disabled {blocklist_key} domain blocklist for guild {interaction.guild.id}",
        )

    @blocklists.command(name="reload", description="Force a global domain-blocklist reload from disk.")
    @guild_only_check()
    @control_admin_only()
    async def blocklists_reload(self, interaction: discord.Interaction) -> None:
        await interaction.response.defer(ephemeral=True)

        try:
            counts = await refresh_domain_blocklists(force=True)
        except Exception as exc:
            await interaction.followup.send(f"Failed to reload domain blocklists: {exc}", ephemeral=True)
            await audit_error(interaction.guild, "Domain Blocklist Reload Failed", "blocklists_reload", exc)
            return

        embed = base_embed(
            title="Domain Blocklists Reloaded",
            color=discord.Color.green(),
            description="The blocklist files were reloaded from disk for this bot instance.",
        )
        for key in DOMAIN_BLOCKLIST_KEYS:
            embed.add_field(
                name=format_domain_blocklist_label(key),
                value=f"Loaded Domains: `{counts.get(key, 0)}`\nPath: `{DOMAIN_BLOCKLIST_PATHS[key]}`",
                inline=False,
            )
        await interaction.followup.send(embed=embed, ephemeral=True)
        await audit_control_action(interaction, "blocklists-reload", "Reloaded domain blocklists from disk")

    @blocklists.command(name="add-domain", description="Append one domain or URL to a global domain blocklist file and reload it.")
    @app_commands.describe(
        blocklist="Which global blocklist file to add to",
        domain_or_url="A domain like example.com or a URL like https://example.com/path",
    )
    @app_commands.choices(blocklist=[
        app_commands.Choice(name="Porn Sites", value="porn"),
        app_commands.Choice(name="Malicious Sites", value="malicious"),
        app_commands.Choice(name="Custom Sites", value="custom"),
    ])
    @guild_only_check()
    @control_admin_only()
    async def blocklists_add_domain(self, interaction: discord.Interaction, blocklist: str, domain_or_url: str) -> None:
        blocklist_key = normalize_domain_blocklist_key(blocklist)
        await interaction.response.defer(ephemeral=True)

        try:
            normalized_domain, added, counts = await add_domain_to_named_blocklist(blocklist_key, domain_or_url)
        except Exception as exc:
            await interaction.followup.send(f"Failed to add that domain to the blocklist: {exc}", ephemeral=True)
            await audit_error(interaction.guild, "Domain Blocklist Add Failed", "blocklists_add_domain", exc)
            return

        embed = base_embed(
            title="Domain Blocklist Updated",
            color=discord.Color.green() if added else discord.Color.blurple(),
            description=(
                "The domain was written to the blocklist file and reloaded."
                if added
                else "That domain was already present in the blocklist file."
            ),
        )
        embed.add_field(name="Blocklist", value=format_domain_blocklist_label(blocklist_key), inline=True)
        embed.add_field(name="Domain", value=f"`{normalized_domain}`", inline=True)
        embed.add_field(name="Added", value=str(added), inline=True)
        embed.add_field(name="Loaded Domains", value=str(counts.get(blocklist_key, 0)), inline=True)
        embed.add_field(name="Path", value=f"`{DOMAIN_BLOCKLIST_PATHS[blocklist_key]}`", inline=False)
        await interaction.followup.send(embed=embed, ephemeral=True)
        await audit_control_action(
            interaction,
            "blocklists-add-domain",
            f"Added={added} domain={normalized_domain} blocklist={blocklist_key}",
        )

    @violations.command(name="reset", description="Reset a user's spam violation counter in this server.")
    @app_commands.describe(user_ref="Mention, raw user ID, or a last-known username/display name")
    @guild_only_check()
    @guild_admin_or_super_user_only()
    async def reset_violations(self, interaction: discord.Interaction, user_ref: str) -> None:
        assert interaction.guild is not None

        guild_id = interaction.guild.id
        user_id = resolve_user_id_from_ref(guild_id, user_ref)
        if user_id is None:
            await respond_ephemeral(
                interaction,
                content="Could not resolve that user. Use a mention, raw user ID, or pick a suggested autocomplete value.",
            )
            return

        before, after = await reset_violation_count(guild_id, user_id)

        embed = base_embed(
            title="Violation Counter Reset",
            color=discord.Color.green(),
            description="The user's spam violation counter was reset for this guild.",
        )
        embed.add_field(name="User", value=format_known_user(guild_id, user_id), inline=False)
        embed.add_field(name="Guild", value=f"{interaction.guild.name} (`{guild_id}`)", inline=False)
        embed.add_field(name="Before", value=str(before), inline=True)
        embed.add_field(name="After", value=str(after), inline=True)
        embed.add_field(name="Reset By", value=f"{interaction.user.mention} (`{interaction.user.id}`)", inline=False)

        await respond_ephemeral(interaction, embed=embed)
        await audit_control_action(
            interaction,
            "reset-violations",
            f"Reset violation counter for user {user_id} in guild {guild_id} (before={before}, after={after})",
        )

    @reset_violations.autocomplete("user_ref")
    async def reset_violations_autocomplete(
        self,
        interaction: discord.Interaction,
        current: str,
    ) -> List[app_commands.Choice[str]]:
        guild_id = interaction.guild.id if interaction.guild else None
        if guild_id is None:
            return []

        current = current.lower()
        choices: List[app_commands.Choice[str]] = []
        for user_id, labels in LAST_KNOWN_USER_LABELS.get(guild_id, {}).items():
            labels_list = sorted(labels)
            if current and not any(current in label for label in labels_list):
                continue

            label = next((label for label in labels_list if not label.isdigit()), str(user_id))
            display = f"{label} ({user_id})"
            choices.append(app_commands.Choice(name=display[:100], value=str(user_id)))
            if len(choices) >= 25:
                break

        return choices

    @violations.command(name="reset-all", description="Reset all spam violation counters to 0 in this server.")
    @guild_only_check()
    @guild_admin_or_super_user_only()
    async def reset_all_violations(self, interaction: discord.Interaction) -> None:
        assert interaction.guild is not None

        guild_id = interaction.guild.id
        affected_users = await reset_all_violation_counts(guild_id)

        embed = base_embed(
            title="All Violation Counters Reset",
            color=discord.Color.orange(),
            description="All tracked spam violation counters were reset to 0 for this guild.",
        )
        embed.add_field(name="Guild", value=f"{interaction.guild.name} (`{guild_id}`)", inline=False)
        embed.add_field(name="Users Reset", value=str(affected_users), inline=True)
        embed.add_field(name="New Value", value="0", inline=True)
        embed.add_field(name="Reset By", value=f"{interaction.user.mention} (`{interaction.user.id}`)", inline=False)

        await respond_ephemeral(interaction, embed=embed)
        await audit_control_action(
            interaction,
            "reset-all-violations",
            f"Reset all violation counters to 0 in guild {guild_id} (users={affected_users})",
        )

    @retro.command(name="start", description="Preview or execute a spam scan across recent channel history.")
    @app_commands.describe(
        months="How many months of message history to scan (1-12)",
        execute="Leave false to preview only. Set true to delete matches and apply moderation.",
        deep_image_hash_scan="Also hash image attachments and match exact known image hashes. Slower but stronger for photo spam.",
        server="Optional target guild ID. Leave empty to use this server.",
    )
    @guild_only_check()
    @guild_admin_or_super_user_only()
    async def retro_scan(
        self,
        interaction: discord.Interaction,
        months: int,
        execute: bool = False,
        deep_image_hash_scan: bool = False,
        server: Optional[str] = None,
    ) -> None:
        global RETRO_SCAN
        assert interaction.guild is not None

        if months < 1 or months > RETRO_SCAN_MAX_MONTHS:
            await respond_ephemeral(
                interaction,
                content=f"`months` must be between 1 and {RETRO_SCAN_MAX_MONTHS}.",
            )
            return
        if execute and SPAM_DRY_RUN:
            await respond_ephemeral(
                interaction,
                content="Retro scans cannot run in execute mode while `spam_dry_run` is enabled. Turn dry-run off first or run a preview scan.",
            )
            return

        is_global_control = is_control_operator(interaction.user.id)
        target_guild_id = resolve_guild_id_from_ref(server)
        if target_guild_id is None:
            target_guild = interaction.guild
        else:
            target_guild = self.bot.get_guild(target_guild_id)
            if target_guild is None:
                await respond_ephemeral(
                    interaction,
                    content="I could not find a guild with that ID in this bot session.",
                )
                return
            if target_guild.id != interaction.guild.id and not is_global_control:
                await respond_ephemeral(
                    interaction,
                    content="You can only target another guild if you are a configured control admin or super-user.",
                )
                return

        if RETRO_SCAN.running:
            if RETRO_SCAN.guild_id not in (None, target_guild.id) and not is_global_control:
                await respond_ephemeral(
                    interaction,
                    content="A retro scan is already running elsewhere. Try again after it finishes.",
                )
                return

            embed = build_retro_scan_embed(RETRO_SCAN)
            await respond_ephemeral(
                interaction,
                content="A retro scan is already running. Use `/spamfighter retro status` to follow it or `/spamfighter retro cancel` to stop it.",
                embed=embed,
            )
            return

        if execute:
            confirm_view = RetroExecuteConfirmView(
                actor_id=interaction.user.id,
                target_guild_id=target_guild.id,
                months=months,
                deep_image_hash_scan=deep_image_hash_scan,
            )
            embed = base_embed(
                title="Confirm Retro Execute",
                color=discord.Color.orange(),
                description=(
                    "Retro execute will delete matched messages when possible and apply retroactive moderation. "
                    "Confirm below if you want to start it."
                ),
            )
            embed.add_field(name="Guild", value=f"{target_guild.name} (`{target_guild.id}`)", inline=False)
            embed.add_field(name="Months", value=str(months), inline=True)
            embed.add_field(name="Deep Image Hashing", value=str(deep_image_hash_scan), inline=True)
            await respond_ephemeral(interaction, embed=embed, view=confirm_view)
            return

        try:
            scan = await start_retro_scan_request(
                target_guild=target_guild,
                requested_by=interaction.user.id,
                months=months,
                execute=False,
                deep_image_hash_scan=deep_image_hash_scan,
            )
        except RuntimeError as exc:
            await respond_ephemeral(interaction, content=str(exc))
            return
        embed = build_retro_scan_embed(scan)
        embed.description = "Retro scan started in preview mode. It will only report what would happen. Use `/spamfighter retro status` to check progress."
        if deep_image_hash_scan:
            embed.description += " Exact known image hashes will also be checked during this scan."

        await respond_ephemeral(interaction, embed=embed)
        await audit_control_action(
            interaction,
            "retro-scan",
            f"Started retro scan for target guild {target_guild.id} from guild {interaction.guild.id} months={months} mode=preview deep_image_hash_scan={deep_image_hash_scan}",
        )

    @retro.command(name="validate-clean", description="Scan known-clean channels for potential false positives.")
    @app_commands.describe(
        months="How many months of message history to scan (1-12)",
        channel_1="A known-clean text or voice-channel chat to validate",
        channel_2="Optional second known-clean text or voice-channel chat",
        channel_3="Optional third known-clean text or voice-channel chat",
        deep_image_hash_scan="Also hash image attachments and match exact known image hashes. Slower but useful for photo-only checks.",
    )
    @guild_only_check()
    @guild_admin_or_super_user_only()
    async def retro_validate_clean(
        self,
        interaction: discord.Interaction,
        months: int,
        channel_1: discord.abc.GuildChannel,
        channel_2: Optional[discord.abc.GuildChannel] = None,
        channel_3: Optional[discord.abc.GuildChannel] = None,
        deep_image_hash_scan: bool = False,
    ) -> None:
        global RETRO_SCAN
        assert interaction.guild is not None

        if months < 1 or months > RETRO_SCAN_MAX_MONTHS:
            await respond_ephemeral(
                interaction,
                content=f"`months` must be between 1 and {RETRO_SCAN_MAX_MONTHS}.",
            )
            return

        if RETRO_SCAN.running:
            embed = build_retro_scan_embed(RETRO_SCAN)
            await respond_ephemeral(
                interaction,
                content="A retro scan is already running. Use `/spamfighter retro status` to follow it or `/spamfighter retro cancel` to stop it first.",
                embed=embed,
            )
            return

        selected_channels = [channel for channel in (channel_1, channel_2, channel_3) if channel is not None and is_message_history_channel(channel)]
        if len(selected_channels) != len([channel for channel in (channel_1, channel_2, channel_3) if channel is not None]):
            await respond_ephemeral(interaction, content="Choose only text channels or voice-channel chats for validation.")
            return
        selected_channel_ids = trim_unique_int_list([channel.id for channel in selected_channels], limit=10)
        scope_label = ", ".join(channel.mention for channel in selected_channels)

        try:
            scan = await start_retro_scan_request(
                target_guild=interaction.guild,
                requested_by=interaction.user.id,
                months=months,
                execute=False,
                deep_image_hash_scan=deep_image_hash_scan,
                validation_mode=True,
                scope_label=scope_label,
                selected_channel_ids=selected_channel_ids,
            )
        except RuntimeError as exc:
            await respond_ephemeral(interaction, content=str(exc))
            return

        embed = build_retro_scan_embed(scan)
        embed.description = (
            "Known-clean validation scan started. Any matches found here should be reviewed as potential false positives before approving new rules."
        )
        if deep_image_hash_scan:
            embed.description += " Exact known image hashes will also be checked during this scan."

        await respond_ephemeral(interaction, embed=embed)
        await audit_control_action(
            interaction,
            "retro-validate-clean",
            f"Started clean-channel validation scan in guild {interaction.guild.id} months={months} channels={selected_channel_ids} deep_image_hash_scan={deep_image_hash_scan}",
        )

    @retro.command(name="status", description="Show the current or most recent retro scan status.")
    @app_commands.describe(server="Optional target guild ID. Leave empty to use this server.")
    @guild_only_check()
    @guild_admin_or_super_user_only()
    async def retro_scan_status(self, interaction: discord.Interaction, server: Optional[str] = None) -> None:
        assert interaction.guild is not None

        is_global_control = is_control_operator(interaction.user.id)
        target_guild_id = resolve_guild_id_from_ref(server)
        if target_guild_id is None:
            target_guild = interaction.guild
        else:
            target_guild = self.bot.get_guild(target_guild_id)
            if target_guild is None:
                await respond_ephemeral(
                    interaction,
                    content="I could not find a guild with that ID in this bot session.",
                )
                return
            if target_guild.id != interaction.guild.id and not is_global_control:
                await respond_ephemeral(
                    interaction,
                    content="You can only view another guild's retro scan status if you are a configured control admin or super-user.",
                )
                return

        if RETRO_SCAN.guild_id is None:
            await respond_ephemeral(interaction, content="No retro scan has been started in this bot process yet.")
            return

        if RETRO_SCAN.guild_id != target_guild.id:
            if RETRO_SCAN.running:
                await respond_ephemeral(interaction, content="No retro scan is currently running for that guild.")
            else:
                await respond_ephemeral(interaction, content="No recent retro scan is available for that guild.")
            return

        await respond_ephemeral(interaction, embed=build_retro_scan_embed(RETRO_SCAN))

    @retro.command(name="cancel", description="Cancel the currently running retro scan.")
    @app_commands.describe(server="Optional target guild ID. Leave empty to use this server.")
    @guild_only_check()
    @guild_admin_or_super_user_only()
    async def retro_scan_cancel(self, interaction: discord.Interaction, server: Optional[str] = None) -> None:
        assert interaction.guild is not None

        is_global_control = is_control_operator(interaction.user.id)
        target_guild_id = resolve_guild_id_from_ref(server)
        if target_guild_id is None:
            target_guild = interaction.guild
        else:
            target_guild = self.bot.get_guild(target_guild_id)
            if target_guild is None:
                await respond_ephemeral(
                    interaction,
                    content="I could not find a guild with that ID in this bot session.",
                )
                return
            if target_guild.id != interaction.guild.id and not is_global_control:
                await respond_ephemeral(
                    interaction,
                    content="You can only cancel another guild's retro scan if you are a configured control admin or super-user.",
                )
                return

        if not RETRO_SCAN.running or RETRO_SCAN.task is None:
            await respond_ephemeral(interaction, content="There is no retro scan running right now.")
            return

        if RETRO_SCAN.guild_id != target_guild.id:
            await respond_ephemeral(interaction, content="There is no running retro scan for that guild.")
            return

        RETRO_SCAN.cancelled = True
        RETRO_SCAN.task.cancel()

        embed = base_embed(
            title="Retro Scan Cancelling",
            color=discord.Color.orange(),
            description="The running retro scan was asked to stop. It may take a short moment to wind down cleanly.",
        )
        embed.add_field(name="Guild", value=f"{RETRO_SCAN.guild_name} (`{RETRO_SCAN.guild_id}`)", inline=False)
        embed.add_field(name="Requested By", value=f"{interaction.user.mention} (`{interaction.user.id}`)", inline=False)

        await respond_ephemeral(interaction, embed=embed)
        await audit_control_action(
            interaction,
            "retro-scan-cancel",
            f"Cancel requested for retro scan in guild {RETRO_SCAN.guild_id}",
        )

    def _guild_ref_choices(
        self,
        interaction: discord.Interaction,
        current: str,
    ) -> List[app_commands.Choice[str]]:
        if interaction.guild is None:
            return []

        current = current.lower().strip()
        guilds = self.bot.guilds if is_control_operator(interaction.user.id) else [interaction.guild]
        choices: List[app_commands.Choice[str]] = []

        for guild in sorted(guilds, key=lambda item: item.name.lower()):
            display = f"{guild.name} ({guild.id})"
            if current and current not in guild.name.lower() and current not in str(guild.id):
                continue
            choices.append(app_commands.Choice(name=display[:100], value=str(guild.id)))
            if len(choices) >= 25:
                break

        return choices

    @retro_scan.autocomplete("server")
    async def retro_scan_server_autocomplete(
        self,
        interaction: discord.Interaction,
        current: str,
    ) -> List[app_commands.Choice[str]]:
        return self._guild_ref_choices(interaction, current)

    @retro_scan_status.autocomplete("server")
    async def retro_scan_status_server_autocomplete(
        self,
        interaction: discord.Interaction,
        current: str,
    ) -> List[app_commands.Choice[str]]:
        return self._guild_ref_choices(interaction, current)

    @retro_scan_cancel.autocomplete("server")
    async def retro_scan_cancel_server_autocomplete(
        self,
        interaction: discord.Interaction,
        current: str,
    ) -> List[app_commands.Choice[str]]:
        return self._guild_ref_choices(interaction, current)

    @open_reviews.autocomplete("server")
    async def open_reviews_server_autocomplete(
        self,
        interaction: discord.Interaction,
        current: str,
    ) -> List[app_commands.Choice[str]]:
        return self._guild_ref_choices(interaction, current)

    @preview_ai_prompt.autocomplete("report_id")
    async def preview_ai_prompt_report_autocomplete(
        self,
        interaction: discord.Interaction,
        current: str,
    ) -> List[app_commands.Choice[str]]:
        guild_id = interaction.guild.id if interaction.guild else None
        if guild_id is None:
            return []

        current = current.lower().strip()
        can_cross_guild = is_control_operator(interaction.user.id)
        reports = [
            report
            for report in RULE_REPORTS.values()
            if report.status not in {"approved", "denied"}
            and (can_cross_guild or report.source_guild_id == guild_id)
        ]
        reports.sort(key=lambda item: (item.last_reported_at, item.created_at), reverse=True)

        choices: List[app_commands.Choice[str]] = []
        for report in reports:
            preview = re.sub(r"\s+", " ", report.message_content or report.media_indicators or "[no content]").strip()
            preview = limit_text(preview, 45)[0]
            label = f"{report.report_id} | {report.source_guild_name} | {preview}"
            lowered = label.lower()
            if current and current not in lowered and current not in report.report_id.lower():
                continue
            choices.append(app_commands.Choice(name=label[:100], value=report.report_id))
            if len(choices) >= 25:
                break
        return choices

    @reviews.command(name="set-validation-channels", description="Set the known-clean validation channels used before rule deployment.")
    @app_commands.describe(
        months="How many months of known-clean history to validate against (1-12)",
        channel_1="First known-clean text or voice-channel chat",
        channel_2="Optional second known-clean text or voice-channel chat",
        channel_3="Optional third known-clean text or voice-channel chat",
        channel_4="Optional fourth known-clean text or voice-channel chat",
        channel_5="Optional fifth known-clean text or voice-channel chat",
    )
    @guild_only_check()
    @guild_admin_or_super_user_only()
    async def set_fp_channels(
        self,
        interaction: discord.Interaction,
        months: app_commands.Range[int, 1, 12] = 3,
        channel_1: Optional[discord.abc.GuildChannel] = None,
        channel_2: Optional[discord.abc.GuildChannel] = None,
        channel_3: Optional[discord.abc.GuildChannel] = None,
        channel_4: Optional[discord.abc.GuildChannel] = None,
        channel_5: Optional[discord.abc.GuildChannel] = None,
    ) -> None:
        assert interaction.guild is not None

        config_guild_id = get_effective_validation_guild_id(interaction.guild.id)
        if REPORT_VALIDATION_MASTER_GUILD_ID and interaction.guild.id != config_guild_id:
            await respond_ephemeral(
                interaction,
                content=(
                    "Validation is centralized to "
                    f"{describe_guild_for_logs(config_guild_id)}. "
                    "Run this command there so the selected channels come from the master guild."
                ),
            )
            return

        requested_channels = [channel for channel in (channel_1, channel_2, channel_3, channel_4, channel_5) if channel is not None]
        selected_channels = [channel for channel in requested_channels if is_message_history_channel(channel)]
        if len(selected_channels) != len(requested_channels):
            await respond_ephemeral(interaction, content="Choose only text channels or voice-channel chats for validation.")
            return
        channel_ids = [channel.id for channel in selected_channels]
        await set_validation_channel_config(config_guild_id, months=months, channel_ids=channel_ids)

        description = (
            "Validation channels were updated. Every rule deployment now checks this known-clean regression corpus first."
            if channel_ids
            else "Validation channels were cleared for this validation guild. Rule deployment will stay blocked until you set them again."
        )
        embed = base_embed(
            title="Validation Channels Updated",
            color=discord.Color.green() if channel_ids else discord.Color.orange(),
            description=description,
        )
        embed.add_field(name="Validation Guild", value=describe_guild_for_logs(config_guild_id), inline=False)
        embed.add_field(name="Months", value=str(months), inline=True)
        embed.add_field(
            name="Channels",
            value=", ".join(channel.mention for channel in selected_channels) if selected_channels else "None configured",
            inline=False,
        )
        await respond_ephemeral(interaction, embed=embed)
        await audit_control_action(
            interaction,
            "set-validation-channels",
            f"Updated validation channel config for guild {config_guild_id} months={months} channels={channel_ids}",
        )

    @reviews.command(name="show-validation-channels", description="Show the known-clean validation channels used before rule deployment.")
    @guild_only_check()
    @guild_admin_or_super_user_only()
    async def show_fp_channels(self, interaction: discord.Interaction) -> None:
        assert interaction.guild is not None

        config_guild_id = get_effective_validation_guild_id(interaction.guild.id)
        months, channel_ids = await get_validation_channel_config(config_guild_id)
        config_guild = bot.get_guild(config_guild_id)
        channel_mentions: List[str] = []
        for channel_id in channel_ids:
            channel = get_message_history_channel(config_guild, channel_id) if config_guild is not None else None
            channel_mentions.append(channel.mention if channel is not None else f"`{channel_id}`")

        embed = base_embed(
            title="Validation Channel Config",
            color=discord.Color.blurple(),
        )
        if REPORT_VALIDATION_MASTER_GUILD_ID:
            embed.description = "All rule validations currently use the configured validation master guild."
        embed.add_field(name="Validation Guild", value=describe_guild_for_logs(config_guild_id), inline=False)
        embed.add_field(name="Months", value=str(months), inline=True)
        embed.add_field(name="Configured Channels", value=str(len(channel_ids)), inline=True)
        embed.add_field(
            name="Channels",
            value=", ".join(channel_mentions) if channel_mentions else "None configured",
            inline=False,
        )
        await respond_ephemeral(interaction, embed=embed)
        await audit_control_action(interaction, "show-validation-channels", f"Viewed validation channel config for guild {config_guild_id}")

    @reviews.command(name="test-report", description="Create a synthetic SpamFighter AI review entry for testing.")
    @app_commands.describe(
        text="Synthetic message text to send into the review pipeline",
        reporter="Optional user to attribute as the reporter",
        author="Optional user to attribute as the reported author",
        media_indicators="Optional attachment/media URLs or filenames, one blob of text",
        image_hashes="Optional comma-separated sha256 hashes for image-hash rule testing",
        affect_confidence="Whether this test report should count toward reporter confidence history",
    )
    @guild_only_check()
    @control_admin_only()
    async def test_report(
        self,
        interaction: discord.Interaction,
        text: str,
        reporter: Optional[discord.Member] = None,
        author: Optional[discord.Member] = None,
        media_indicators: Optional[str] = None,
        image_hashes: Optional[str] = None,
        affect_confidence: bool = False,
    ) -> None:
        assert interaction.guild is not None

        if REPORT_REVIEW_CHANNEL_ID is None:
            await respond_ephemeral(interaction, content="SpamFighter review is not configured yet. Set the review channel first.")
            return

        await interaction.response.defer(ephemeral=True)
        reporter_user = reporter or interaction.user
        author_user = author or interaction.user
        remember_user_identity(interaction.guild.id, reporter_user)
        remember_user_identity(interaction.guild.id, author_user)

        parsed_hashes = trim_unique_list(
            [value.strip().lower() for value in str(image_hashes or "").split(",") if value.strip()],
            limit=8,
        )
        normalized = normalize_for_scan(text or media_indicators or "")
        matched, reason, _ = classify_candidate_content_and_media(
            content=text,
            media_indicators=media_indicators or "",
            image_hashes=parsed_hashes,
        )
        report_id = f"test-{utcnow().strftime('%Y%m%d%H%M%S%f')}"
        report = RuleReportState(
            report_id=report_id,
            cluster_key=f"test:{hashlib.sha256(report_id.encode('utf-8')).hexdigest()}",
            source_guild_id=interaction.guild.id,
            source_guild_name=interaction.guild.name,
            source_channel_id=interaction.channel_id or 0,
            source_channel_label=format_channel_scan_label(interaction.channel) if interaction.channel else "test-channel",
            source_message_id=0,
            source_author_id=author_user.id,
            source_author_label=format_known_user(interaction.guild.id, author_user.id),
            source_jump_url="",
            message_content=text,
            normalized_content=normalized,
            media_indicators=media_indicators or "",
            image_hashes=parsed_hashes,
            reporter_ids={reporter_user.id},
            current_matched=matched,
            current_reason=reason,
            review_channel_id=REPORT_REVIEW_CHANNEL_ID,
        )

        if affect_confidence:
            await record_reporter_event(interaction.guild.id, reporter_user.id, report.report_id, "submitted")
        await refresh_rule_reporter_snapshot(report)

        async with RULE_REPORTS_LOCK:
            RULE_REPORTS[report.report_id] = report
            update_rule_report_cluster_map(report)
        await persist_rule_report_state(report)

        try:
            await post_rule_report(report)
        except Exception as exc:
            async with RULE_REPORTS_LOCK:
                RULE_REPORTS.pop(report.report_id, None)
                RULE_REPORTS_BY_CLUSTER.pop(
                    rule_report_cluster_map_key(report.source_guild_id, report.cluster_key),
                    None,
                )
            await remove_rule_report_state(report.report_id)
            await interaction.followup.send(f"Failed to post the synthetic review: {exc}", ephemeral=True)
            return

        embed = base_embed(
            title="Synthetic Review Created",
            color=discord.Color.green(),
            description="A synthetic SpamFighter AI review entry was posted to the review channel for testing.",
        )
        embed.add_field(name="Report ID", value=report.report_id, inline=True)
        embed.add_field(name="Matched Current Rules", value=f"{report.current_matched} ({report.current_reason or 'none'})", inline=True)
        embed.add_field(name="Affects Confidence", value=str(affect_confidence), inline=True)
        if is_trusted_reporter(interaction.guild.id, reporter_user.id):
            embed.add_field(name="Trusted Reporter", value="Yes - cooldown penalties are bypassed for this reporter.", inline=False)
        await interaction.followup.send(embed=embed, ephemeral=True)
        await audit_control_action(
            interaction,
            "test-report",
            f"Created synthetic review {report.report_id} matched={report.current_matched} affect_confidence={affect_confidence}",
        )

    @reviews.command(name="set-review-channel", description="Set the global review channel used by the SpamFighter AI Report app.")
    @app_commands.describe(channel="The text channel on your main server where reported spam AI reviews should be handled")
    @guild_only_check()
    @control_admin_only()
    async def set_review_channel(self, interaction: discord.Interaction, channel: discord.TextChannel) -> None:
        await interaction.response.defer(ephemeral=True)

        try:
            await write_review_channel(channel.id)
        except Exception as exc:
            await interaction.followup.send(f"Failed to update the review channel: {exc}", ephemeral=True)
            await audit_error(interaction.guild, "Set Review Channel Failed", "set_review_channel", exc)
            return

        embed = base_embed(
            title="Review Channel Updated",
            color=discord.Color.green(),
            description="Reported spam messages will now be forwarded to this channel for rule review.",
        )
        embed.add_field(name="Channel", value=f"{channel.mention} (`{channel.id}`)", inline=False)
        embed.add_field(name="Updated By", value=f"{interaction.user.mention} (`{interaction.user.id}`)", inline=False)

        await interaction.followup.send(embed=embed, ephemeral=True)
        await audit_control_action(interaction, "set-review-channel", f"Set the global rule review channel to {channel.id}")

    @rules.command(name="reload", description="Reload spam_rules.toml without restarting the bot.")
    @guild_only_check()
    @control_admin_only()
    async def reload_spam_rules(self, interaction: discord.Interaction) -> None:
        await interaction.response.defer(ephemeral=True)

        try:
            new_rules = load_spam_rules(SPAM_RULES_PATH)
            apply_spam_rules(new_rules)
        except FileNotFoundError as exc:
            await interaction.followup.send("spam_rules.toml was not found.", ephemeral=True)
            await audit_error(interaction.guild, "Spam Rules Reload Failed", "reload_spam_rules.load", exc)
            return
        except tomllib.TOMLDecodeError as exc:
            await interaction.followup.send(f"spam_rules.toml is invalid TOML: {exc}", ephemeral=True)
            await audit_error(interaction.guild, "Spam Rules Reload Failed", "reload_spam_rules.parse", exc)
            return
        except ValueError as exc:
            await interaction.followup.send(f"spam_rules.toml failed validation: {exc}", ephemeral=True)
            await audit_error(interaction.guild, "Spam Rules Reload Failed", "reload_spam_rules.validate", exc)
            return
        except OSError as exc:
            await interaction.followup.send(f"Could not read spam_rules.toml: {exc}", ephemeral=True)
            await audit_error(interaction.guild, "Spam Rules Reload Failed", "reload_spam_rules.read", exc)
            return

        embed = base_embed(
            title="Managed Spam Rules Reloaded",
            color=discord.Color.green(),
            description="spam_rules.toml was reloaded successfully.",
        )
        embed.add_field(name="Artifacts", value=str(len(SPAM_RULES.artifact_values)), inline=True)
        embed.add_field(name="Image Hashes", value=str(len(SPAM_RULES.image_hashes)), inline=True)
        embed.add_field(name="Custom Rules", value=str(len(SPAM_RULES.custom_rules)), inline=True)
        embed.add_field(name="Managed Hooks", value=str(len(MANAGED_RULE_HOOK_NAMES)), inline=True)
        embed.add_field(name="Review Channel", value=f"<#{REPORT_REVIEW_CHANNEL_ID}>" if REPORT_REVIEW_CHANNEL_ID else "Not configured", inline=False)
        embed.add_field(
            name="Validation Master Guild",
            value=describe_guild_for_logs(REPORT_VALIDATION_MASTER_GUILD_ID) if REPORT_VALIDATION_MASTER_GUILD_ID else "Per-source guild",
            inline=False,
        )
        embed.add_field(name="Model", value=OPENAI_RULE_MODEL, inline=True)
        embed.add_field(name="Updated By", value=f"{interaction.user.mention} (`{interaction.user.id}`)", inline=False)

        await interaction.followup.send(embed=embed, ephemeral=True)
        await audit_control_action(
            interaction,
            "reload-spam-rules",
            f"Reloaded spam_rules.toml (artifacts={len(SPAM_RULES.artifact_values)}, image_hashes={len(SPAM_RULES.image_hashes)}, custom_rules={len(SPAM_RULES.custom_rules)})",
        )

    @rules.command(name="list", description="Show managed SpamFighter rules from spam_rules.toml.")
    @app_commands.describe(category="summary, artifacts, image_hashes, hooks, or custom_rules", hook_name="Optional hook name when category=hooks")
    @app_commands.choices(category=[
        app_commands.Choice(name="summary", value="summary"),
        app_commands.Choice(name="artifacts", value="artifacts"),
        app_commands.Choice(name="image_hashes", value="image_hashes"),
        app_commands.Choice(name="hooks", value="hooks"),
        app_commands.Choice(name="custom_rules", value="custom_rules"),
    ])
    @guild_only_check()
    @control_admin_only()
    async def list_rules(self, interaction: discord.Interaction, category: str = "summary", hook_name: Optional[str] = None) -> None:
        embed = base_embed(title="Managed Spam Rules", color=discord.Color.blurple())
        embed.add_field(name="Category", value=category, inline=True)
        embed.add_field(name="Artifacts", value=str(len(SPAM_RULES.artifact_values)), inline=True)
        embed.add_field(name="Image Hashes", value=str(len(SPAM_RULES.image_hashes)), inline=True)
        embed.add_field(name="Custom Rules", value=str(len(SPAM_RULES.custom_rules)), inline=True)

        if category == "summary":
            hook_lines = [f"{name}: {len(SPAM_RULES.hooks.get(name, ()))}" for name in MANAGED_RULE_HOOK_NAMES]
            embed.add_field(name="Hooks", value=format_embed_field_value("\n".join(hook_lines), limit=500, codeblock=True), inline=False)
        elif category == "artifacts":
            values = "\n".join(SPAM_RULES.artifact_values) or "None"
            embed.add_field(name="Artifact Values", value=format_embed_field_value(values, limit=900), inline=False)
        elif category == "image_hashes":
            values = "\n".join(SPAM_RULES.image_hashes) or "None"
            embed.add_field(name="Image Hashes", value=format_embed_field_value(values, limit=900, codeblock=True), inline=False)
        elif category == "hooks":
            if hook_name:
                patterns = SPAM_RULES.hooks.get(hook_name, tuple())
                embed.add_field(name=f"Hook: {hook_name}", value=format_embed_field_value("\n".join(patterns) or "None", limit=900, codeblock=True), inline=False)
            else:
                hook_lines = [f"{name}: {len(SPAM_RULES.hooks.get(name, ()))}" for name in MANAGED_RULE_HOOK_NAMES]
                embed.add_field(name="Hook Counts", value=format_embed_field_value("\n".join(hook_lines), limit=900, codeblock=True), inline=False)
        elif category == "custom_rules":
            lines = [
                f"{rule.rule_id} | enabled={rule.enabled} | reason={rule.reason}"
                for rule in SPAM_RULES.custom_rules
            ]
            embed.add_field(name="Custom Rules", value=format_embed_field_value("\n".join(lines) or "None", limit=900, codeblock=True), inline=False)
        else:
            await respond_ephemeral(interaction, content="Unsupported category.")
            return

        await respond_ephemeral(interaction, embed=embed)
        await audit_control_action(interaction, "list-rules", f"Viewed spam rules category={category} hook={hook_name or 'none'}")

    @rules.command(name="disable", description="Disable or remove a managed spam rule entry.")
    @app_commands.describe(
        target_type="artifact, image_hash, hook, or custom_rule",
        identifier="Exact artifact value, image hash, hook regex, or custom rule ID",
        hook_name="Required when target_type=hook",
    )
    @app_commands.choices(target_type=[
        app_commands.Choice(name="artifact", value="artifact"),
        app_commands.Choice(name="image_hash", value="image_hash"),
        app_commands.Choice(name="hook", value="hook"),
        app_commands.Choice(name="custom_rule", value="custom_rule"),
    ])
    @guild_only_check()
    @control_admin_only()
    async def disable_rule(
        self,
        interaction: discord.Interaction,
        target_type: str,
        identifier: str,
        hook_name: Optional[str] = None,
    ) -> None:
        await interaction.response.defer(ephemeral=True)
        identifier = identifier.strip()
        if not identifier:
            await interaction.followup.send("`identifier` is required.", ephemeral=True)
            return

        result = {"changed": False}

        def mutator(raw: dict) -> None:
            normalize_spam_rules_raw(raw)
            if target_type == "artifact":
                values = raw.setdefault("artifacts", {}).setdefault("values", [])
                filtered = [value for value in values if str(value).strip() != identifier]
                if len(filtered) != len(values):
                    raw["artifacts"]["values"] = filtered
                    result["changed"] = True
                return

            if target_type == "image_hash":
                values = raw.setdefault("image_hashes", {}).setdefault("sha256", [])
                target_hash = identifier.lower().removeprefix("sha256:")
                filtered = [value for value in values if str(value).strip().lower() != target_hash]
                if len(filtered) != len(values):
                    raw["image_hashes"]["sha256"] = filtered
                    result["changed"] = True
                return

            if target_type == "hook":
                if hook_name not in MANAGED_RULE_HOOK_NAMES:
                    raise ValueError("A valid hook_name is required when target_type=hook.")
                values = raw.setdefault("hooks", {}).setdefault(hook_name, [])
                filtered = [value for value in values if str(value).strip() != identifier]
                if len(filtered) != len(values):
                    raw["hooks"][hook_name] = filtered
                    result["changed"] = True
                return

            if target_type == "custom_rule":
                for item in raw.setdefault("custom_rules", []):
                    if not isinstance(item, dict):
                        continue
                    if str(item.get("id", "")).strip() == identifier and bool(item.get("enabled", True)):
                        item["enabled"] = False
                        result["changed"] = True
                        return
                return

            raise ValueError("Unsupported target_type.")

        try:
            await mutate_spam_rules(mutator)
        except Exception as exc:
            await interaction.followup.send(f"Failed to disable that rule entry: {exc}", ephemeral=True)
            await audit_error(interaction.guild, "Disable Rule Failed", "disable_rule", exc)
            return

        if not result["changed"]:
            await interaction.followup.send("No matching managed rule entry was found.", ephemeral=True)
            return

        embed = base_embed(
            title="Managed Rule Updated",
            color=discord.Color.green(),
            description="The selected managed rule entry was disabled or removed.",
        )
        embed.add_field(name="Target Type", value=target_type, inline=True)
        embed.add_field(name="Identifier", value=format_embed_field_value(identifier, limit=400, codeblock=True), inline=False)
        if hook_name:
            embed.add_field(name="Hook", value=hook_name, inline=True)
        await interaction.followup.send(embed=embed, ephemeral=True)
        await audit_control_action(interaction, "disable-rule", f"Disabled target_type={target_type} identifier={identifier} hook={hook_name or 'none'}")

    @rules.command(name="history", description="List recent spam_rules.toml backups.")
    @guild_only_check()
    @control_admin_only()
    async def show_rule_history(self, interaction: discord.Interaction) -> None:
        backups = list_spam_rule_backups()
        lines = [
            f"{path.name} | {datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}"
            for path in backups[:10]
        ]
        embed = base_embed(
            title="spam_rules.toml History",
            color=discord.Color.blurple(),
            description="Newest backups first.",
        )
        embed.add_field(name="Backups", value=format_embed_field_value("\n".join(lines) or "None", limit=900, codeblock=True), inline=False)
        await respond_ephemeral(interaction, embed=embed)
        await audit_control_action(interaction, "show-rule-history", f"Viewed {len(backups)} spam rule backups")

    @rules.command(name="rollback", description="Restore spam_rules.toml from a recent backup.")
    @app_commands.describe(backup_name="The backup filename from /spamfighter rules history")
    @guild_only_check()
    @control_admin_only()
    async def rollback_rule(self, interaction: discord.Interaction, backup_name: str) -> None:
        backups = {path.name for path in list_spam_rule_backups()}
        if backup_name not in backups:
            await respond_ephemeral(interaction, content="That backup file was not found in spam_rules_history.")
            return

        embed = base_embed(
            title="Confirm Rollback",
            color=discord.Color.orange(),
            description="Restoring a spam_rules.toml backup will immediately replace the active managed rules. Confirm below if you want to proceed.",
        )
        embed.add_field(name="Backup", value=backup_name, inline=False)
        await respond_ephemeral(
            interaction,
            embed=embed,
            view=RollbackConfirmView(actor_id=interaction.user.id, backup_name=backup_name),
        )

    @list_rules.autocomplete("hook_name")
    async def list_rules_hook_autocomplete(
        self,
        interaction: discord.Interaction,
        current: str,
    ) -> List[app_commands.Choice[str]]:
        current = current.lower().strip()
        return [
            app_commands.Choice(name=hook_name, value=hook_name)
            for hook_name in MANAGED_RULE_HOOK_NAMES
            if not current or current in hook_name
        ][:25]

    @disable_rule.autocomplete("hook_name")
    async def disable_rule_hook_autocomplete(
        self,
        interaction: discord.Interaction,
        current: str,
    ) -> List[app_commands.Choice[str]]:
        current = current.lower().strip()
        return [
            app_commands.Choice(name=hook_name, value=hook_name)
            for hook_name in MANAGED_RULE_HOOK_NAMES
            if not current or current in hook_name
        ][:25]

    @disable_rule.autocomplete("identifier")
    async def disable_rule_identifier_autocomplete(
        self,
        interaction: discord.Interaction,
        current: str,
    ) -> List[app_commands.Choice[str]]:
        current = current.lower().strip()
        target_type = str(getattr(interaction.namespace, "target_type", "")).strip()
        hook_name = str(getattr(interaction.namespace, "hook_name", "")).strip()

        values: List[str]
        if target_type == "artifact":
            values = list(SPAM_RULES.artifact_values)
        elif target_type == "image_hash":
            values = [f"sha256:{value}" for value in SPAM_RULES.image_hashes]
        elif target_type == "hook" and hook_name in MANAGED_RULE_HOOK_NAMES:
            values = list(SPAM_RULES.hooks.get(hook_name, tuple()))
        elif target_type == "custom_rule":
            values = [rule.rule_id for rule in SPAM_RULES.custom_rules]
        else:
            values = []

        choices: List[app_commands.Choice[str]] = []
        for value in values:
            lowered = value.lower()
            if current and current not in lowered:
                continue
            choices.append(app_commands.Choice(name=value[:100], value=value))
            if len(choices) >= 25:
                break
        return choices

    @rollback_rule.autocomplete("backup_name")
    async def rollback_rule_backup_autocomplete(
        self,
        interaction: discord.Interaction,
        current: str,
    ) -> List[app_commands.Choice[str]]:
        current = current.lower().strip()
        choices: List[app_commands.Choice[str]] = []
        for path in list_spam_rule_backups():
            if current and current not in path.name.lower():
                continue
            choices.append(app_commands.Choice(name=path.name[:100], value=path.name))
            if len(choices) >= 25:
                break
        return choices

    @app_commands.command(name="audit-test", description="Send a test audit embed to the configured audit log channels.")
    @guild_only_check()
    @control_admin_only()
    async def audit_test(self, interaction: discord.Interaction) -> None:
        embed = base_embed(
            title="Audit Log Test",
            color=discord.Color.blurple(),
            description="This is a test audit embed.",
        )
        embed.add_field(name="Triggered By", value=f"{interaction.user.mention} (`{interaction.user.id}`)", inline=False)
        embed.add_field(name="Guild", value=f"{interaction.guild.name} (`{interaction.guild.id}`)" if interaction.guild else "DM/Unknown", inline=False)
        embed.add_field(name="When", value=pretty_ts(utcnow(), "F"), inline=False)

        await send_audit_embeds(interaction.guild, [embed])
        await respond_ephemeral(interaction, content="Sent a test embed to the configured audit log destinations.")
        await audit_control_action(interaction, "audit-test", "Sent test audit embed")

    @app_commands.command(name="reload-config", description="Reload config.toml without restarting the bot.")
    @guild_only_check()
    @control_admin_only()
    async def reload_config(self, interaction: discord.Interaction) -> None:
        await interaction.response.defer(ephemeral=True)

        try:
            new_config = load_config(str(CONFIG_PATH))
            validate_config(new_config)
            apply_config(new_config)
        except FileNotFoundError as exc:
            await interaction.followup.send("config.toml was not found.", ephemeral=True)
            await audit_error(interaction.guild, "Config Reload Failed", "reload_config.load", exc)
            return
        except tomllib.TOMLDecodeError as exc:
            await interaction.followup.send(f"config.toml is invalid TOML: {exc}", ephemeral=True)
            await audit_error(interaction.guild, "Config Reload Failed", "reload_config.parse", exc)
            return
        except ValueError as exc:
            await interaction.followup.send(f"config.toml failed validation: {exc}", ephemeral=True)
            await audit_error(interaction.guild, "Config Reload Failed", "reload_config.validate", exc)
            return
        except OSError as exc:
            await interaction.followup.send(f"Could not read config.toml: {exc}", ephemeral=True)
            await audit_error(interaction.guild, "Config Reload Failed", "reload_config.read", exc)
            return

        try:
            sync_note = await self.bot.sync_application_commands()
        except RuntimeError as exc:
            await interaction.followup.send(str(exc), ephemeral=True)
            await audit_error(interaction.guild, "Config Reload Sync Failed", "reload_config.sync", exc)
            return
        except app_commands.CommandSyncFailure as exc:
            await interaction.followup.send(f"Config reloaded, but command sync failed: {exc}", ephemeral=True)
            await audit_error(interaction.guild, "Config Reload Sync Failed", "reload_config.sync", exc)
            return
        except discord.HTTPException as exc:
            await interaction.followup.send("Config reloaded, but command sync hit a Discord HTTP error.", ephemeral=True)
            await audit_error(interaction.guild, "Config Reload Sync Failed", "reload_config.sync", exc)
            return

        if interaction.guild:
            await self.bot._enforce_guild_allowlist(interaction.guild, source="reload_config")

        embed = base_embed(
            title="Configuration Reloaded",
            color=discord.Color.green(),
            description="config.toml was reloaded successfully.",
        )
        embed.add_field(name="Environment", value=APP_ENV, inline=True)
        embed.add_field(name="Dry Run", value=str(SPAM_DRY_RUN), inline=True)
        embed.add_field(name="Ignore Admins", value=str(IGNORE_GUILD_ADMINS), inline=True)
        embed.add_field(name="Guild Allowlist Enabled", value=str(GUILD_ALLOWLIST_ENABLED), inline=True)
        embed.add_field(name="Allowed Guilds", value=str(len(ALLOWED_GUILD_IDS)), inline=True)
        embed.add_field(name="Control Admins", value=str(len(CONTROL_ADMIN_USER_IDS)), inline=True)
        embed.add_field(name="Sync Result", value=sync_note, inline=False)

        await interaction.followup.send(embed=embed, ephemeral=True)
        await audit_control_action(interaction, "reload-config", sync_note)

    @app_commands.command(name="sync-commands", description="Explicitly re-sync slash commands.")
    @guild_only_check()
    @control_admin_only()
    async def sync_commands(self, interaction: discord.Interaction) -> None:
        await interaction.response.defer(ephemeral=True)
        try:
            note = await self.bot.sync_application_commands()
        except Exception as exc:
            await interaction.followup.send(f"Command sync failed: {exc}", ephemeral=True)
            await audit_error(interaction.guild, "Manual Command Sync Failed", "sync_commands", exc)
            return

        await interaction.followup.send(note, ephemeral=True)
        await audit_control_action(interaction, "sync-commands", note)

    @scanning.command(name="pause", description="Pause message scanning.")
    @guild_only_check()
    @control_admin_only()
    async def pause(self, interaction: discord.Interaction) -> None:
        if STATE.paused:
            await respond_ephemeral(interaction, content="Bot scanning is already paused.")
            return

        STATE.paused = True
        STATE.pause_changed_at = utcnow()
        await persist_runtime_state()

        embed = base_embed(
            title="Bot Paused",
            color=discord.Color.yellow(),
            description="Message scanning has been paused.",
        )
        embed.add_field(name="Changed By", value=f"{interaction.user.mention} (`{interaction.user.id}`)", inline=False)
        embed.add_field(name="When", value=pretty_ts(STATE.pause_changed_at, "F"), inline=False)

        await respond_ephemeral(interaction, embed=embed)
        await audit_control_action(interaction, "pause", "Paused message scanning")

    @scanning.command(name="resume", description="Resume message scanning.")
    @guild_only_check()
    @control_admin_only()
    async def resume(self, interaction: discord.Interaction) -> None:
        if not STATE.paused:
            await respond_ephemeral(interaction, content="Bot scanning is already active.")
            return

        STATE.paused = False
        STATE.pause_changed_at = utcnow()
        await persist_runtime_state()

        embed = base_embed(
            title="Bot Resumed",
            color=discord.Color.green(),
            description="Message scanning has resumed.",
        )
        embed.add_field(name="Changed By", value=f"{interaction.user.mention} (`{interaction.user.id}`)", inline=False)
        embed.add_field(name="When", value=pretty_ts(STATE.pause_changed_at, "F"), inline=False)

        await respond_ephemeral(interaction, embed=embed)
        await audit_control_action(interaction, "resume", "Resumed message scanning")


# ============================================================
# App command error handler
# ============================================================

@bot.tree.error
async def on_app_command_error(interaction: discord.Interaction, error: app_commands.AppCommandError) -> None:
    if isinstance(error, GuildOnlyCommand):
        await respond_ephemeral(interaction, content="This command must be used in a guild.")
        return

    if isinstance(error, GuildCommandDisabled):
        await respond_ephemeral(interaction, content=str(error))
        await audit_error(interaction.guild, "Command Disabled For Guild", "app_command_check", error)
        return

    if isinstance(error, ControlAdminOnly):
        await respond_ephemeral(interaction, content="You are not authorized to use this command.")
        await audit_error(
            interaction.guild,
            title="Unauthorized Control Command Attempt",
            where="app_command_check",
            exc=error,
            extra={
                "User": f"{interaction.user} ({interaction.user.id})",
                "Command": interaction.command.qualified_name if interaction.command else "unknown",
            },
        )
        return

    if isinstance(error, GuildAdminOrSuperUserOnly):
        await respond_ephemeral(
            interaction,
            content="You must have Administrator or Manage Server in this guild, or be a configured control admin/super-user.",
        )
        await audit_error(
            interaction.guild,
            "Unauthorized Guild Admin Command Attempt",
            "app_command_check",
            error,
            extra={
                "User": f"{interaction.user} ({interaction.user.id})",
                "Command": interaction.command.qualified_name if interaction.command else "unknown",
            },
        )
        return

    if isinstance(error, app_commands.BotMissingPermissions):
        await respond_ephemeral(interaction, content=f"Bot is missing permissions: {', '.join(error.missing_permissions)}")
        await audit_error(interaction.guild, "Bot Missing Permissions", "app_command", error)
        return

    if isinstance(error, app_commands.MissingPermissions):
        await respond_ephemeral(interaction, content=f"You are missing permissions: {', '.join(error.missing_permissions)}")
        await audit_error(interaction.guild, "User Missing Permissions", "app_command", error)
        return

    if isinstance(error, app_commands.CommandOnCooldown):
        await respond_ephemeral(interaction, content=f"Command is on cooldown. Retry after {error.retry_after:.1f}s.")
        await audit_error(interaction.guild, "Command On Cooldown", "app_command", error)
        return

    if isinstance(error, app_commands.TransformerError):
        await respond_ephemeral(interaction, content="I couldn't understand that input. Check the command options and try again.")
        await audit_error(interaction.guild, "Transformer Error", "app_command", error)
        return

    if isinstance(error, app_commands.CommandSignatureMismatch):
        await respond_ephemeral(interaction, content="This command is out of sync. Run /spamfighter sync-commands.")
        await audit_error(interaction.guild, "Command Signature Mismatch", "app_command", error)
        return

    if isinstance(error, app_commands.CommandInvokeError):
        original = error.original

        if isinstance(original, discord.Forbidden):
            await respond_ephemeral(interaction, content="Bot is forbidden from completing that action.")
            await audit_error(interaction.guild, "Forbidden During Command", "command_invoke", original)
            return

        if isinstance(original, discord.NotFound):
            await respond_ephemeral(interaction, content="The target resource was not found.")
            await audit_error(interaction.guild, "Resource Not Found", "command_invoke", original)
            return

        if isinstance(original, discord.HTTPException):
            await respond_ephemeral(interaction, content="Discord returned an HTTP error.")
            await audit_error(interaction.guild, "Discord HTTP Exception", "command_invoke", original)
            return

        if isinstance(original, ValueError):
            await respond_ephemeral(interaction, content="A value error occurred while running that command.")
            await audit_error(interaction.guild, "Value Error", "command_invoke", original)
            return

        await respond_ephemeral(interaction, content="The command failed.")
        await audit_error(
            interaction.guild,
            "Unhandled CommandInvokeError Original Type",
            "command_invoke",
            original,
            extra={"Original Type": type(original).__name__},
        )
        return

    if isinstance(error, app_commands.CheckFailure):
        await respond_ephemeral(interaction, content="That command is blocked by its current permission or availability checks.")
        await audit_error(interaction.guild, "Command Check Failure", "app_command", error)
        return

    await respond_ephemeral(interaction, content="An application command error occurred.")
    await audit_error(
        interaction.guild,
        "Unhandled AppCommandError Type",
        "app_command",
        error,
        extra={"Error Type": type(error).__name__},
    )


# ============================================================
# Message handling
# ============================================================

async def handle_spam_message(message: discord.Message, source: str) -> None:
    if not message.guild:
        return

    if GUILD_ALLOWLIST_ENABLED and ALLOWED_GUILD_IDS and message.guild.id not in ALLOWED_GUILD_IDS:
        return

    if STATE.paused:
        return

    if is_exempt_message(message):
        return

    remember_user_identity(message.guild.id, message.author)

    STATE.scanned_messages += 1
    matched, reason, normalized = await classify_message_for_moderation_async(message)
    if not matched:
        return

    STATE.matched_messages += 1
    STATE.last_match_reason = reason
    STATE.last_match_at = utcnow()
    image_hashes = await compute_message_image_hashes(message) if message.attachments else []

    guild_id = message.guild.id
    user_id = message.author.id
    moderation_settings = resolve_moderation_settings(guild_id)
    deletion_enabled_for_guild = moderation_settings.enable_deletion
    effective_dry_run = SPAM_DRY_RUN or not deletion_enabled_for_guild
    existing_violation_count = await get_violation_count(guild_id, user_id)
    violation_count = existing_violation_count + 1
    if not effective_dry_run:
        violation_count = await increment_violation_count(guild_id, user_id)

    log.info(
        "Spam matched: source=%s guild_id=%s user_id=%s reason=%s new_count=%s",
        source,
        guild_id,
        user_id,
        reason,
        violation_count,
    )

    if effective_dry_run:
        await audit_message_deletion(
            message,
            reason,
            normalized,
            deleted=False,
            violation_count=violation_count,
            image_hashes=image_hashes,
        )
        await enforcement_log_deletion(
            message,
            reason,
            violation_count,
            deleted=False,
            image_hashes=image_hashes,
        )
        return

    try:
        await message.delete()
        STATE.deleted_messages += 1
        await audit_message_deletion(
            message,
            reason,
            normalized,
            deleted=True,
            violation_count=violation_count,
            image_hashes=image_hashes,
        )
        await enforcement_log_deletion(
            message,
            reason,
            violation_count,
            deleted=True,
            image_hashes=image_hashes,
        )
        await maybe_escalate_member(message, violation_count)
    except discord.Forbidden as exc:
        await audit_error(
            message.guild,
            "Delete Forbidden",
            "handle_spam_message.delete",
            exc,
            extra={
                "Channel": str(message.channel.id),
                "Author": str(message.author.id),
                "Reason": reason,
            },
        )
    except discord.NotFound as exc:
        await audit_error(
            message.guild,
            "Message Already Gone",
            "handle_spam_message.delete",
            exc,
            extra={
                "Channel": str(message.channel.id),
                "Author": str(message.author.id),
                "Reason": reason,
            },
        )
    except discord.HTTPException as exc:
        await audit_error(
            message.guild,
            "Delete HTTP Exception",
            "handle_spam_message.delete",
            exc,
            extra={
                "Channel": str(message.channel.id),
                "Author": str(message.author.id),
                "Reason": reason,
            },
        )


@bot.event
async def on_message(message: discord.Message) -> None:
    await handle_spam_message(message, source="create")


@bot.event
async def on_message_edit(before: discord.Message, after: discord.Message) -> None:
    before_media = render_message_media_indicators(before)
    after_media = render_message_media_indicators(after)
    if before.content == after.content and before_media == after_media:
        return
    await handle_spam_message(after, source="edit")


# ============================================================
# Health / watchdog
# ============================================================

def note_gateway_activity(source: str) -> None:
    STATE.last_gateway_event_at = utcnow()
    if source == "resumed":
        STATE.last_resumed_at = STATE.last_gateway_event_at


def build_health_status() -> Tuple[bool, bool, Dict[str, object]]:
    now = utcnow()
    startup_age = max(0.0, (now - STATE.started_at).total_seconds())
    last_event_age = None
    if STATE.last_gateway_event_at is not None:
        last_event_age = round((now - STATE.last_gateway_event_at).total_seconds(), 2)

    ready = bot.is_ready() and not bot.is_closed()
    live = not bot.is_closed()
    reasons: List[str] = []

    if not ready:
        reasons.append("discord_not_ready")

    if startup_age > HEALTHCHECK_STARTUP_GRACE_SECONDS and STATE.last_ready_at is None:
        live = False
        ready = False
        reasons.append("startup_ready_timeout")

    if last_event_age is not None and startup_age > HEALTHCHECK_STARTUP_GRACE_SECONDS and last_event_age > HEALTHCHECK_STALE_SECONDS:
        live = False
        ready = False
        reasons.append("gateway_stale")

    if (
        STATE.last_disconnect_at is not None
        and startup_age > HEALTHCHECK_STARTUP_GRACE_SECONDS
        and (
            STATE.last_resumed_at is None
            or STATE.last_resumed_at < STATE.last_disconnect_at
        )
        and (now - STATE.last_disconnect_at).total_seconds() > HEALTHCHECK_STALE_SECONDS
    ):
        live = False
        ready = False
        reasons.append("gateway_disconnected")

    latency_ms: Optional[float] = None
    if bot.latency == bot.latency and bot.latency >= 0:
        latency_ms = round(bot.latency * 1000, 2)

    payload = {
        "status": "ok" if live and ready else ("degraded" if live else "failed"),
        "live": live,
        "ready": ready,
        "instance_role": current_instance_role(),
        "startup_command_sync_performed": getattr(bot, "startup_command_sync_performed", False),
        "started_at": STATE.started_at.isoformat(),
        "last_ready_at": STATE.last_ready_at.isoformat() if STATE.last_ready_at else None,
        "last_gateway_event_at": STATE.last_gateway_event_at.isoformat() if STATE.last_gateway_event_at else None,
        "last_gateway_event_age_seconds": last_event_age,
        "last_disconnect_at": STATE.last_disconnect_at.isoformat() if STATE.last_disconnect_at else None,
        "last_resumed_at": STATE.last_resumed_at.isoformat() if STATE.last_resumed_at else None,
        "latency_ms": latency_ms,
        "paused": STATE.paused,
        "retro_scan_running": RETRO_SCAN.running,
        "open_rule_review_tasks": sum(1 for report in RULE_REPORTS.values() if report.task is not None),
        "reasons": reasons,
    }
    return live, ready, payload


async def healthcheck_request_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        request_line = await asyncio.wait_for(reader.readline(), timeout=5)
        if not request_line:
            return
        request_text = request_line.decode("utf-8", errors="replace").strip()
        parts = request_text.split(" ")
        path = parts[1] if len(parts) >= 2 else "/healthz"

        while True:
            header_line = await asyncio.wait_for(reader.readline(), timeout=5)
            if not header_line or header_line in {b"\r\n", b"\n"}:
                break

        live, ready, payload = build_health_status()
        if path == "/livez":
            ok = live
        elif path == "/readyz":
            ok = ready
        else:
            ok = live and ready

        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        status_line = b"HTTP/1.1 200 OK\r\n" if ok else b"HTTP/1.1 503 Service Unavailable\r\n"
        writer.write(status_line)
        writer.write(b"Content-Type: application/json\r\n")
        writer.write(f"Content-Length: {len(body)}\r\n".encode("ascii"))
        writer.write(b"Connection: close\r\n\r\n")
        writer.write(body)
        await writer.drain()
    except Exception as exc:
        log.warning("Healthcheck request failed: %s", exc)
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


async def start_healthcheck_server() -> None:
    global HEALTHCHECK_SERVER
    if HEALTHCHECK_SERVER is not None or HEALTHCHECK_PORT <= 0:
        return
    HEALTHCHECK_SERVER = await asyncio.start_server(
        healthcheck_request_handler,
        host=HEALTHCHECK_HOST,
        port=HEALTHCHECK_PORT,
    )
    log.info("Healthcheck server listening on %s:%s", HEALTHCHECK_HOST, HEALTHCHECK_PORT)


async def stop_healthcheck_server() -> None:
    global HEALTHCHECK_SERVER
    if HEALTHCHECK_SERVER is None:
        return
    HEALTHCHECK_SERVER.close()
    await HEALTHCHECK_SERVER.wait_closed()
    HEALTHCHECK_SERVER = None


async def watchdog_loop() -> None:
    while True:
        await asyncio.sleep(max(5, WATCHDOG_INTERVAL_SECONDS))
        live, _, payload = build_health_status()
        if not live:
            log.error("Health watchdog detected an unhealthy gateway state: %s", payload)
            await close_bot(reason="health_watchdog", exit_status=1)
            return


def start_watchdog_task() -> None:
    global WATCHDOG_TASK
    if not WATCHDOG_ENABLED or WATCHDOG_TASK is not None:
        return
    WATCHDOG_TASK = asyncio.create_task(watchdog_loop(), name="spamfighter-watchdog")


def prune_known_user_cache(*, now: Optional[datetime] = None) -> None:
    current_time = now or utcnow()
    cutoff = current_time - timedelta(seconds=max(60, KNOWN_USER_CACHE_TTL_SECONDS))
    stale_keys = [key for key, seen_at in LAST_KNOWN_USER_LAST_SEEN.items() if seen_at < cutoff]
    for guild_id, user_id in stale_keys:
        LAST_KNOWN_USER_LAST_SEEN.pop((guild_id, user_id), None)
        guild_users = LAST_KNOWN_USER_LABELS.get(guild_id)
        if guild_users is None:
            continue
        guild_users.pop(user_id, None)
        if not guild_users:
            LAST_KNOWN_USER_LABELS.pop(guild_id, None)


async def prune_old_state_records() -> None:
    now = utcnow()
    report_cutoff = (now - timedelta(days=max(1, RULE_REPORT_RETENTION_DAYS))).isoformat()
    reporter_event_cutoff = (now - timedelta(days=max(1, REPORTER_EVENT_RETENTION_DAYS))).isoformat()

    async with STATE_DB_LOCK:
        connection = await get_state_db_connection()
        await connection.execute(
            """
            DELETE FROM rule_reports
            WHERE status IN ('approved', 'denied')
              AND COALESCE(last_reported_at, created_at, '') < ?
            """,
            (report_cutoff,),
        )
        await connection.execute(
            "DELETE FROM reporter_events WHERE created_at < ?",
            (reporter_event_cutoff,),
        )
        await connection.commit()

    async with RULE_REPORTS_LOCK:
        stale_report_ids = [
            report_id
            for report_id, report in RULE_REPORTS.items()
            if report.status in {"approved", "denied"}
            and report.last_reported_at < datetime.fromisoformat(report_cutoff)
        ]
        for report_id in stale_report_ids:
            report = RULE_REPORTS.pop(report_id, None)
            if report is None:
                continue
            RULE_REPORTS_BY_MESSAGE_ID.pop(report.source_message_id, None)
            if report.cluster_key:
                RULE_REPORTS_BY_CLUSTER.pop(
                    rule_report_cluster_map_key(report.source_guild_id, report.cluster_key),
                    None,
                )

    prune_known_user_cache(now=now)
    prune_attachment_hash_cache(now=now)


async def instance_role_refresh_loop() -> None:
    while True:
        await asyncio.sleep(max(5, INSTANCE_ROLE_REFRESH_SECONDS))
        await refresh_instance_role()


def start_instance_role_task() -> None:
    global INSTANCE_ROLE_TASK
    if INSTANCE_ROLE_TASK is not None or INSTANCE_ROLE not in {"auto", "leader", "follower"}:
        return
    INSTANCE_ROLE_TASK = asyncio.create_task(
        instance_role_refresh_loop(),
        name="spamfighter-instance-role-refresh",
    )


async def state_refresh_loop() -> None:
    while True:
        await asyncio.sleep(max(5, STATE_REFRESH_INTERVAL_SECONDS))
        try:
            await load_runtime_state()
            await load_retro_scan_state(preserve_active_task=True)
            await load_disabled_guild_commands()
            await load_guild_domain_blocklist_settings()
            await refresh_domain_blocklists()
            await load_ai_usage_state()
            await load_rule_reports_state(preserve_tasks=True)
        except Exception as exc:
            log.warning("Shared-state refresh failed: %s", exc)


def start_state_refresh_task() -> None:
    global STATE_REFRESH_TASK
    if STATE_REFRESH_TASK is not None or STATE_REFRESH_INTERVAL_SECONDS <= 0:
        return
    STATE_REFRESH_TASK = asyncio.create_task(
        state_refresh_loop(),
        name="spamfighter-state-refresh",
    )


async def state_retention_loop() -> None:
    while True:
        await asyncio.sleep(max(60, STATE_RETENTION_INTERVAL_SECONDS))
        try:
            await prune_old_state_records()
        except Exception as exc:
            log.warning("State retention cleanup failed: %s", exc)


def start_state_retention_task() -> None:
    global STATE_RETENTION_TASK
    if STATE_RETENTION_TASK is not None or STATE_RETENTION_INTERVAL_SECONDS <= 0:
        return
    STATE_RETENTION_TASK = asyncio.create_task(
        state_retention_loop(),
        name="spamfighter-state-retention",
    )


# ============================================================
# Graceful shutdown
# ============================================================

async def close_state_db_connection() -> None:
    global STATE_DB_CONNECTION
    if STATE_DB_CONNECTION is not None:
        try:
            await STATE_DB_CONNECTION.close()
        except Exception:
            pass
        STATE_DB_CONNECTION = None


async def cancel_background_tasks() -> None:
    global WATCHDOG_TASK, INSTANCE_ROLE_TASK, STATE_REFRESH_TASK, STATE_RETENTION_TASK, MODERATION_LOG_TASK
    current_task = asyncio.current_task()
    tasks_to_cancel: List[asyncio.Task] = []

    if RETRO_SCAN.task is not None and RETRO_SCAN.task is not current_task:
        RETRO_SCAN.cancelled = True
        RETRO_SCAN.task.cancel()
        tasks_to_cancel.append(RETRO_SCAN.task)

    for report in RULE_REPORTS.values():
        if report.task is not None and report.task is not current_task:
            report.task.cancel()
            tasks_to_cancel.append(report.task)

    if WATCHDOG_TASK is not None and WATCHDOG_TASK is not current_task:
        WATCHDOG_TASK.cancel()
        tasks_to_cancel.append(WATCHDOG_TASK)
    if INSTANCE_ROLE_TASK is not None and INSTANCE_ROLE_TASK is not current_task:
        INSTANCE_ROLE_TASK.cancel()
        tasks_to_cancel.append(INSTANCE_ROLE_TASK)
    if STATE_REFRESH_TASK is not None and STATE_REFRESH_TASK is not current_task:
        STATE_REFRESH_TASK.cancel()
        tasks_to_cancel.append(STATE_REFRESH_TASK)
    if STATE_RETENTION_TASK is not None and STATE_RETENTION_TASK is not current_task:
        STATE_RETENTION_TASK.cancel()
        tasks_to_cancel.append(STATE_RETENTION_TASK)
    if MODERATION_LOG_TASK is not None and MODERATION_LOG_TASK is not current_task:
        MODERATION_LOG_TASK.cancel()
        tasks_to_cancel.append(MODERATION_LOG_TASK)

    if tasks_to_cancel:
        with contextlib.suppress(Exception):
            await asyncio.gather(*tasks_to_cancel, return_exceptions=True)
    WATCHDOG_TASK = None
    INSTANCE_ROLE_TASK = None
    STATE_REFRESH_TASK = None
    STATE_RETENTION_TASK = None
    MODERATION_LOG_TASK = None


async def close_bot(*, reason: str = "shutdown", exit_status: Optional[int] = None) -> None:
    global SHUTDOWN_REQUESTED, EXIT_STATUS, CPU_WORKER_POOL

    async with SHUTDOWN_LOCK:
        if SHUTDOWN_REQUESTED:
            return
        SHUTDOWN_REQUESTED = True
        if exit_status is not None:
            EXIT_STATUS = max(EXIT_STATUS, exit_status)
        log.info("Closing SpamFighter. reason=%s exit_status=%s", reason, EXIT_STATUS)

        with contextlib.suppress(Exception):
            await persist_runtime_state()
        with contextlib.suppress(Exception):
            await persist_retro_scan_state()
        with contextlib.suppress(Exception):
            await flush_moderation_log_queue()
        with contextlib.suppress(Exception):
            await cancel_background_tasks()
        with contextlib.suppress(Exception):
            await release_distributed_lease(RETRO_SCAN_LEASE_KEY, owner_id=INSTANCE_ID)
        with contextlib.suppress(Exception):
            await release_distributed_lease(INSTANCE_LEASE_KEY, owner_id=INSTANCE_ID)
        with contextlib.suppress(Exception):
            await stop_healthcheck_server()
        if not bot.is_closed():
            with contextlib.suppress(Exception):
                await bot.close()
        if CPU_WORKER_POOL is not None:
            CPU_WORKER_POOL.shutdown(wait=False, cancel_futures=True)
            CPU_WORKER_POOL = None
        await close_state_db_connection()


def install_signal_handlers(loop: asyncio.AbstractEventLoop) -> None:
    if sys.platform.startswith("win"):
        return

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(
            sig,
            lambda current_sig=sig: asyncio.create_task(
                close_bot(reason=f"signal:{current_sig.name}", exit_status=0)
            ),
        )


# ============================================================
# Main
# ============================================================

async def main() -> None:
    global CPU_WORKER_POOL
    loop = asyncio.get_running_loop()
    if CPU_WORKER_POOL is None:
        CPU_WORKER_POOL = concurrent.futures.ThreadPoolExecutor(
            max_workers=CPU_WORKER_THREADS,
            thread_name_prefix="spamfighter-worker",
        )
        loop.set_default_executor(CPU_WORKER_POOL)
        log.info("Configured SpamFighter worker pool with %s thread(s).", CPU_WORKER_THREADS)
    install_signal_handlers(loop)

    try:
        async with bot:
            await bot.login(BOT_TOKEN)
            connect_attempt = 0
            while not SHUTDOWN_REQUESTED:
                try:
                    await bot.connect(reconnect=True)
                    break
                except asyncio.CancelledError:
                    raise
                except (
                    aiohttp.ClientError,
                    asyncio.TimeoutError,
                    discord.GatewayNotFound,
                    OSError,
                ) as exc:
                    if SHUTDOWN_REQUESTED:
                        break
                    connect_attempt += 1
                    retry_delay = min(
                        DISCORD_CONNECT_RETRY_MAX_SECONDS,
                        DISCORD_CONNECT_RETRY_BASE_SECONDS * max(1, connect_attempt),
                    )
                    log.warning(
                        "Discord connection failed with a transient network error (%s). Retrying in %.1fs.",
                        exc,
                        retry_delay,
                    )
                    await asyncio.sleep(retry_delay)
    except asyncio.CancelledError:
        log.info("Shutdown requested. Closing SpamFighter cleanly.")
    except discord.LoginFailure as exc:
        log.critical("Login failure. Check SPAMFIGHTER_BOT_TOKEN. %s", exc)
    except discord.PrivilegedIntentsRequired as exc:
        log.critical("Privileged intents are required but not enabled in the portal. %s", exc)
    except discord.HTTPException as exc:
        log.critical(
            "Discord HTTP exception during startup/run: status=%s text=%s",
            getattr(exc, "status", None),
            getattr(exc, "text", str(exc)),
        )
    except OSError as exc:
        log.critical("OS/network error during startup/run: %s", exc)
    finally:
        await close_bot(reason="main_finally")


def _parse_regression_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="SpamFighter regression harness")
    parser.add_argument("--regression", action="store_true", help="Run TOML-vs-Postgres regression suite and exit.")
    parser.add_argument("--sync-postgres-from-toml", action="store_true", help="Strictly overwrite Postgres rules payload from TOML and verify parity.")
    parser.add_argument("--strict", action="store_true", help="Require zero mismatches for sync/regression checks.")
    parser.add_argument("--toml", default=str(SPAM_RULES_PATH), help="Path to spam_rules.toml")
    parser.add_argument("--database-url", default=(SPAM_RULES_DATABASE_URL or ""), help="Postgres URL for rules backend")
    parser.add_argument("--corpus", default="tests/fixtures/regression_messages.jsonl", help="JSONL corpus path")
    parser.add_argument("--report", default="", help="Optional JSON report output path")
    parser.add_argument("--csv", default="", help="Optional CSV report output path")
    parser.add_argument("--backup", default="", help="Optional JSON path to save current Postgres payload before sync.")
    return parser.parse_args(list(argv))


if __name__ == "__main__":
    args = _parse_regression_args(sys.argv[1:])
    if args.sync_postgres_from_toml:
        if not args.database_url:
            print("Missing --database-url or SPAMFIGHTER_SPAM_RULES_DATABASE_URL")
            sys.exit(2)
        report = sync_postgres_from_toml_strict(
            toml_path=Path(args.toml),
            database_url=str(args.database_url),
            corpus_path=Path(args.corpus) if args.corpus else None,
            backup_path=Path(args.backup) if args.backup else None,
        )
        print("Postgres sync from TOML completed.")
        print_regression_summary(report)
        if args.strict:
            summary = report.get("summary", {})
            failed = any(
                int(summary.get(key, 0) or 0) > 0
                for key in ("equivalence_mismatch_count", "regex_failure_count", "behavior_mismatch_count")
            )
            sys.exit(1 if failed else 0)
        sys.exit(0)
    if args.regression:
        if not args.database_url:
            print("Missing --database-url or SPAMFIGHTER_SPAM_RULES_DATABASE_URL")
            sys.exit(2)
        report = run_regression_suite(
            toml_path=Path(args.toml),
            database_url=str(args.database_url),
            corpus_path=Path(args.corpus),
            report_path=Path(args.report) if args.report else None,
            csv_path=Path(args.csv) if args.csv else None,
        )
        print_regression_summary(report)
        summary = report.get("summary", {})
        failed = any(
            int(summary.get(key, 0) or 0) > 0
            for key in ("equivalence_mismatch_count", "regex_failure_count", "behavior_mismatch_count")
        )
        sys.exit(1 if failed else 0)
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
    finally:
        if EXIT_STATUS:
            sys.exit(EXIT_STATUS)
