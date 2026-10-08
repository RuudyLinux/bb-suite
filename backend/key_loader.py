"""Parse environment variables, .env, and key.env from project root."""
from __future__ import annotations
import os
import re

_ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
_KEY_ENV = os.path.join(_ROOT_DIR, 'key.env')
_DOT_ENV = os.path.join(_ROOT_DIR, '.env')

_keys: dict[str, str] = {}


def _load_env_file(filepath: str) -> None:
    if not os.path.exists(filepath):
        return
    with open(filepath, encoding='utf-8', errors='ignore') as f:
        lines = [line.strip() for line in f]

    i = 0
    while i < len(lines):
        line = lines[i]
        if not line or line.startswith('#'):
            i += 1
            continue

        # Standard KEY=value format
        if '=' in line:
            key, _, val = line.partition('=')
            k = key.strip().lower()
            v = val.strip().strip('"').strip("'")
            if k:
                _keys[k] = v
            i += 1
            continue

        # Legacy multi-line colon format (e.g., "ZAP API:\n<key>")
        if line.endswith(':') and i + 1 < len(lines):
            label = line[:-1].lower().strip()
            val = lines[i + 1].strip()
            if val and not val.endswith(':') and not val.startswith('#'):
                _keys[label] = val
                i += 2
                continue
        i += 1


def _reload() -> None:
    _keys.clear()
    _load_env_file(_KEY_ENV)
    _load_env_file(_DOT_ENV)


_reload()


def get(label: str, default: str = '') -> str:
    """Get config value by label or env var name."""
    norm = label.lower().strip()
    # 1. Check loaded files
    if norm in _keys:
        return _keys[norm]

    # 2. Check uppercase underscore format in os.environ
    env_key = re.sub(r'[^a-zA-Z0-9]+', '_', label).upper()
    if env_key in os.environ:
        return os.environ[env_key]

    return default


# Named constants with standard fallbacks
ZAP_KEY = get('zap_api_key') or get('zap api') or get('zap_key', '')
LOCAL_LLM_URL = get('local_llm_url') or get('local llm url', 'http://localhost:11434')
LOCAL_LLM_MODEL = get('local_llm_model') or get('local llm model', 'deepseek-r1')
