"""Parse key.env from project root and expose API keys."""
from __future__ import annotations
import os

_KEY_ENV = os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..', 'key.env')
)

_keys: dict[str, str] = {}


def _parse() -> None:
    if not os.path.exists(_KEY_ENV):
        return
    with open(_KEY_ENV, encoding='utf-8') as f:
        lines = [l.rstrip() for l in f]
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        if line.endswith(':') and i + 1 < len(lines):
            label = line[:-1].lower().strip()
            val   = lines[i + 1].strip()
            if val and not val.endswith(':'):
                _keys[label] = val
                i += 2
                continue
        i += 1


_parse()


def get(label: str, default: str = '') -> str:
    return _keys.get(label.lower().strip(), default)


# Named constants
ZAP_KEY         = get('zap api')
LOCAL_LLM_URL   = get('local llm url', 'http://localhost:11434')
LOCAL_LLM_MODEL = get('local llm model', 'deepseek-r1')
