from pydantic import BaseModel


class TargetReq(BaseModel):
    target: str

class PageDiscoverReq(BaseModel):
    target: str
    depth: int = 2
    max_pages: int = 150
    wordlist: str = "medium"

class PortScanReq(BaseModel):
    target: str
    ports: str = "common"

class TlsReq(BaseModel):
    target: str
    port: int = 443

class SubdomainReq(BaseModel):
    target: str
    wordlist: str = "medium"

class WordlistReq(BaseModel):
    target: str
    wordlist: str = "medium"
    filter: str = "found"

class CorsReq(BaseModel):
    target: str
    origin: str = ""

class CloudReq(BaseModel):
    target: str

class SqliReq(BaseModel):
    target: str
    type: str = "all"
    db: str = "all"

class BruteReq(BaseModel):
    target: str
    username_field: str = "username"
    password_field: str = "password"
    username: str = "admin"
    success_indicator: str = ""
    passwords: str = ""
    credentials: str = ""
    concurrency: int = 5
    payload_type: str = "form"
    wordlist_size: str = "medium"

class PasswordCrackReq(BaseModel):
    mode: str = "hash_crack"
    hashes: str = ""
    hash_type: str = "auto"
    attack_type: str = "all"
    custom_wordlist: str = ""
    salt: str = ""
    mask: str = "?d?d?d?d"
    target_info: str = ""
    passwords: str = ""

class StuffingReq(BaseModel):
    target: str
    username_field: str = "email"
    password_field: str = "password"
    success_indicator: str = ""
    credentials: str

class AuthFlawsReq(BaseModel):
    target: str
    username_field: str = "username"
    password_field: str = "password"
    username: str = "admin"

class ZapReq(BaseModel):
    target: str
    scan_type: str = "active"
    api_key: str = ""  # loaded from key.env at runtime via key_loader
    zap_host: str = "http://localhost:8080"
    action: str = "scan"

class RateLimitReq(BaseModel):
    target: str
    requests: int = 50
    concurrency: int = 5
    custom_header: str = ""

class VulnMapReq(BaseModel):
    target: str
    max_pages: int = 40

class SsrfReq(BaseModel):
    target: str
    param: str = ""
    mode: str = "all"

class SstiReq(BaseModel):
    target: str
    param: str = ""
    method: str = "GET"

class GraphqlReq(BaseModel):
    target: str
    endpoint: str = ""

class ProtoReq(BaseModel):
    target: str
    method: str = "ALL"

class PocReq(BaseModel):
    vuln_type: str = "xss"
    target: str = "https://example.com/search"
    parameter: str = "q"
    custom_payload: str = ""
    http_method: str = "GET"

class AiAnalysisReq(BaseModel):
    target: str = ""
    findings: list = []
    engine: str = "builtin"
    local_url: str = ""
    model: str = "deepseek-r1"
