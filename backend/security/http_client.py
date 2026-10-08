"""Centralized Secure HTTP Client Layer for BB-SUITE.

Provides defense against SSRF, DoS, TLS stripping, infinite redirects,
memory exhaustion bombs, and unvalidated redirect targets.
"""
from __future__ import annotations
import json
from typing import Any, Dict, Optional, Tuple, Union
from urllib.parse import urljoin

import httpx

from backend.security.config import (
    BB_ALLOW_INSECURE_TLS,
    BB_MAX_REDIRECTS,
    BB_MAX_RESPONSE_SIZE,
    BB_TIMEOUT_CONNECT,
    BB_TIMEOUT_READ,
    BB_TIMEOUT_TOTAL,
    is_private_allowed,
)
from backend.security.target_validator import (
    TargetValidationError,
    validate_redirect_target,
    validate_target_url,
)

DEFAULT_USER_AGENT = "BB-Suite-Security-Scanner/1.0 (+https://github.com/RuudyLinux/bb-suite; Authorized Security Assessment)"


class ResponseTooLargeError(Exception):
    """Raised when an HTTP response exceeds the global maximum response size."""
    pass


class SafeResponse:
    """Wrapper around httpx.Response providing safe attributes and size bounding."""

    def __init__(
        self,
        status_code: int,
        content: bytes,
        headers: httpx.Headers,
        url: str,
        elapsed_seconds: float = 0.0,
        truncated: bool = False,
    ):
        self.status_code = status_code
        self.content = content
        self.headers = headers
        self.url = url
        self.elapsed_seconds = elapsed_seconds
        self.truncated = truncated
        self._text: Optional[str] = None

    @property
    def text(self) -> str:
        if self._text is None:
            try:
                self._text = self.content.decode("utf-8", errors="replace")
            except Exception:
                self._text = str(self.content)
        return self._text

    def json(self) -> Any:
        return json.loads(self.text)

    def __repr__(self) -> str:
        return f"<SafeResponse [{self.status_code}] len={len(self.content)} url={self.url}>"


async def safe_request(
    method: str,
    url: str,
    headers: Optional[Dict[str, str]] = None,
    params: Optional[Dict[str, Any]] = None,
    data: Optional[Any] = None,
    json_data: Optional[Any] = None,
    follow_redirects: bool = True,
    max_redirects: Optional[int] = None,
    verify: Optional[bool] = None,
    timeout: Optional[float] = None,
    max_response_size: Optional[int] = None,
    allow_private: Optional[bool] = None,
    cookies: Optional[Dict[str, str]] = None,
) -> SafeResponse:
    """Execute an outbound HTTP request through strict security boundary filters.

    - Validates URL against SSRF / private targets.
    - Manages manual redirect verification preventing redirection into internal space.
    - Limits streaming bytes to max_response_size.
    - Defaults to TLS verification enabled.
    """
    if allow_private is None:
        allow_private = is_private_allowed()

    if max_redirects is None:
        max_redirects = BB_MAX_REDIRECTS

    if max_response_size is None:
        max_response_size = BB_MAX_RESPONSE_SIZE

    if verify is None:
        # If BB_ALLOW_INSECURE_TLS is True, verify can be False, else True
        verify = not BB_ALLOW_INSECURE_TLS

    total_timeout = timeout if timeout is not None else BB_TIMEOUT_TOTAL
    timeout_config = httpx.Timeout(
        total_timeout,
        connect=BB_TIMEOUT_CONNECT,
        read=BB_TIMEOUT_READ,
        write=BB_TIMEOUT_CONNECT,
    )

    req_headers = {"User-Agent": DEFAULT_USER_AGENT, "Accept": "*/*"}
    if headers:
        req_headers.update(headers)

    current_url = validate_target_url(url, allow_private=allow_private)
    redirect_count = 0

    # We manage redirects manually if follow_redirects is True to inspect every hop
    transport_verify = verify

    async with httpx.AsyncClient(
        verify=transport_verify,
        timeout=timeout_config,
        follow_redirects=False,
    ) as client:
        while True:
            # Re-validate URL for each iteration (initial + redirects)
            validate_target_url(current_url, allow_private=allow_private)

            # Stream request to enforce maximum size limit
            req = client.build_request(
                method=method,
                url=current_url,
                headers=req_headers,
                params=params,
                data=data,
                json=json_data,
                cookies=cookies,
            )

            response = await client.send(req, stream=True)
            try:
                # Check status code for redirect
                if follow_redirects and response.is_redirect:
                    redirect_count += 1
                    if redirect_count > max_redirects:
                        raise TargetValidationError(
                            f"Exceeded maximum allowed redirects ({max_redirects})."
                        )

                    location = response.headers.get("Location")
                    if not location:
                        break  # Malformed redirect, keep current response

                    next_url = urljoin(current_url, location)
                    # Validate redirect hop against private networks/cloud metadata!
                    current_url = validate_redirect_target(
                        initial_url=current_url,
                        target_redirect_url=next_url,
                        allow_private=allow_private,
                    )
                    # For redirects, standard RFC behaviour converts POST to GET (301, 302, 303)
                    if response.status_code in (301, 302, 303):
                        method = "GET"
                        data = None
                        json_data = None
                        params = None
                    await response.aclose()
                    continue

                # Read response safely with size cap
                content_chunks = []
                bytes_read = 0
                truncated = False

                async for chunk in response.aiter_bytes():
                    bytes_read += len(chunk)
                    if bytes_read > max_response_size:
                        # Append up to limit and flag truncated or stop
                        remaining = max_response_size - (bytes_read - len(chunk))
                        if remaining > 0:
                            content_chunks.append(chunk[:remaining])
                        truncated = True
                        break
                    content_chunks.append(chunk)

                total_content = b"".join(content_chunks)
                elapsed = response.elapsed.total_seconds() if response.elapsed else 0.0

                return SafeResponse(
                    status_code=response.status_code,
                    content=total_content,
                    headers=response.headers,
                    url=str(response.url),
                    elapsed_seconds=elapsed,
                    truncated=truncated,
                )
            finally:
                await response.aclose()


# Convenience wrappers
async def safe_get(url: str, **kwargs: Any) -> SafeResponse:
    return await safe_request("GET", url, **kwargs)


async def safe_post(url: str, **kwargs: Any) -> SafeResponse:
    return await safe_request("POST", url, **kwargs)


async def safe_head(url: str, **kwargs: Any) -> SafeResponse:
    return await safe_request("HEAD", url, **kwargs)
