"""
Asynchronous HTTP client with authentication support.
Handles all HTTP operations for API Fortress.
"""

import asyncio
from typing import Optional, Dict, Any, List
import aiohttp
import httpx
from aiohttp import ClientSession, ClientTimeout, TCPConnector
import time
import base64

from api_fortress.models import AuthType, HTTPResponse, ScanConfig


class FortressHTTPClient:
    """Premium async HTTP client with comprehensive authentication."""

    def __init__(self, config: ScanConfig):
        self.config = config
        self.session: Optional[ClientSession] = None
        self.semaphore = asyncio.Semaphore(config.max_concurrent)
        self.total_requests = 0

    async def __aenter__(self) -> "FortressHTTPClient":
        """Context manager entry."""
        await self.create_session()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Context manager exit."""
        await self.close()

    async def create_session(self) -> None:
        """Create aiohttp session with proper configuration."""
        timeout = ClientTimeout(total=self.config.timeout)
        connector = TCPConnector(
            limit=self.config.max_concurrent,
            ssl=self.config.verify_ssl,
        )

        headers = self._build_headers()

        self.session = ClientSession(
            timeout=timeout,
            connector=connector,
            headers=headers,
        )

    def _build_headers(self) -> Dict[str, str]:
        """Build headers with authentication."""
        headers = {
            "User-Agent": self.config.user_agent,
            "Accept": "application/json, */*",
            **self.config.headers,
        }

        # Add authentication headers
        if self.config.auth_type == AuthType.BEARER and self.config.auth_token:
            headers["Authorization"] = f"Bearer {self.config.auth_token}"
        elif self.config.auth_type == AuthType.API_KEY and self.config.auth_token:
            headers["X-API-Key"] = self.config.auth_token
        elif self.config.auth_type == AuthType.BASIC and self.config.auth_token:
            # Expect token in format "username:password"
            encoded = base64.b64encode(self.config.auth_token.encode()).decode()
            headers["Authorization"] = f"Basic {encoded}"

        return headers

    async def request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        json: Optional[Dict[str, Any]] = None,
        data: Optional[Any] = None,
    ) -> HTTPResponse:
        """Execute HTTP request with rate limiting."""
        if not self.session:
            await self.create_session()

        async with self.semaphore:
            start_time = time.time()
            self.total_requests += 1

            merged_headers = {**self.session.headers, **(headers or {})}

            try:
                async with self.session.request(
                    method=method,
                    url=url,
                    headers=merged_headers,
                    params=params,
                    json=json,
                    data=data,
                    allow_redirects=True,
                ) as response:
                    body = await response.text()
                    elapsed = time.time() - start_time

                    return HTTPResponse(
                        status_code=response.status,
                        headers=dict(response.headers),
                        body=body,
                        elapsed_time=elapsed,
                        url=str(response.url),
                    )
            except asyncio.TimeoutError:
                return HTTPResponse(
                    status_code=0,
                    headers={},
                    body="Request timeout",
                    elapsed_time=time.time() - start_time,
                    url=url,
                )
            except Exception as e:
                return HTTPResponse(
                    status_code=0,
                    headers={},
                    body=f"Request failed: {str(e)}",
                    elapsed_time=time.time() - start_time,
                    url=url,
                )

    async def get(self, url: str, **kwargs: Any) -> HTTPResponse:
        """Execute GET request."""
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> HTTPResponse:
        """Execute POST request."""
        return await self.request("POST", url, **kwargs)

    async def put(self, url: str, **kwargs: Any) -> HTTPResponse:
        """Execute PUT request."""
        return await self.request("PUT", url, **kwargs)

    async def delete(self, url: str, **kwargs: Any) -> HTTPResponse:
        """Execute DELETE request."""
        return await self.request("DELETE", url, **kwargs)

    async def patch(self, url: str, **kwargs: Any) -> HTTPResponse:
        """Execute PATCH request."""
        return await self.request("PATCH", url, **kwargs)

    async def options(self, url: str, **kwargs: Any) -> HTTPResponse:
        """Execute OPTIONS request."""
        return await self.request("OPTIONS", url, **kwargs)

    async def head(self, url: str, **kwargs: Any) -> HTTPResponse:
        """Execute HEAD request."""
        return await self.request("HEAD", url, **kwargs)

    async def batch_request(
        self, requests: List[Dict[str, Any]]
    ) -> List[HTTPResponse]:
        """Execute multiple requests concurrently."""
        tasks = [
            self.request(
                method=req.get("method", "GET"),
                url=req["url"],
                headers=req.get("headers"),
                params=req.get("params"),
                json=req.get("json"),
                data=req.get("data"),
            )
            for req in requests
        ]
        return await asyncio.gather(*tasks, return_exceptions=True)

    async def close(self) -> None:
        """Close the HTTP session."""
        if self.session:
            await self.session.close()
            self.session = None

    def get_request_count(self) -> int:
        """Get total number of requests made."""
        return self.total_requests
