"""Async Ollama API client."""

import json
from typing import Any, AsyncGenerator, Dict, List, Optional

import httpx
import structlog

logger = structlog.get_logger()


class OllamaClient:
    """Async client for Ollama's API."""

    def __init__(self, base_url: str = None, model: str = "phi3:mini") -> None:
        import os
        self.base_url = base_url or os.environ.get("OLLAMA_HOST", "http://localhost:11434").rstrip("/")
        self.model = model
        self._client: Optional[httpx.AsyncClient] = None

    async def __aenter__(self) -> "OllamaClient":
        self._client = httpx.AsyncClient(timeout=60.0)
        return self

    async def __aexit__(self, *args: Any) -> None:
        if self._client:
            await self._client.aclose()

    async def health_check(self) -> bool:
        if not self._client:
            return False
        try:
            resp = await self._client.get(f"{self.base_url}/api/tags")
            return resp.status_code == 200
        except Exception:
            return False

    async def generate(
        self,
        prompt: str,
        system: Optional[str] = None,
        stream: bool = False,
        temperature: float = 0.7,
    ) -> str:
        if not self._client:
            raise RuntimeError("Client not initialized")
        payload: Dict[str, Any] = {
            "model": self.model,
            "prompt": prompt,
            "stream": stream,
            "options": {"temperature": temperature},
        }
        if system:
            payload["system"] = system
        resp = await self._client.post(f"{self.base_url}/api/generate", json=payload)
        resp.raise_for_status()
        data = resp.json()
        return data.get("response", "")

    async def chat(
        self,
        messages: List[Dict[str, str]],
        stream: bool = False,
        temperature: float = 0.7,
    ) -> str:
        if not self._client:
            raise RuntimeError("Client not initialized")
        payload = {
            "model": self.model,
            "messages": messages,
            "stream": stream,
            "options": {"temperature": temperature},
        }
        resp = await self._client.post(f"{self.base_url}/api/chat", json=payload)
        resp.raise_for_status()
        data = resp.json()
        return data.get("message", {}).get("content", "")