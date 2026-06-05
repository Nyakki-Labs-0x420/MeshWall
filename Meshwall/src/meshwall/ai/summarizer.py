"""AI summarization of scan events."""

import asyncio
import json
import logging
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional

import structlog

from meshwall.ai.client import OllamaClient
from meshwall.ai.rag import RAGIndex
from meshwall.config import Config
from meshwall.ipset_manager import IPSetManager

logger = structlog.get_logger()
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)

SYSTEM_PROMPT = """You are a cybersecurity analyst assistant for MeshWall, an intrusion detection system.
Analyze the provided scan events and provide a concise summary.
Include: attack patterns observed, likely intent, geographic origins, and recommended actions.
Be factual and technical. Keep response under 500 words."""


class ScanSummarizer:
    """Summarize scan activity using Ollama."""

    def __init__(self, config: Config) -> None:
        self.config = config
        self.trace_dir = config.data_dir / "traces"
        self.trace_dir.mkdir(parents=True, exist_ok=True)
        self.client: Optional[OllamaClient] = None
        self.rag = RAGIndex(self.trace_dir)
        self.ipset = IPSetManager(config)

    async def _ensure_client(self) -> bool:
        if self.client is not None:
            return True
        self.client = OllamaClient(model="phi3:mini")
        await self.client.__aenter__()
        healthy = await self.client.health_check()
        if not healthy:
            logger.error("Ollama not reachable. Is it running?")
            await self.client.__aexit__(None, None, None)
            self.client = None
            return False
        return True

    async def summarize_recent(self, hours: int = 24) -> Optional[str]:
        if not await self._ensure_client():
            return None

        self.rag.build()
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        recent_docs = []
        for doc in self.rag.documents:
            try:
                ts = datetime.fromisoformat(doc["timestamp"].replace("Z", "+00:00"))
                if ts.replace(tzinfo=None) > cutoff:
                    recent_docs.append(doc)
            except Exception:
                continue

        if not recent_docs:
            return "No scan events in the last {} hours.".format(hours)

        country_counts = Counter()
        ip_counts = Counter()
        for trace in recent_docs:
            country = trace.get("geo", {}).get("country", "Unknown")
            country_counts[country] += 1
            ip_counts[trace["src_ip"]] += 1

        context = self._format_docs(recent_docs, max_docs=20)
        prompt = f"""Recent port scan events ({hours}h):
{context}

Statistics:
- Top countries: {', '.join(f'{c}({n})' for c,n in country_counts.most_common(5))}
- Top IPs: {', '.join(f'{ip}({n})' for ip,n in ip_counts.most_common(5))}

Provide a summary analysis."""
        try:
            response = await self.client.generate(prompt, system=SYSTEM_PROMPT)
            return response
        except Exception as e:
            logger.error("Ollama generation failed", error=str(e))
            return None

    def _format_docs(self, docs: List[Dict], max_docs: int) -> str:
        lines = []
        for doc in docs[:max_docs]:
            ip = doc.get("src_ip", "unknown")
            geo = doc.get("geo", {})
            country = geo.get("country", "??")
            city = geo.get("city", "")
            ts = doc.get("timestamp", "")[:19]
            lines.append(f"- {ts} {ip} ({country} {city})")
        return "\n".join(lines)

    async def ask(self, question: str) -> Optional[str]:
        if not await self._ensure_client():
            return None
        self.rag.build()
        relevant_docs = self.rag.search(question, top_k=5)
        context = "\n\n".join(json.dumps(doc, indent=2) for doc in relevant_docs)
        prompt = f"""Context from MeshWall traces:
{context}

Question: {question}

Answer concisely based only on the provided context. If the answer cannot be found, say so."""
        try:
            response = await self.client.generate(prompt, system=SYSTEM_PROMPT)
            return response
        except Exception as e:
            logger.error("Ollama generation failed", error=str(e))
            return None

    async def close(self) -> None:
        if self.client:
            await self.client.__aexit__(None, None, None)
            self.client = None