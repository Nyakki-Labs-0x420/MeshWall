import json
import re
from pathlib import Path
from typing import Dict, List

import structlog

logger = structlog.get_logger()


class RAGIndex:
    """In-memory index of trace files for retrieval."""

    def __init__(self, trace_dir: Path) -> None:
        self.trace_dir = Path(trace_dir)
        self.trace_dir.mkdir(parents=True, exist_ok=True)
        self.documents: List[Dict] = []
        self._index: Dict[str, List[int]] = {}

    def build(self) -> None:
        if not self.trace_dir.exists():
            logger.warning("Trace directory does not exist", path=str(self.trace_dir))
            return
        self.documents.clear()
        self._index.clear()
        for json_file in self.trace_dir.glob("*.json"):
            try:
                with open(json_file, "r") as f:
                    doc = json.load(f)
                    doc["_file"] = str(json_file)
                    self.documents.append(doc)
            except Exception as e:
                logger.error("Failed to load trace file", file=str(json_file), error=str(e))
        for idx, doc in enumerate(self.documents):
            text = self._doc_to_text(doc)
            words = set(re.findall(r"\w+", text.lower()))
            for word in words:
                if word not in self._index:
                    self._index[word] = []
                self._index[word].append(idx)
        logger.info("RAG index built", documents=len(self.documents))

    def _doc_to_text(self, doc: Dict) -> str:
        parts = [
            f"IP: {doc.get('src_ip', '')}",
            f"Country: {doc.get('geo', {}).get('country', '')}",
            f"City: {doc.get('geo', {}).get('city', '')}",
            f"Timestamp: {doc.get('timestamp', '')}",
            " ".join(doc.get("traceroute", [])),
        ]
        return " ".join(parts)

    def search(self, query: str, top_k: int = 5) -> List[Dict]:
        query_words = set(re.findall(r"\w+", query.lower()))
        scores: Dict[int, float] = {}
        for word in query_words:
            for doc_idx in self._index.get(word, []):
                scores[doc_idx] = scores.get(doc_idx, 0) + 1
        sorted_docs = sorted(scores.items(), key=lambda x: x[1], reverse=True)
        return [self.documents[idx] for idx, _ in sorted_docs[:top_k]]