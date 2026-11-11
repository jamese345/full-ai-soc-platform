from pathlib import Path
import re

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity


DEFAULT_KNOWLEDGE_BASE = "data/knowledge_base"


class KnowledgeBaseRetriever:
    """Simple TF-IDF based retriever for SOC investigation knowledge."""

    def __init__(
        self,
        knowledge_base_path: str = DEFAULT_KNOWLEDGE_BASE,
    ):
        self.knowledge_base_path = Path(knowledge_base_path)
        self.documents = []
        self.vectorizer = TfidfVectorizer(
            lowercase=True,
            stop_words="english",
        )
        self.document_matrix = None

    def load_documents(self) -> list[dict]:
        """Load Markdown knowledge-base documents."""

        if not self.knowledge_base_path.exists():
            raise FileNotFoundError(
                f"Knowledge base not found: "
                f"{self.knowledge_base_path}"
            )

        documents = []

        for path in sorted(
            self.knowledge_base_path.glob("*.md")
        ):
            text = path.read_text(encoding="utf-8").strip()

            if not text:
                continue

            documents.append({
                "source": path.name,
                "text": text,
            })

        if not documents:
            raise ValueError(
                "No knowledge-base documents were found."
            )

        self.documents = documents
        return documents

    def _chunk_document(
        self,
        text: str,
        chunk_size: int = 120,
        overlap: int = 20,
    ) -> list[str]:
        """Split a document into overlapping word chunks."""

        words = re.findall(r"\S+", text)

        if not words:
            return []

        chunks = []
        start = 0

        while start < len(words):
            end = start + chunk_size
            chunk = " ".join(words[start:end])
            chunks.append(chunk)

            if end >= len(words):
                break

            start = end - overlap

        return chunks

    def build_index(self) -> None:
        """Build the TF-IDF search index."""

        if not self.documents:
            self.load_documents()

        chunks = []

        for document in self.documents:
            document_chunks = self._chunk_document(
                document["text"]
            )

            for index, chunk in enumerate(document_chunks):
                chunks.append({
                    "source": document["source"],
                    "chunk_id": index,
                    "text": chunk,
                })

        if not chunks:
            raise ValueError(
                "No searchable chunks were created."
            )

        self.documents = chunks

        self.document_matrix = self.vectorizer.fit_transform(
            [document["text"] for document in self.documents]
        )

    def retrieve(
        self,
        query: str,
        top_k: int = 3,
    ) -> list[dict]:
        """Retrieve the most relevant knowledge chunks."""

        if not query or not query.strip():
            return []

        if self.document_matrix is None:
            self.build_index()

        query_vector = self.vectorizer.transform(
            [query]
        )

        similarities = cosine_similarity(
            query_vector,
            self.document_matrix,
        )[0]

        ranked_indexes = similarities.argsort()[::-1]

        results = []

        for index in ranked_indexes[:top_k]:
            score = float(similarities[index])

            if score <= 0:
                continue

            document = self.documents[index]

            results.append({
                "source": document["source"],
                "chunk_id": document["chunk_id"],
                "score": score,
                "text": document["text"],
            })

        return results
