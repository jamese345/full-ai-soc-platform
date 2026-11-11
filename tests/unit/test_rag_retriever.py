import unittest

from src.rag.retriever import KnowledgeBaseRetriever


class TestKnowledgeBaseRetriever(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.retriever = KnowledgeBaseRetriever()
        cls.retriever.build_index()

    def test_knowledge_base_loads(self):
        documents = self.retriever.documents

        self.assertGreater(
            len(documents),
            0,
        )

    def test_brute_force_query_returns_results(self):
        results = self.retriever.retrieve(
            "multiple failed login attempts brute force",
            top_k=3,
        )

        self.assertGreater(
            len(results),
            0,
        )

        sources = [
            result["source"]
            for result in results
        ]

        self.assertIn(
            "brute_force.md",
            sources,
        )

    def test_suspicious_login_query_returns_results(self):
        results = self.retriever.retrieve(
            "successful login after failed authentication",
            top_k=3,
        )

        self.assertGreater(
            len(results),
            0,
        )

        sources = [
            result["source"]
            for result in results
        ]

        self.assertTrue(
            "suspicious_login.md" in sources
            or "soc_investigation.md" in sources
        )

    def test_empty_query_returns_no_results(self):
        results = self.retriever.retrieve(
            "",
            top_k=3,
        )

        self.assertEqual(
            results,
            [],
        )

    def test_top_k_is_respected(self):
        results = self.retriever.retrieve(
            "SOC investigation",
            top_k=2,
        )

        self.assertLessEqual(
            len(results),
            2,
        )

    def test_results_contain_required_fields(self):
        results = self.retriever.retrieve(
            "brute force investigation",
            top_k=1,
        )

        self.assertGreater(
            len(results),
            0,
        )

        result = results[0]

        self.assertIn("source", result)
        self.assertIn("chunk_id", result)
        self.assertIn("score", result)
        self.assertIn("text", result)


if __name__ == "__main__":
    unittest.main()