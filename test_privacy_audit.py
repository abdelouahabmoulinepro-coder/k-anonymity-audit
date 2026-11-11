import tempfile
import unittest
from pathlib import Path

from privacy_audit import audit, load_csv, write_report


def rows(sizes):
    result = []
    for group, size in enumerate(sizes):
        result.extend({"region": str(group), "age": "adult"} for _ in range(size))
    return result


class PrivacyAuditTests(unittest.TestCase):
    def test_all_classes_meet_k(self):
        result = audit(rows([5, 7]), ["region", "age"], 5)
        self.assertTrue(result["screen_passed"])
        self.assertEqual(result["equivalence_classes"], 2)
        self.assertEqual(result["records_in_classes_below_k"], 0)

    def test_small_classes_report_records_not_just_groups(self):
        result = audit(rows([1, 2, 5]), ["region", "age"], 3)
        self.assertEqual(result["classes_below_k"], 2)
        self.assertEqual(result["records_in_classes_below_k"], 3)
        self.assertAlmostEqual(result["share_records_below_k"], 3 / 8)
        self.assertFalse(result["screen_passed"])

    def test_unique_record_count(self):
        result = audit(rows([1, 1, 4]), ["region"], 2)
        self.assertEqual(result["unique_records"], 2)

    def test_empty_dataset_is_not_reported_as_pass(self):
        result = audit([], ["region"], 2)
        self.assertIsNone(result["share_records_below_k"])
        self.assertIsNone(result["minimum_class_size"])
        self.assertFalse(result["screen_passed"])

    def test_k_must_be_at_least_two(self):
        with self.assertRaisesRegex(ValueError, "supérieur ou égal"):
            audit([], ["region"], 1)

    def test_quasi_identifier_list_required_and_unique(self):
        with self.assertRaises(ValueError):
            audit([], [], 2)
        with self.assertRaises(ValueError):
            audit([], ["region", "region"], 2)

    def test_missing_quasi_identifier_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "colonnes absentes"):
            audit([{"region": "north"}], ["region", "age"], 2)

    def test_csv_loader_validates_header(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sample.csv"
            path.write_text("region,age\nnorth,30-44\n", encoding="utf-8")
            self.assertEqual(load_csv(path, ["region"]), [{"region": "north"}])
            with self.assertRaisesRegex(ValueError, "Colonnes absentes"):
                load_csv(path, ["postcode"])

    def test_duplicate_csv_headers_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sample.csv"
            path.write_text("region,region\nnorth,south\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "uniques"):
                load_csv(path, ["region"])

    def test_report_contains_only_aggregate_metrics(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            result = audit([{"region": "secret-place"}, {"region": "secret-place"}], ["region"], 2)
            write_report(result, out)
            report = (out / "report.md").read_text(encoding="utf-8")
            self.assertIn("PASS", report)
            self.assertNotIn("secret-place", report)
            self.assertTrue((out / "audit.json").exists())


if __name__ == "__main__":
    unittest.main()
