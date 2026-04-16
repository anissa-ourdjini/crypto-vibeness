import unittest

import server


class TestServerHelpers(unittest.TestCase):
    def test_safe_b64d_valid(self):
        decoded = server.safe_b64d("SGVsbG8=")
        self.assertEqual(decoded, b"Hello")

    def test_safe_b64d_invalid(self):
        decoded = server.safe_b64d("not-base64!!!")
        self.assertIsNone(decoded)

    def test_valid_msg_id(self):
        self.assertTrue(server.valid_msg_id("a" * 32))
        self.assertFalse(server.valid_msg_id("A" * 32))
        self.assertFalse(server.valid_msg_id("abc"))

    def test_validate_password_rules(self):
        rules = {
            "min_length": 10,
            "require_uppercase": True,
            "require_lowercase": True,
            "require_digit": True,
            "require_symbol": True,
        }
        ok, _ = server.validate_password("Abcd1234!x", rules)
        self.assertTrue(ok)

        ok, reason = server.validate_password("abcd1234!x", rules)
        self.assertFalse(ok)
        self.assertIn("uppercase", reason.lower())

    def test_password_entropy_and_strength(self):
        weak = server.password_entropy_bits("aaaa")
        medium = server.password_entropy_bits("Abcd1234")
        strong = server.password_entropy_bits("Abcd1234!xyz")

        self.assertLess(weak, medium)
        self.assertLess(medium, strong)
        self.assertEqual(server.password_strength_level(10), "faible")
        self.assertEqual(server.password_strength_level(50), "medium")
        self.assertEqual(server.password_strength_level(80), "fort")

    def test_hash_and_verify_password_record(self):
        password = "S3cur3!Pass"
        record = server.hash_password_record(password, cost=10_000)
        self.assertTrue(record.startswith("pbkdf2_sha256:"))
        self.assertTrue(server.verify_password_record(record, password))
        self.assertFalse(server.verify_password_record(record, "wrong"))

    def test_anonymize_ip_ipv4_ipv6(self):
        self.assertEqual(server.anonymize_ip("192.168.1.42"), "192.168.1.x")
        self.assertEqual(server.anonymize_ip("2001:db8:abcd:0012::1"), "2001:db8:*")
        self.assertEqual(server.anonymize_ip("bad-ip"), "unknown")

    def test_maybe_tamper_dm_ciphertext_flips_one_byte(self):
        chat_server = server.ChatServer("127.0.0.1", 5050, tamper_next_dm=True)
        original = bytes(range(1, 17))
        tampered_b64 = chat_server.maybe_tamper_dm_ciphertext(server.b64e(original))
        self.assertIsInstance(tampered_b64, str)
        tampered = server.b64d(tampered_b64)

        self.assertEqual(len(original), len(tampered))
        diff_count = sum(1 for a, b in zip(original, tampered) if a != b)
        self.assertEqual(diff_count, 1)
        self.assertNotEqual(original[-1], tampered[-1])


if __name__ == "__main__":
    unittest.main()
