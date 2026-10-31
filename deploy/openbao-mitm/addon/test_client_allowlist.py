import unittest

from client_allowlist import ClientAllowlist, ClientAllowlistError


class ClientAllowlistTests(unittest.TestCase):
    def test_default_allows_only_the_app_container_address(self):
        allow = ClientAllowlist()
        self.assertTrue(allow.allows(("198.51.100.3", 41234)))
        for other in ("198.51.100.4", "198.51.100.2", "203.0.113.2", "203.0.113.3"):
            with self.subTest(other=other):
                self.assertFalse(allow.allows((other, 41234)))

    def test_explicit_cidrs_are_matched(self):
        allow = ClientAllowlist("198.51.100.0/29, 2001:db8::/64")
        self.assertTrue(allow.allows(("198.51.100.5", 1)))
        self.assertTrue(allow.allows(("2001:db8::7", 1)))
        self.assertFalse(allow.allows(("198.51.100.8", 1)))

    def test_missing_or_unparsable_peer_is_refused(self):
        allow = ClientAllowlist()
        self.assertFalse(allow.allows(None))
        self.assertFalse(allow.allows(()))
        self.assertFalse(allow.allows(("not-an-address", 1)))

    def test_ipv4_mapped_ipv6_is_normalised(self):
        self.assertTrue(ClientAllowlist().allows(("::ffff:198.51.100.3", 1)))

    def test_invalid_or_empty_configuration_fails_closed(self):
        for raw in ("", " ", ",", "198.51.100.3/33", "not-a-network"):
            with self.subTest(raw=raw), self.assertRaises(ClientAllowlistError):
                ClientAllowlist(raw)


if __name__ == "__main__":
    unittest.main()
