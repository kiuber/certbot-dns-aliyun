"""Tests for certbot_dns_aliyun.alidns."""

import os
import unittest

try:
    from .alidns import AliDNSClient
except:
    from alidns import AliDNSClient

ACCESS_KEY = '123'
ACCESS_KEY_SECRET = 'bar'
DOMAIN_NAME = 'foo.bar.example.com'

class AliDNSClientTest(unittest.TestCase):

    _client = None

    def setUp(self):
        super(AliDNSClientTest, self).setUp()
        self._client = AliDNSClient(ACCESS_KEY, ACCESS_KEY_SECRET)

    def test_determine_idn(self):
        idn_decoded = '你好世界.com'
        idn_encoded = 'xn--rhq34a65tw32a.com'

        self.assertFalse(self._client._is_idn_punycode(idn_decoded))
        self.assertTrue(self._client._is_idn_punycode(idn_encoded))
        self.assertTrue(self._client.determine_domain(idn_encoded) == idn_decoded)

        sub_name = 'print'
        sub_idn_decoded = f'{sub_name}.{idn_decoded}'
        sub_idn_encoded = f'{sub_name}.{idn_encoded}'
        self.assertTrue(self._client.determine_record_name(idn_encoded, sub_idn_encoded)[0] == idn_decoded)
        self.assertTrue(self._client.determine_record_name(idn_encoded, sub_idn_encoded)[1] == sub_idn_decoded)
        self.assertTrue(self._client.determine_rr(idn_encoded, sub_idn_encoded) == sub_name)

    def test_add_txt_record(self):
        self._client.add_txt_record(DOMAIN_NAME, 'test.' + DOMAIN_NAME, 'test')

    def test_del_txt_record(self):
        self._client.del_txt_record(DOMAIN_NAME, 'test.' + DOMAIN_NAME, 'test')

if __name__ == "__main__":
    unittest.main()  # pragma: no cover
