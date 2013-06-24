# Copyright 2013 OpenStack LLC.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import os

import testtools
from OpenSSL import crypto

from swiftclient import https_connection as h


TEST_VAR_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__),
                                            'var'))


class TestHTTPSConnection(testtools.TestCase):
    def test_ssl_init_ok(self):
        """
        Test HTTPSConnection class init
        """
        key_file = os.path.join(TEST_VAR_DIR, 'privatekey.key')
        cert_file = os.path.join(TEST_VAR_DIR, 'certificate.crt')
        cacert = os.path.join(TEST_VAR_DIR, 'ca.crt')
        try:
            h.HTTPSConnection('127.0.0.1', 0,
                              key_file=key_file,
                              cert_file=cert_file,
                              cacert=cacert)
        except h.SSLConfigurationError:
            self.fail('Failed to init HTTPSConnection.')

    def test_ssl_init_cert_no_key(self):
        """
        Test HTTPSConnection: absense of SSL key file.
        """
        cert_file = os.path.join(TEST_VAR_DIR, 'certificate.crt')
        cacert = os.path.join(TEST_VAR_DIR, 'ca.crt')
        try:
            h.HTTPSConnection('127.0.0.1', 0,
                              cert_file=cert_file,
                              cacert=cacert)
            self.fail('Failed to raise assertion.')
        except h.SSLConfigurationError:
            pass

    def test_ssl_init_key_no_cert(self):
        """
        Test HTTPSConnection: absense of SSL cert file.
        """
        key_file = os.path.join(TEST_VAR_DIR, 'privatekey.key')
        cacert = os.path.join(TEST_VAR_DIR, 'ca.crt')
        try:
            h.HTTPSConnection('127.0.0.1', 0,
                              key_file=key_file,
                              cacert=cacert)
        except:
            self.fail('Failed to init HTTPSConnection.')

    def test_ssl_init_bad_key(self):
        """
        Test HTTPSConnection: bad key.
        """
        cert_file = os.path.join(TEST_VAR_DIR, 'certificate.crt')
        cacert = os.path.join(TEST_VAR_DIR, 'ca.crt')
        try:
            h.HTTPSConnection('127.0.0.1', 0,
                              cert_file=cert_file,
                              cacert=cacert)
            self.fail('Failed to raise assertion.')
        except h.SSLConfigurationError:
            pass

    def test_ssl_init_bad_cert(self):
        """
        Test HTTPSConnection: bad cert.
        """
        cert_file = os.path.join(TEST_VAR_DIR, 'badcert.crt')
        cacert = os.path.join(TEST_VAR_DIR, 'ca.crt')
        try:
            h.HTTPSConnection('127.0.0.1', 0,
                              cert_file=cert_file,
                              cacert=cacert)
            self.fail('Failed to raise assertion.')
        except h.SSLConfigurationError:
            pass

    def test_ssl_init_bad_ca(self):
        """
        Test HTTPSConnection: bad CA.
        """
        cert_file = os.path.join(TEST_VAR_DIR, 'certificate.crt')
        cacert = os.path.join(TEST_VAR_DIR, 'badca.crt')
        try:
            h.HTTPSConnection('127.0.0.1', 0,
                              cert_file=cert_file,
                              cacert=cacert)
            self.fail('Failed to raise assertion.')
        except h.SSLConfigurationError:
            pass

    def test_ssl_cert_cname(self):
        """
        Test certificate: CN match
        """
        cert_file = os.path.join(TEST_VAR_DIR, 'certificate.crt')
        cert = crypto.load_certificate(crypto.FILETYPE_PEM,
                                       file(cert_file).read())
        # The expected cert should have CN=0.0.0.0
        self.assertEqual(cert.get_subject().commonName, '0.0.0.0')
        try:
            conn = h.HTTPSConnection('0.0.0.0', 0)
            conn.verify_callback(None, cert, 0, 0, 1)
        except:
            self.fail('Unexpected exception.')

    def test_ssl_cert_subject_alt_name(self):
        """
        Test certificate: SAN match
        """
        cert_file = os.path.join(TEST_VAR_DIR, 'certificate.crt')
        cert = crypto.load_certificate(crypto.FILETYPE_PEM,
                                       file(cert_file).read())
        # The expected cert should have CN=0.0.0.0
        self.assertEqual(cert.get_subject().commonName, '0.0.0.0')
        try:
            conn = h.HTTPSConnection('alt1.example.com', 0)
            conn.verify_callback(None, cert, 0, 0, 1)
        except:
            self.fail('Unexpected exception.')

        try:
            conn = h.HTTPSConnection('alt2.example.com', 0)
            conn.verify_callback(None, cert, 0, 0, 1)
        except:
            self.fail('Unexpected exception.')

    def test_ssl_cert_mismatch(self):
        """
        Test certificate: bogus host
        """
        cert_file = os.path.join(TEST_VAR_DIR, 'certificate.crt')
        cert = crypto.load_certificate(crypto.FILETYPE_PEM,
                                       file(cert_file).read())
        # The expected cert should have CN=0.0.0.0
        self.assertEqual(cert.get_subject().commonName, '0.0.0.0')
        try:
            conn = h.HTTPSConnection('mismatch.example.com', 0)
        except:
            self.fail('Failed to init HTTPSConnection.')

        self.assertRaises(h.SSLCertificateError,
                          conn.verify_callback, None, cert, 0, 0, 1)

    def test_ssl_expired_cert(self):
        """
        Test certificate: out of date cert
        """
        cert_file = os.path.join(TEST_VAR_DIR, 'expired-cert.crt')
        cert = crypto.load_certificate(crypto.FILETYPE_PEM,
                                       file(cert_file).read())
        # The expected expired cert has CN=openstack.example.com
        self.assertEqual(cert.get_subject().commonName,
                         'openstack.example.com')
        try:
            conn = h.HTTPSConnection('openstack.example.com', 0)
        except:
            self.fail('Failed to init HTTPSConnection.')

        self.assertRaises(h.SSLCertificateError,
                          conn.verify_callback, None, cert, 0, 0, 1)

    def test_ssl_broken_key_file(self):
        """
        Test verify exception is raised.
        """
        cert_file = os.path.join(TEST_VAR_DIR, 'certificate.crt')
        cacert = os.path.join(TEST_VAR_DIR, 'ca.crt')
        key_file = 'fake.key'
        self.assertRaises(
            h.SSLConfigurationError,
            h.HTTPSConnection, '127.0.0.1',
            0, key_file=key_file,
            cert_file=cert_file, cacert=cacert)

    def test_ssl_init_ok_with_insecure_true(self):
        """
        Test HTTPSConnection class init
        """
        key_file = os.path.join(TEST_VAR_DIR, 'privatekey.key')
        cert_file = os.path.join(TEST_VAR_DIR, 'certificate.crt')
        cacert = os.path.join(TEST_VAR_DIR, 'ca.crt')
        try:
            h.HTTPSConnection('127.0.0.1', 0,
                              key_file=key_file,
                              cert_file=cert_file,
                              cacert=cacert, insecure=True)
        except h.SSLConfigurationError:
            self.fail('Failed to init HTTPSConnection.')

    def test_ssl_init_ok_with_ssl_compression_false(self):
        """
        Test HTTPSConnection class init
        """
        key_file = os.path.join(TEST_VAR_DIR, 'privatekey.key')
        cert_file = os.path.join(TEST_VAR_DIR, 'certificate.crt')
        cacert = os.path.join(TEST_VAR_DIR, 'ca.crt')
        try:
            h.HTTPSConnection('127.0.0.1', 0,
                              key_file=key_file,
                              cert_file=cert_file,
                              cacert=cacert, ssl_compression=False)
        except h.SSLConfigurationError:
            self.fail('Failed to init HTTPSConnection.')
