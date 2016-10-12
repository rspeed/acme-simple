import unittest, os, sys, tempfile
from subprocess import Popen, PIPE
import multiprocessing
from contextlib import contextmanager
try:
    from StringIO import StringIO # Python 2
except ImportError:
    from io import StringIO # Python 3

import acme_simple
from tests.monkey import gen_keys, run_server

@contextmanager
def captured_output():
    new_out, new_err = StringIO(), StringIO()
    old_out, old_err = sys.stdout, sys.stderr
    try:
        sys.stdout, sys.stderr = new_out, new_err
        yield sys.stdout, sys.stderr
    finally:
        sys.stdout, sys.stderr = old_out, old_err

class TestModule(unittest.TestCase):
    "Tests for acme_simple.get_crt()"
    keys = None
    talkie = None

    @classmethod
    def setUpClass(cls):
        walkie, cls.talkie = multiprocessing.Pipe()
        cls.server = multiprocessing.Process(target=run_server, args=[walkie, '0.0.0.0', 8080])
        cls.server.start()
        cls.keys = gen_keys()

    @classmethod
    def tearDownClass(cls):
        cls.server.terminate()
        cls.server.join() # wait for the server process to quit

    def setUp(self):
        self.CA = "https://acme-staging.api.letsencrypt.org"
        self.tempdir = tempfile.mkdtemp()
        self.talkie.send(self.tempdir)
        self.talkie.recv() # prevent a race condition by waiting for the confirmation

    def tearDown(self):
        os.rmdir(self.tempdir)

    def test_success_cn(self):
        """ Successfully issue a certificate via common name """
        old_stdout = sys.stdout
        sys.stdout = StringIO()
        result = acme_simple.main([
            "--account-key", self.keys['account_key'].name,
            "--csr", self.keys['domain_csr'].name,
            "--acme-dir", self.tempdir,
            "--ca", self.CA,
        ])
        sys.stdout.seek(0)
        crt = sys.stdout.read().encode("utf8")
        sys.stdout = old_stdout
        out, err = Popen(["openssl", "x509", "-text", "-noout"], stdin=PIPE,
            stdout=PIPE, stderr=PIPE).communicate(crt)
        self.assertIn("Issuer: CN=Fake LE Intermediate", out.decode("utf8"))

    def test_success_san(self):
        """ Successfully issue a certificate via subject alt name """
        old_stdout = sys.stdout
        sys.stdout = StringIO()
        result = acme_simple.main([
            "--account-key", self.keys['account_key'].name,
            "--csr", self.keys['san_csr'].name,
            "--acme-dir", self.tempdir,
            "--ca", self.CA,
        ])
        sys.stdout.seek(0)
        crt = sys.stdout.read().encode("utf8")
        sys.stdout = old_stdout
        out, err = Popen(["openssl", "x509", "-text", "-noout"], stdin=PIPE,
            stdout=PIPE, stderr=PIPE).communicate(crt)
        self.assertIn("Issuer: CN=Fake LE Intermediate", out.decode("utf8"))

    def test_success_cli(self):
        """ Successfully issue a certificate via command line interface """
        blarg = Popen([
            sys.executable, "-m", "acme_tiny",
            "--account-key", self.keys['account_key'].name,
            "--csr", self.keys['domain_csr'].name,
            "--acme-dir", self.tempdir,
            "--ca", self.CA,
        ], stdout=PIPE, stderr=PIPE)
        crt, err = blarg.communicate()
        out, err = Popen(["openssl", "x509", "-text", "-noout"], stdin=PIPE,
            stdout=PIPE, stderr=PIPE).communicate(crt)
        self.assertIn("Issuer: CN=Fake LE Intermediate", out.decode("utf8"))

    def test_missing_account_key(self):
        """ OpenSSL throws an error when the account key is missing """
        try:
            result = acme_simple.main([
                "--account-key", "/foo/bar",
                "--csr", self.keys['domain_csr'].name,
                "--acme-dir", self.tempdir,
                "--ca", self.CA,
            ])
        except Exception as e:
            result = e
        self.assertIsInstance(result, IOError)
        self.assertIn("Error opening Private Key", result.args[0])

    def test_missing_csr(self):
        """ OpenSSL throws an error when the CSR is missing """
        try:
            result = acme_simple.main([
                "--account-key", self.keys['account_key'].name,
                "--csr", "/foo/bar",
                "--acme-dir", self.tempdir,
                "--ca", self.CA,
            ])
        except Exception as e:
            result = e
        self.assertIsInstance(result, IOError)
        self.assertIn("/foo/bar: No such file or directory", result.args[0])

    def test_weak_key(self):
        """ Let's Encrypt rejects weak keys """
        try:
            result = acme_simple.main([
                "--account-key", self.keys['weak_key'].name,
                "--csr", self.keys['domain_csr'].name,
                "--acme-dir", self.tempdir,
                "--ca", self.CA,
            ])
        except Exception as e:
            result = e
        self.assertIsInstance(result, ValueError)
        self.assertIn("Key too small", result.args[0])

    def test_invalid_domain(self):
        """ Let's Encrypt rejects invalid domains """
        try:
            result = acme_simple.main([
                "--account-key", self.keys['account_key'].name,
                "--csr", self.keys['invalid_csr'].name,
                "--acme-dir", self.tempdir,
                "--ca", self.CA,
            ])
        except Exception as e:
            result = e
        self.assertIsInstance(result, ValueError)
        self.assertIn("Invalid character in DNS name", result.args[0])

    def test_nonexistent_domain(self):
        """ Should be unable verify a nonexistent domain """
        try:
            result = acme_simple.main([
                "--account-key", self.keys['account_key'].name,
                "--csr", self.keys['nonexistent_csr'].name,
                "--acme-dir", self.tempdir,
                "--ca", self.CA,
            ])
        except Exception as e:
            result = e
        self.assertIsInstance(result, ValueError)
        self.assertIn("but couldn't download", result.args[0])

    def test_account_key_domain(self):
        """ Can't use the account key for the CSR """
        try:
            result = acme_simple.main([
                "--account-key", self.keys['account_key'].name,
                "--csr", self.keys['account_csr'].name,
                "--acme-dir", self.tempdir,
                "--ca", self.CA,
            ])
        except Exception as e:
            result = e
        self.assertIsInstance(result, ValueError)
        self.assertIn("Certificate public key must be different than account key", result.args[0])

if __name__ == "__main__":
    unittest.main()
