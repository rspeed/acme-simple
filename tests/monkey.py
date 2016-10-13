import os, signal, socket
from tempfile import NamedTemporaryFile
from subprocess import Popen
try:
	from urllib.request import urlopen # Python 3
	from http.server import SimpleHTTPRequestHandler, HTTPServer
except ImportError:
	from urllib2 import urlopen # Python 2
	from SimpleHTTPServer import SimpleHTTPRequestHandler
	from BaseHTTPServer import HTTPServer

# domain with server.py running on it for testing
DOMAIN = os.getenv("TRAVIS_DOMAIN", "travis-ci.gethttpsforfree.com")
OPENSSL_CNF = os.getenv("OPENSSL_CNF", "etc/openssl/openssl.cnf")

# generate account and domain keys
def gen_keys():
	# good account key
	account_key = NamedTemporaryFile()
	Popen(["openssl", "genrsa", "-out", account_key.name, "2048"]).wait()

	# weak 1024 bit key
	weak_key = NamedTemporaryFile()
	Popen(["openssl", "genrsa", "-out", weak_key.name, "1024"]).wait()

	# good domain key
	domain_key = NamedTemporaryFile()
	domain_csr = NamedTemporaryFile()
	Popen(["openssl", "req", "-newkey", "rsa:2048", "-nodes", "-keyout", domain_key.name,
		"-subj", "/CN={0}".format(DOMAIN), "-out", domain_csr.name]).wait()

	# subject alt-name domain
	san_csr = NamedTemporaryFile()
	san_conf = NamedTemporaryFile()
	with open(OPENSSL_CNF) as openssl_conf:
		san_conf.write(openssl_conf.read().encode("utf8"))
	san_conf.write("\n[SAN]\nsubjectAltName=DNS:{0}\n".format(DOMAIN).encode("utf8"))
	san_conf.seek(0)
	Popen(["openssl", "req", "-new", "-sha256", "-key", domain_key.name,
		"-subj", "/", "-reqexts", "SAN", "-config", san_conf.name,
		"-out", san_csr.name]).wait()

	# invalid domain csr
	invalid_csr = NamedTemporaryFile()
	Popen(["openssl", "req", "-new", "-sha256", "-key", domain_key.name,
		"-subj", "/CN=\xC3\xA0\xC2\xB2\xC2\xA0_\xC3\xA0\xC2\xB2\xC2\xA0.com", "-out", invalid_csr.name]).wait()

	# nonexistent domain csr
	nonexistent_csr = NamedTemporaryFile()
	Popen(["openssl", "req", "-new", "-sha256", "-key", domain_key.name,
		"-subj", "/CN=404.gethttpsforfree.com", "-out", nonexistent_csr.name]).wait()

	# account-signed domain csr
	account_csr = NamedTemporaryFile()
	Popen(["openssl", "req", "-new", "-sha256", "-key", account_key.name,
		"-subj", "/CN={0}".format(DOMAIN), "-out", account_csr.name]).wait()

	return {
		"account_key": account_key,
		"weak_key": weak_key,
		"domain_key": domain_key,
		"domain_csr": domain_csr,
		"san_csr": san_csr,
		"invalid_csr": invalid_csr,
		"nonexistent_csr": nonexistent_csr,
		"account_csr": account_csr,
	}

class WellKnownHTTPRequestHandler(SimpleHTTPRequestHandler):
	def translate_path(self, path):
		# Ugh, old-style class in python 2
		return SimpleHTTPRequestHandler.translate_path(self, "/{}".format(path.split("/")[-1]))

def run_server(path, address="localhost", port=8080):
	httpd = HTTPServer((address, port), WellKnownHTTPRequestHandler)
	httpd.timeout = 0.1

	def handle_shutdown(*args):
		httpd.server_close()

	signal.signal(signal.SIGINT, handle_shutdown)
	signal.signal(signal.SIGTERM, handle_shutdown)

	while True:
		if path.poll():
			new_path = path.recv()
			print("Serving directory {0} on {1}:{2}".format(new_path, address, port))
			os.chdir(new_path)
			path.send(True)

		try:
			httpd.handle_request()
		except (ValueError, socket.error):
			# a closed socket indicates that a sigterm has been handled
			break
