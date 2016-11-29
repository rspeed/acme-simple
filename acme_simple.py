#!/usr/bin/env python
from __future__ import unicode_literals
import subprocess, json, os, base64, binascii, time, hashlib, re, copy, textwrap
try:
	# Python 3
	from urllib.request import urlopen
	from urllib.error import URLError, HTTPError
except ImportError:
	# Python 2
	from urllib2 import urlopen, URLError, HTTPError

import logging

LOGGER = logging.getLogger(__name__)
LOGGER.addHandler(logging.StreamHandler())
LOGGER.setLevel(logging.INFO)


class ACMESimple(object):
	"""Create and renew SSL/TLS certificates using the ACME protocol."""

	CA = "https://acme-v01.api.letsencrypt.org"
	"""URL of the certificate authority's ACME API endpoint"""

	@property
	def header(self):
		"""Standard header used when making signed ACME requests"""
		return {
			"alg": "RS256",
			"jwk": {
				"e": self._b64(self._public[0]),
				"kty": "RSA",
				"n": self._b64(self._public[1])
			}
		}

	account_key = None
	csr = None
	acme_dir = None

	#TODO: Fetch this dynamically
	agreement_uri = "https://letsencrypt.org/documents/LE-SA-v1.1.1-August-1-2016.pdf"

	#TODO: Keep a list of unused nonces
	_nonces = []
	def add_nonce(self, nonce):
		self._nonces.append(nonce)

	def get_nonce(self):
		try:
			return self._nonces.pop()
		except IndexError:
			# No spare nonces, so continue on and get a new one
			pass

		# Fetch a new nonce and return it
		return urlopen(self.CA + "/directory").headers['Replay-Nonce']


	def __init__(self, account_key, csr, acme_dir, CA=None):
		"""Initialize the ACME client"""
		self.account_key = account_key
		self.csr = csr
		self.acme_dir = acme_dir
		self.CA = CA


	@staticmethod
	def _openssl(command, options, communicate=None):
		"""Utility to run a openssl subprocess and return the result."""

		openssl = subprocess.Popen(
			["openssl", command] + options,
			stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
		)
		stdout, stderr = openssl.communicate(communicate)

		if openssl.returncode != 0:
			raise IOError("OpenSSL Error: {0}".format(stderr))

		return stdout


	@staticmethod
	def _b64(b):
		"""Utility to encode data as JOSE-compliant Base64."""
		return base64.urlsafe_b64encode(b).replace("=", "")


	def _send_signed_request (self, url, payload, return_codes, error_message):
		"""Utility to submit a cryptographically signed HTTP request."""
		payload = self._b64(json.dumps(payload, separators=(',',':')))

		# Duplicate the default header and fetch a nonce
		header = copy.deepcopy(self.header)
		header["nonce"] = self.nonce

		protected = self._b64(json.dumps(header, separators=(',',':')))

		# Sign the request data using the account key
		signature = self._b64(
			self._openssl(
				"dgst",
				["-sha256", "-sign", self.account_key],
				communicate="{0}.{1}".format(protected, payload)
			)
		)

		# Assemble the request body
		signed_request = json.dumps({
			"header": self.header,
			"protected": protected,
			"payload": payload,
			"signature": signature
		}, separators=(',',':'))

		try:
			# Initiate the request
			response = urlopen(url, signed_request)

			try:
				# If we got a new nonce, save it for subsequent use
				self.nonce = response.headers['Replay-Nonce']
			except KeyError:
				# A nonce wasn't returned, which is fine
				LOGGER.debug("Request to {0} didn't return a nonce".format(url))
				pass

			# HTTP status code
			code = response.getcode()

			# Body
			result = response.read()
		except (HTTPError, URLError) as e:
			# We handle errors the same way, so extract the equivalent info
			code = getattr(e, "code", None)
			result = getattr(e, "reason", str(e))
		finally:
			try:
				message = return_codes[code]
				if message is not None:
					LOGGER.info(message)
				return result
			except KeyError:
				raise ValueError(error_message.format(code=code, result=result))


	def parse_account_key(self):
		"""Extract the public modulus and exponent from the account key"""
		#TODO: Give this a better name

		LOGGER.info("Parsing account key...")

		# Use openssl to output the key's properties
		account_key = self._openssl("rsa", ["-in", self.account_key, "-noout", "-text"])

		# Extract the public key's modulus and exponent using a regular expression
		#TODO: Make this more readable
		modulus, exponent = re.search(r"modulus:\n\s+00:([a-f0-9:\s]+?)\npublicExponent: ([0-9]+)", account_key, re.MULTILINE | re.DOTALL).groups()

		# Remove whitespace and colons to distill the hex string, then convert it to bytes
		modulus = binascii.unhexlify(re.sub(r"(\s|:)", "", modulus))

		# Convert to a sequence of three-bytes
		try:
			# Python 3
			exponent = exponent.as_bin(3, 'big')
		except AttributeError:
			# Python 2
			exponent = "{0:x}".format(exponent).zfill(6).decode("hex")

		# Store for later use
		self._public = (modulus, exponent)


	def register_account(self):
		LOGGER.info("Registering account...")

		self._send_signed_request(
			self.CA + "/acme/new-reg",
			{
				"resource": "new-reg",
				"agreement": self.agreement_uri
			},
			{
				201: "Registered!",
				409: "Already registered!"
			},
			"Error registering: {code} {result}"
		)


	def find_domains(self, csr):
		"""Assembles a list of all domains included in the Certificate Signing Request."""
		LOGGER.info("Parsing CSR...")

		csr = self._openssl("req", ["-in", csr, "-noout", "-text"])

		domains = set([])

		common_name = re.search(r"Subject:.*? CN=([^\s,;/]+)", csr)
		if common_name is not None:
			domains.add(common_name.group(1))

		subject_alt_names = re.search(r"X509v3 Subject Alternative Name: \n +([^\n]+)\n", csr, re.MULTILINE | re.DOTALL)
		if subject_alt_names is not None:
			for san in subject_alt_names.group(1).split(", "):
				if san.startswith("DNS:"):
					domains.add(san[4:])

		return domains


	def _verify_domain(self, domain):
		LOGGER.info("Verifying {0}...".format(domain))

		# get new challenge
		result = self._send_signed_request(
			self.CA + "/acme/new-authz",
			{
				"resource": "new-authz",
				"identifier": {"type": "dns", "value": domain}
			},
			{201: None},
			"Error requesting challenges: {code} {result}"
		)

		# Create the account's thumbprint
		account_key = json.dumps(self.header["jwk"], sort_keys=True, separators=(',', ':'))
		thumbprint = self._b64(hashlib.sha256(account_key).digest())

		# Make the challenge file
		challenge = [c for c in json.loads(result)['challenges'] if c['type'] == "http-01"][0]

		token = re.sub(r"[^A-Za-z0-9_\-]", "_", challenge['token'])

		keyauthorization = "{0}.{1}".format(token, thumbprint)
		wellknown_path = os.path.join(self.acme_dir, token)
		with open(wellknown_path, "w") as wellknown_file:
			wellknown_file.write(keyauthorization)

		# Verify that the challenge is in place
		wellknown_url = "http://{0}/.well-known/acme-challenge/{1}".format(domain, token)
		try:
			resp = urlopen(wellknown_url)
			resp_data = resp.read().strip()
			assert resp_data == keyauthorization
		except (IOError, AssertionError):
			os.remove(wellknown_path)
			raise ValueError("Wrote file to {0}, but couldn't download {1}".format(wellknown_path, wellknown_url))

		# Notify challenge are met
		self._send_signed_request(
			challenge['uri'],
			{
				"resource": "challenge",
				"keyAuthorization": keyauthorization
			},
			{202: None},
			"Error triggering challenge: {code} {result}"
		)

		# Wait for challenge to be verified
		while True:
			try:
				resp = urlopen(challenge['uri'])
				challenge_status = json.loads(resp.read())
			except IOError as e:
				raise ValueError("Error checking challenge: {0} {1}".format(e.code, json.loads(e.read())))

			if challenge_status['status'] == 'pending':
				# No response yet, wait two seconds before trying again
				time.sleep(2)
			elif challenge_status['status'] == 'valid':
				LOGGER.info("{0} verified!".format(domain))
				os.remove(wellknown_path)
				break
			else:
				raise ValueError("{0} challenge did not pass: {1}".format(domain, challenge_status))


	def fetch_certificate(self):
		# Check each domain
		for domain in self.domains:
			self._verify_domain(domain)

		# get the new certificate
		LOGGER.info("Signing certificate...")

		# Convert the CSR to DER
		der_csr = self._openssl("req", ["-in", self.csr, "-outform", "DER"])

		# Request the signed certificate
		result = self._send_signed_request(
			self.CA + "/acme/new-cert",
			{
				"resource": "new-cert",
				"csr": self._b64(der_csr)
			},
			{201: None},
			"Error signing certificate: {code} {result}"
		)

		# Build the certificate and return it
		LOGGER.info("Certificate signed!")
		return """-----BEGIN CERTIFICATE-----\n{0}\n-----END CERTIFICATE-----\n""".format(textwrap.fill(base64.b64encode(result), 64))

