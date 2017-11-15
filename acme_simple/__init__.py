import os
import json
import re
import textwrap
from binascii import unhexlify
from base64 import b64encode
from hashlib import sha256
from copy import copy, deepcopy
from time import sleep
from urllib.request import urlopen
from urllib.error import URLError, HTTPError

from .utils import jose_b64encode, openssl

import logging


logging.basicConfig(level=logging.INFO)


class ACMESimple:
	"""
	Create and renew SSL/TLS certificates using the ACME protocol.
	"""

	directory_url = 'https://acme-v01.api.letsencrypt.org'
	""" URL of the CA's root directory. """

	account = None
	csr = None

	acme_dir = None
	""" Path to the directory where wellknown challenges will be served. """

	agreement_uri = None
	""" The URI of the TOS agreement document. """

	directory = None
	""" Mapping of resource names to their API endpoints. """



	_nonces = []

	@property
	def nonce (self):
		"""
		Maintains a queue of anti-replay nonces supplied by the ACME server.

		ACME servers include a new nonce in the response headers. Saving them allows us to avoid making additional HTTP requests.

		When accessed, it returns the next nonce in the queue. If the queue is empty, a new nonce is fetched from the server.
		"""

		if not len(self._nonces):
			# The queue is empty! But no worries, _get_main_directory will fetch a new one.
			self._get_main_directory()

		return self._nonces.pop()


	@nonce.setter
	def nonce (self, nonce):
		""" Property setter to add a nonce to the end of the queue. """
		self._nonces.append(nonce)



	def __init__ (self, account_key_path, csr_path, acme_dir, directory_url=None):
		""" Initialize the ACME client. """

		self.account = Account(account_key_path)
		self.csr = CSR(csr_path)
		self.acme_dir = acme_dir

		if directory_url is not None:
			self.directory_url = directory_url

		# Make this local to the object
		self._nonces = copy(self._nonces)



	def _get_main_directory (self):
		""" Fetches information from the /directory API. """

		# Fetch a new nonce and return it
		response = urlopen(self.directory_url)

		# Nonce
		self.nonces = response.headers['Replay-Nonce']

		# Main directory map
		self.directory = json.load(response)

		try:
			# Remove the meta element and grab the URI of the TOS document
			self.agreement_uri = self.directory.pop('meta')['terms-of-service']

		except KeyError:
			raise Exception("Could not get the URI for Terms-of-Service agreement.")



	def _call_api (self, resource, payload, return_codes, error_message):
		""" Convenience method for simple API calls. """

		payload['resource'] = resource

		return self._send_signed_request(self.directory[resource], payload, return_codes, error_message)



	def _send_signed_request (self, url, payload, return_codes, error_message):
		""" Submits a cryptographically-signed request to the CA. """

		payload = jose_b64encode(json.dumps(payload, separators=(',', ':')))

		# Duplicate the default header and fetch a nonce
		header = deepcopy(self.account.header)
		header['nonce'] = self.nonce

		protected = jose_b64encode(json.dumps(header, separators=(',', ':')))

		# Sign the request data using the account key
		signature = jose_b64encode(
			openssl('dgst', ['-sha256', '-sign', self.account.path], communicate='{0}.{1}'.format(protected, payload))
		)

		# Assemble the request body
		signed_request = json.dumps({
			'header': self.account.header,
			'protected': protected,
			'payload': payload,
			'signature': signature
		}, separators=(',',':'))

		try:
			# Initiate the request
			response = urlopen(url, signed_request)

			try:
				# If we got a new nonce, save it for subsequent use
				self.nonce = response.headers['Replay-Nonce']
			except KeyError:
				# A nonce wasn't returned, which is fine
				logging.debug("Request to {0} didn't return a nonce".format(url))
				pass

		except HTTPError as response:
			code = response.getcode()
			result = response.read()

		except URLError as e:
			# We handle success and failure the same way
			code = getattr(e, 'code', None)
			result = getattr(e, 'reason', str(e))

		else:
			code = response.getcode()
			result = response.read()

		try:
			message = return_codes[code]
			if message is not None:
				logging.info(message)
			return result
		except KeyError:
			raise ValueError(error_message.format(code=code, result=result))



	def register_account (self):
		logging.info("Registering account...")

		self._call_api(
			'new-reg',
			{ 'agreement': self.agreement_uri },
			{
				201: 'New account registered.',
				409: 'Account is already registered.'
			},
			"Error registering: {code} {result}"
		)


	def verify_domain_challenge (self, domain):
		logging.info("Verifying {0}...".format(domain))

		# Get new challenge
		result = self._call_api(
			'new-authz',
			{ 'identifier': {'type': 'dns', 'value': domain} },
			{ 201: None },
			"Error requesting challenges: {code} {result}"
		)

		# Get the first http-01 challenge
		challenge = [c for c in json.loads(result)['challenges'] if c['type'] == 'http-01'][0]

		token = re.sub(r'[^A-Za-z0-9_\-]', '_', challenge['token'])

		key_authorization = '{0}.{1}'.format(token, self.account.thumbprint)
		wellknown_path = os.path.join(self.acme_dir, token)

		# Write the challenge authorization file to wellknown_path
		with open(wellknown_path, 'w') as wellknown_file:
			wellknown_file.write(key_authorization)

		# TODO: Make this optional
		# Verify that the challenge is in place
		wellknown_url = 'http://{0}/.well-known/acme-challenge/{1}'.format(domain, token)
		try:
			assert urlopen(wellknown_url).read().strip() == key_authorization

		except (IOError, AssertionError):
			os.remove(wellknown_path)
			raise ValueError("Wrote file to {0}, but couldn't download {1}".format(wellknown_path, wellknown_url))

		# Tell the ACME server to verify the challenge
		self._send_signed_request(
			challenge['uri'],
			{
				'resource': 'challenge',
				'keyAuthorization': key_authorization
			},
			{ 202: None },
			"Error triggering challenge: {code} {result}"
		)

		# Wait for the challenge to be verified
		while True:
			try:
				resp = urlopen(challenge['uri'])
				challenge_status = json.loads(resp.read())

			except HTTPError as e:
				raise ValueError("Error checking challenge: {0} {1}".format(e.code, json.loads(e.read())))

			if challenge_status['status'] == 'pending':
				# No response yet, wait two seconds before trying again
				sleep(2)

			elif challenge_status['status'] == 'valid':
				logging.info("{0} verified.".format(domain))
				os.remove(wellknown_path)
				break

			else:
				raise ValueError("{0} challenge did not pass: {1}".format(domain, challenge_status))


	def fetch_certificate (self):
		# Check each domain
		for domain in self.csr.domains:
			self.verify_domain_challenge(domain)

		# get the new certificate
		logging.info("Signing certificate...")

		# Convert the CSR from PEM to DER
		der_csr = openssl('req', ['-in', self.csr.path, '-outform', 'DER'])

		# Request the signed certificate
		result = self._call_api(
			'new-cert',
			{ 'csr': jose_b64encode(der_csr) },
			{ 201: None },
			"Error signing certificate: {code} {result}"
		)

		# Build the certificate and return it
		logging.info("Certificate signed.")

		return '\n'.join((
			'-----BEGIN CERTIFICATE-----',
			str(textwrap.fill(b64encode(result), 64)),
			'-----END CERTIFICATE-----'
		))



class Account:
	path = None

	public_modulus = None
	public_exponent = None
	header = None
	thumbprint = None



	def __init__ (self, file_path):
		self.path = file_path
		(self.public_modulus, self.public_exponent) = self._get_public_key()
		self.header = self._get_header()
		self.thumbprint = self._get_thumbprint()


	def _get_public_key (self):
		""" Extracts the public modulus and exponent from the account key. """

		logging.info("Parsing account key...")

		# Use openssl to output the key's properties
		account_key = openssl('rsa', ['-in', self.path, '-noout', '-text'])

		# Extract the public key's modulus and exponent using a regular expression
		modulus, exponent = re.findall(r'modulus:\n\s+00:([a-f0-9:\s]+?)\npublicExponent: ([0-9]+)', account_key)

		# Remove whitespace and colons to distill the hex string, then convert it to bytes
		modulus = unhexlify(re.sub(r'(\s|:)', '', modulus))

		# Convert to a sequence of three-bytes
		exponent = exponent.as_bin(3, 'big')

		return modulus, exponent


	def _get_header(self):
		""" Create the standard header used when making signed ACME requests. """

		return {
			'alg': 'RS256',
			'jwk': {
				'e': jose_b64encode(self.public_modulus),
				'kty': 'RSA',
				'n': jose_b64encode(self.public_exponent)
			}
		}


	def _get_thumbprint (self):
		""" Create the account's thumbprint. """

		if self._thumbprint is None:
			account_key = json.dumps(self.header['jwk'], sort_keys=True, separators=(',', ':'))
			self._thumbprint = jose_b64encode(sha256(account_key).digest())

		return self._thumbprint



class CSR:
	path = None
	domains = []


	def __init__ (self, file_path):
		self.path = file_path


		# Get a list of domains included in the CSR
		logging.info("Parsing CSR...")

		# Produce human-readable information about the CSR with a limited number of options
		csr = openssl('req', ['-in', self.path, '-noout', '-reqopt', 'no_header,no_version,no_pubkey,no_sigdump' '-text'])

		domains = set()

		# Subject common name
		domains.update(re.findall(r'Subject:.*? CN=([^\s,;/]+)', csr))

		# Subject alt names
		domains.update(re.findall(r'DNS:([^\n, ]+)', csr))

		self.domains = list(domains)

