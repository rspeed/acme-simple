from base64 import urlsafe_b64encode
import subprocess



def jose_b64encode (value):
	"""
	Utility to encode data as JOSE-compliant Base64.

	This is simply a URL-safe Base64-encoded string with the padding stripped.

	See: https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-37#appendix-C
	"""

	return urlsafe_b64encode(value).replace('=', '')



def openssl (command, options, communicate=None):
	""" Run an openssl subprocess and return the result. """

	proc = subprocess.Popen(
		['openssl', command] + options,
		stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
	)
	stdout, stderr = proc.communicate(communicate)

	if proc.returncode != 0:
		raise IOError("OpenSSL Error: {0}".format(stderr))

	return stdout
