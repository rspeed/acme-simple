# How to test acme-simple

Testing acme-simple requires a bit of setup since it interacts with other servers
(Let's Encrypt's staging server) to test issuing fake certificates. This readme
explains how to setup and test acme-simple yourself.

## Setup instructions

1. Make a test subdomain for a server you control. Set it as an environmental
	variable on your local test setup.
	* On your local: `export TRAVIS_DOMAIN=travis-ci.gethttpsforfree.com`
1. Reverse-proxy the test subdomain to your local.
1. Run the test suite on your local.
	* `cd /path/to/acme-tiny`
	* `coverage run --source ./ --omit ./tests/server.py -m unittest tests`
