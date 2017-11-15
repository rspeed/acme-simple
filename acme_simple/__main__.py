import sys, argparse, logging
from . import ACMESimple


def main(argv=None):
	parser = argparse.ArgumentParser(
		formatter_class=argparse.RawDescriptionHelpFormatter,
		description="This script automates the process of getting a signed TLS certificate from Let's Encrypt using the ACME protocol. It will need to be run on your server and have access to your private account key, so PLEASE READ THROUGH IT!",
		epilog = "acme-simple --account-key ./account.key --csr ./domain.csr --acme-dir /usr/share/nginx/html/.well-known/acme-challenge/ > signed.crt"
	)
	parser.add_argument("--account-key", required=True, help="path to your Let's Encrypt account private key")
	parser.add_argument("--csr", required=True, help="path to your certificate signing request")
	parser.add_argument("--acme-dir", required=True, help="path to the .well-known/acme-challenge/ directory")
	parser.add_argument("--quiet", action="store_const", const=logging.ERROR, help="suppress output except for errors")
	parser.add_argument("--ca", help="directory URL for the certificate authority")

	args = parser.parse_args(argv)
	#LOGGER.setLevel(args.quiet or LOGGER.level)

	client = ACMESimple(args.account_key, args.csr, args.acme_dir, directory_url=args.ca)
	client.register_account()
	sys.stdout.write(client.fetch_certificate())


if __name__ == "__main__": # pragma: no cover
	main(sys.argv[1:])
