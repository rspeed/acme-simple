## Important Note:

This project is undergoing significant refactoring following the fork from acme-tiny. At this time it is not in any way stable or reliable.


# acme-simple

This is a simple library and script that you can throw on your server to issue and renew [Let's Encrypt](https://letsencrypt.org/) certificates. Since it has to have access to your private Let's Encrypt account, it is designed to make auditing as straightforward as possible. The only prerequisites are python and openssl.

**Please read the source code! Using acme-simple means trusting it with your private keys!**


## Project Goals

Both in general, and how they differ from acme-tiny.

1. Simplicity

	The feature set of acme-simple is intentionally limited based on the most common use cases for certificate issuing and renewals through Let's Encrypt. This primary goal was inherited from acme-tiny.

1. Readability

	The most significant differentiation from acme-tiny is that acme-simple adopts the principle of ease-of-understanding over the size of the codebase. It is my belief that this is a superior method to make it easily auditable.

1. Extensibility

	The class `acme_simple.ACMESimple` can be extended in order to support additional features (such as DNS authentication), or to integrate into your own projects.

1. Testability

	The unit tests have been completely rewritten to allow testing to be performed in a much broader array of environments, and without a dependency on FUSE.

1. Documentation

	A full set of documentation is available, including reference examples for use in various environments. This documentation is based on PyDoc, further easing auditability.

1. Distribution and Versioning

	Rather than relying on pulling the current revision directly from GitHub, acme-simple maintains versioned releases that are available through PyPI and other sources.


## Donate

If this script is useful to you, please donate to the EFF. I don't work there, but they do fantastic work.

[https://eff.org/donate/](https://eff.org/donate/)


## Feedback/Contributing

This project has a very limited scope and codebase. Bug reports and pull requests are very welcome, but contributions should reflect the project goals.

If you want to add features that are outside the scope of this project, go for it! It's open source under the MIT license, so feel free to fork and modify as necessary.
