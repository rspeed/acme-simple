import subprocess
from os import path
from setuptools import setup, find_packages


# Root directory of the project
project_dir = path.dirname(__file__)


setup(
	name='acme-simple',

	use_scm_version={'write_to': path.join(project_dir, 'acme_simple', 'VERSION.txt')},

	description="A simple script to issue and renew TLS certs from Let's Encrypt",
	long_description='',
	long_description_content_type='text/markdown; charset=UTF-8',

	url='https://github.com/rspeed/acme-simple',

	author='Rob Speed',
	author_email='rspeed@bounteo.us',

	packages=find_packages(exclude=[
		'tests',
		'tests.*'
	]),
	package_data={
		'acme-simple': ['VERSION.txt']
	},
	include_package_data=True,

	setup_requires=['setuptools_scm'],
	tests_require=['coveralls'],
	extras_require = {
		'distribution': [
			'wheel',
			'setuptools_scm'
		]
	},

	entry_points={
		'console_scripts': [
			'acme-simple = acme_simple.__main__:main'
		]
	},

	license='MIT',
	classifiers = [
		'Development Status :: 3 - Alpha',

		'Environment :: Console',
		'Intended Audience :: System Administrators',
		'Operating System :: OS Independent',

		'License :: OSI Approved :: MIT License',

		'Programming Language :: Python',
		'Programming Language :: Python :: 3',
		'Programming Language :: Python :: 3.5',
		'Programming Language :: Python :: 3.5'

		'Topic :: Security',
		'Topic :: Security :: Cryptography',
		'Topic :: Internet :: WWW/HTTP'
	]
)
