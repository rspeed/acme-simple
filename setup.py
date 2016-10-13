from setuptools import setup

setup(
    name="acme-simple",
    use_scm_version=True,
    url="https://github.com/rspeed/acme-simple",
    author="Rob Speed",
    author_email="speed.rob@gmail.com",
    description="A simple script to issue and renew TLS certs from Let's Encrypt",
    license="MIT",
    py_modules=['acme_simple'],
    entry_points={'console_scripts': [
        'acme-simple = acme_simple:main',
    ]},
    setup_requires=['setuptools_scm'],
    tests_require=['coveralls'],
    extras_require = {
        'distribution': [
            'wheel',
            'setuptools_scm'
        ]
    },
    classifiers = [
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5'
    ]
)
