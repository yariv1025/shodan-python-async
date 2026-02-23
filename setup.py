#!/usr/bin/env python

from setuptools import setup


with open('requirements.txt', 'r') as f:
    DEPENDENCIES = [line.split('#')[0].strip() for line in f if line.strip() and not line.startswith('#')]

with open('README.rst', 'r') as f:
    README = f.read()


setup(
    name='shodan',
    version='1.31.0',
    description='Python library and command-line utility for Shodan (https://developer.shodan.io)',
    long_description=README,
    long_description_content_type='text/x-rst',
    author='John Matherly',
    author_email='jmath@shodan.io',
    url='https://github.com/achillean/shodan-python',
    packages=['shodan', 'shodan.cli', 'shodan.cli.converter'],
    entry_points={'console_scripts': ['shodan=shodan.__main__:main']},
    install_requires=DEPENDENCIES,
    keywords=['security', 'network'],
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Natural Language :: English',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
)
