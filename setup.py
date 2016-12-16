# -*- coding: utf-8 -*-
import os

from setuptools import find_packages
from setuptools import setup


base_dir = os.path.dirname(__file__)
setup(
    name='index-health',
    version='0.1',
    description='Runs report against ElasticSearch indices',
    author='Anton Sherkhonov',
    author_email='sherkhonov@gmail.com',
    setup_requires='setuptools',
    license='Copyright 2016 Red Hat',
    entry_points={
        'console_scripts': ['reporter=pipeline_reporter.reporter:main']},
    packages=find_packages(),
    install_requires=[
        'argparse',
        'elasticsearch<3.0.0',  # Elastalert is not yet compatible with ES5
        'jsonschema',
        'mock',
        'python-dateutil',
        'PyStaticConfiguration',
        'pyyaml',
        'simplejson',
        'croniter',
        'configparser',
        'texttable',
        'requests'
    ]
)
