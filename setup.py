#!/usr/bin/env python
from distutils.core import setup
setup(
  name = 'onetimejwt',
  packages = ['onetimejwt'],
  version = '1.0.2',
  install_requires = ['pyjwt', 'timeinterval'],
  description = 'Simple one time jwt - server and client bits',
  author = 'Brandon Gillespie',
  author_email = 'bjg-pypi@solv.com',
  url = 'https://github.com/srevenant/onetimejwt', 
  download_url = 'https://github.com/srevenant/onetimejwt/tarball/1.0',
  keywords = ['jwt', 'api', 'auth'],
  classifiers = [],
)

