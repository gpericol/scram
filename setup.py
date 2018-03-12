from setuptools import setup

setup(
  name = 'scram_dh',
  packages = ['scram_dh'],
  version = '1.0',
  description = 'A version of SCRAM-SHA256 Authentication under DH steroids',
  author = 'Gianluca Pericoli, Luca Zanolini',
  keywords = ['crypto', 'Diffie Hellman', 'Key Exchange', 'SCRAM', 'SHA256', 'authentication'],
  url='https://github.com/gpericol/scram',
  license='GPLv3',
  classifiers = [
    	'Programming Language :: Python :: 2.7',
		'Topic :: Security :: Authentication',
		],
)