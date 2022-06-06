from setuptools import setup
from os import path
from distutils import util

with open('README.md') as f:
    long_description = f.read()

name = 'figtion'
version = '1.0.0'

### include README as main package docfile
from shutil import copyfile
_workdir = path.abspath(path.dirname(__file__))
copyfile(_workdir+'/README.md',_workdir+'/{0}/__doc__'.format(name))

setup(name=name
    , version=version
    , description='A simple configuration interface with text file support'
    , long_description=long_description
    , long_description_content_type='text/markdown'
    , author = 'Michael Stewart'
    , author_email = 'statueofmike@gmail.com'
    , url='https://github.com/statueofmike/figtion'
    , download_url="https://github.com/statueofmike/figtion/archive/{0}.tar.gz".format(version)
    , license='MIT'
    , packages=['figtion']
    , include_package_data=True     # includes files from e.g. MANIFEST.in
    , classifiers=[
        'Development Status :: 5 - Production/Stable',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3'
      ]
    , keywords='configuration secret'
    , install_requires=['pyyaml','pynacl']
    , python_requires='>=3.5'
    , zip_safe=False
      )