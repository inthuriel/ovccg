#!/usr/bin/env python2
from shutil import copyfile
import os
from setuptools import setup, find_packages
setup(
    name="ovccg",
    version="0.2",
    packages=find_packages(),

    install_requires=[
        'pyyaml>3.0',
        'unidecode>1.0'],

    entry_points={
        'console_scripts': [
            'ovccg = ovccg:run'
        ]
    },

    author="Mikolaj Niedbala",
    author_email="kontakt@mikolajniedbala.pl",
    description="OVCCG - OpenVpn client config generator",
    license="GNU Library or Lesser General Public License (LGPL)",
    url="https://dev.metatron.com.pl",

)
if not os.path.exists('/etc/openvpn/ovccg'):
    os.makedirs('/etc/openvpn/ovccg', exist_ok=True)

if not os.path.exists('/etc/openvpn/ovccg/config.yaml'):
    copyfile('config.yaml', '/etc/openvpn/ovccg/config.yaml')