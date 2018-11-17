#!/usr/bin/env python2
import os
from shutil import copyfile

from setuptools import setup, find_packages
from setuptools.command.install import install

with open("README.md", "r") as fh:
    long_description = fh.read()


class PostInstallCommand(install):
    def run(self):
        if not self.dry_run:
            if not os.path.exists('/usr/share/ovccg'):
                os.makedirs('/usr/share/ovccg', exist_ok=True)

            if not os.path.exists('/usr/share/ovccg/config.yaml'):
                copyfile('./_data/config.yaml', '/usr/share/ovccg/config.yaml')

        install.run(self)


setup(
    name="ovccg",
    version="0.8",
    packages=find_packages(),
    install_requires=[
        'pyyaml>3.11',
        'unidecode>1.0'],
    entry_points={
        'console_scripts': [
            'ovccg = ovccg:run'
        ]
    },
    author="Mikolaj Niedbala",
    author_email="kontakt@mikolajniedbala.pl",
    description="OVCCG - OpenVpn client config generator",
    long_description=long_description,
    long_description_content_type="text/markdown",
    license="GNU Library or Lesser General Public License (LGPL)",
    url="https://dev.metatron.com.pl",
    classifiers=[
        "Programming Language :: Python :: 3",
        "Development Status :: 5 - Production/Stable",
        "License :: OSI Approved :: GNU Lesser General Public License v3 or later (LGPLv3+)",
        "Operating System :: POSIX :: Linux"
    ],
    cmdclass={
        'install': PostInstallCommand,
    },
)
