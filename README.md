# OVCCG

## OpenVpn client config generator

Script generates __*.ovpn__ config file with certs included

## Installation

```console
sudo pip3 install git+https://github.com/inthuriel/ovccg.git
```

### Configuration

Configuration file is stored by default in `/usr/share/ovccg/config.yaml` - all variables are described in comments.

### Usage

```console
~# ovccg --help
usage: ovccg.py [-h] [-c CONFIG] [-o OUTPUT] [-u USER] [-m EMAIL]
                [-p PASSWORD]

Script to autogenerate OPENvpn config alongside with certs

optional arguments:
  -h, --help            show this help message and exit
  -c CONFIG, --config CONFIG
                        Path to script config
  -o OUTPUT, --output OUTPUT
                        Path to save output [full, inc. filename]
  -u USER, --user USER  Username for certificate and config
  -m EMAIL, --email EMAIL
                        Email address of user
  -p PASSWORD, --password PASSWORD
                        Password for certificate [optional]
```
