# OVCCG
### OpenVpn client config generator

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
usage: ovccg [-h] [-c CONFIG] [-o OUTPUT]

Script to autogenerate OPENvpn config alongside with certs

optional arguments:
  -h, --help            show this help message and exit
  -c CONFIG, --config CONFIG
                        Path to script config
  -o OUTPUT, --output OUTPUT
                        Path to save output [full, inc. filename]
```
