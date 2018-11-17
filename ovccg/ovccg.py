#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OVCCG - OpenVpn client config generator
Script generates *.ovpn config file with certs included
"""
import argparse
import getpass
import os
import re
import shutil
import subprocess as sp

import unidecode
import yaml


class OVCCG:
    """
    OVCCG - OpenVpn client config generator
    Python3 class to automatic generation client configs for openvpn alongside with certs
    """
    def __init__(self, runtime_vars):
        self.__runtime_args = runtime_vars
        self.__config = self.__parse_config(self.__runtime_args.config)

        self.__config_save_path = self.__config.get('save_path', '/etc/openvpn/client').rstrip('/')
        self.__filename = None
        self.__colours = ColorPrint()

    @staticmethod
    def __parse_config(path):
        with open(path, 'r') as config_file:
            try:
                yaml_cfg = yaml.load(config_file)
            except yaml.YAMLError as exc:
                print(exc)

        if isinstance(yaml_cfg['server'], str):
            yaml_cfg['server'] = [yaml_cfg['server']]

        return yaml_cfg

    def __prepare_ovpn_config_object(self, certs):
        config_lines = list()
        config_lines.append('# OpenVPN client config')
        config_lines.append('# generated automatically by OVCCG software')
        config_lines.append('# Script written by Mikolaj Niedbala')
        config_lines.append('# visit https://dev.metatron.com.pl || https://github.com/inthuriel')
        config_lines.append('')
        config_lines.append('client')
        config_lines.append('dev {}'.format(self.__config.get('dev', 'tap')))
        config_lines.append('proto {}'.format(self.__config.get('proto', 'tcp')))
        for position, server in enumerate(self.__config.get('server')):
            config_lines.append('{active}remote '
                                '{host} {port}'.format(active='' if position == 0 else '#',
                                                       host=server,
                                                       port=self.__config.get('port', 1194)))
        config_lines.append('resolv-retry infinite')
        config_lines.append('nobind')
        config_lines.append('comp-lzo')
        config_lines.append('auth-nocache')
        config_lines.append('persist-key')
        config_lines.append('persist-tun')
        config_lines.append('ns-cert-type server')
        config_lines.append('verb {}'.format(self.__config.get('verb', 3)))
        if self.__config.get('tls_path'):
            config_lines.append('key-direction 1')
        config_lines.append('cipher AES-256-CBC')
        if self.__config.get('redirect-gateway'):
            config_lines.append('redirect-gateway {}'.format(self.__config.get('redirect-gateway')))
        for cert, content in certs.items():
            config_lines.append('<{}>'.format(cert))
            config_lines.append(content.rstrip('\n'))
            config_lines.append('</{}>'.format(cert))

        return config_lines

    @staticmethod
    def __produce_ovpn_config(config_object):
        cfg_str = '\n'.join(config_object)
        return cfg_str

    def __collect_onetime_data(self):
        username = input(self.__colours.colorize('[red][Required][/red] '
                                                 '[blue]Please enter name for the VPN user: [/blue]'
                                                 )
                         )
        while not username:
            print(self.__colours.colorize('[red]Set username for proper cert generation[/red]'))
            username = input(self.__colours.colorize('[blue]Please enter name for the '
                                                     'VPN user: [/blue]'))
        email = input(self.__colours.colorize('[red][Required][/red] '
                                              '[blue]Please add VPN user email: [/blue]'))
        while not email:
            print(self.__colours.colorize('[red]Add email to use in cert generation[/red]'))
            email = input(self.__colours.colorize('[blue]Please add VPN user email: [/blue]'))

        password = getpass.getpass(prompt=self.__colours.colorize('[green]Enter cert password, '
                                                                  'leave empty if not needed: '
                                                                  '[/green]'))
        while password and len(password) < 3:
            print(self.__colours.colorize('[red] Password length should be at least 4[/red]'))
            password = getpass.getpass(prompt=self.__colours.colorize('[green]Enter cert password, '
                                                                      'leave empty if not needed: '
                                                                      '[/green]'))

        file_name = unidecode.unidecode(re.sub(r'_+', '_',
                                               re.sub(r'\W', '_', username.strip())
                                               ).strip('_').lower()).encode('ascii').decode("utf-8")

        return {'username': username, 'email': email, 'password': password, 'file_name': file_name}

    @staticmethod
    def __call_process_with_check(command, verbose=False):
        workload = re.split(r'\s+(?=(?:[^\'"]*[\'"][^\'"]*[\'"])*[^\'"]*$)', command)
        workload = list(filter(None, workload))
        workload = [elem.strip('"') for elem in workload]

        pipe = sp.Popen(workload,
                        stdout=sp.PIPE, stderr=sp.PIPE)
        stdout, stderr = pipe.communicate()

        if pipe.returncode > 0:
            raise UnsuccessfulProcess(stderr)

        if not verbose:
            stdout = None

        return stdout

    def __generate_rsa_entity(self, entity_name, command, config, certs=None):
        try:
            self.__call_process_with_check(command)
        except UnsuccessfulProcess as error:
            print(self.__colours.colorize('[red]{} generation fails with error:[/red]'.format(
                entity_name)))
            print(self.__colours.colorize('[red]{}[/red]'.format(error)))
            exit(1)

        if certs:
            with open(config.get(entity_name), 'r') as user_key:
                user_key_content = user_key.read()
            certs.setdefault(entity_name, user_key_content)

        return certs

    def __prepare_certs(self, user_data):
        certs = dict()
        crt_data = self.__config.get('crt', {})

        config_data = {
            'country': crt_data.get('country', 'PL').upper(),
            'province': crt_data.get('province', 'WLKP').upper(),
            'city': crt_data.get('city', 'Poznan'),
            'org': crt_data.get('org', 'Private'),
            'ou': crt_data.get('ou', 'Users'),
            'email': user_data.get('email', 'sample@default.org'),
            'cn': user_data.get('username'),
            'days': crt_data.get('days', 3649),
            'password': '' if not user_data.get('password') else 'pass:{}'.format(
                user_data.get('password')),
            'ca_crt_path': self.__config.get('ca_cert_path', '/etc/openvpn/certs/ca.crt'),
            'ca_key_path': self.__config.get('ca_key_path', '/etc/openvpn/certs/ca.key'),
        }
        config_data.setdefault('subj', '/emailAddress={email}'
                                       '/C={country}/ST={province}/L={city}'
                                       '/O={org}/OU={ou}/CN={cn}'.format(**config_data))

        # create certs and directories for cert and config
        if self.__runtime_args.output is not None:
            dir_path = '{base_path}/{cert_dir}'.format(base_path='/tmp',
                                                       cert_dir=user_data.get('file_name'))
        else:
            dir_path = '{base_path}/{cert_dir}'.format(base_path=self.__config_save_path,
                                                       cert_dir=user_data.get('file_name'))

        if not os.path.exists(dir_path):
            os.makedirs(dir_path, exist_ok=True)

        # get ca cert to config
        with open(config_data.get('ca_crt_path'), 'r') as ca_crt:
            ca_content = ca_crt.read()

        certs.setdefault('ca', ca_content)

        # get tls cert to config
        if self.__config.get('tls_path'):
            with open(self.__config.get('tls_path'), 'r') as tls_crt:
                tls_content = tls_crt.read()

            certs.setdefault('tls-auth', tls_content)

        config_data.setdefault('key', '{}/{}.key'.format(dir_path, user_data.get('file_name')))
        config_data.setdefault('csr', '{}/{}.csr'.format(dir_path, user_data.get('file_name')))
        config_data.setdefault('cert', '{}/{}.crt'.format(dir_path, user_data.get('file_name')))

        # generate key
        print('Generating key')
        gen_key_str = 'openssl genrsa {aes} {pass_phrase} {password} -out {key} 4096'.format(
            pass_phrase='-passout' if config_data.get('password') else '',
            aes='-aes128' if config_data.get('password') else '',
            **config_data)
        certs = self.__generate_rsa_entity('key', gen_key_str, config_data, certs)

        # generate csr
        print('Generating csr')
        pass_phrase = '-passin' if config_data.get('password') else ''
        gen_csr_str = 'openssl req -new ' \
                      '-key {key} -out {csr} ' \
                      '-subj "{subj}" {pass_phrase} {password}'.format(pass_phrase=pass_phrase,
                                                                       **config_data)
        self.__generate_rsa_entity('csr', gen_csr_str, config_data)

        # generate crt
        print('Generating cert from csr')
        gen_crt_str = 'openssl x509 -req -days {days} -in {csr} -CA {ca_crt_path} ' \
                      '-CAkey {ca_key_path} -set_serial {serial} ' \
                      '-out {cert}'.format(serial=int.from_bytes(os.urandom(14),
                                                                 byteorder="little"),
                                           **config_data)
        certs = self.__generate_rsa_entity('cert', gen_crt_str, config_data, certs)

        self.__filename = user_data.get('file_name')

        print(self.__colours.colorize('[blue]Removing tmp files.[/blue]'))
        os.remove(config_data.get('csr'))

        # remove temp directory if set
        if self.__runtime_args.output:
            shutil.rmtree(dir_path)

        return certs

    def cfg_get(self):
        """
        Main method of OVCCG class used for run config generation algorithm
        :return: None
        """
        config = self.__produce_ovpn_config(
            self.__prepare_ovpn_config_object(
                self.__prepare_certs(
                    self.__collect_onetime_data())))

        if self.__config_save_path and not self.__runtime_args.output:
            config_save_path = '{base}/{name}/{name}.ovpn'.format(base=self.__config_save_path,
                                                                  name=self.__filename)
        elif self.__runtime_args.output:
            config_save_path = self.__runtime_args.output

        with open(config_save_path, 'w') as file:
            file.write(config)
        print(self.__colours.colorize('[green]*.ovpn config file saved to:[/green] '
                                      '[blue]{}[/blue]'.format(config_save_path)))

    def runtime_print(self):
        """
        Metrond to print script runtime parameters and config parameters
        :return:
        """
        print(self.__colours.colorize('[blue]Script runtime vars[/blue]'))
        print(self.__runtime_args)
        print(self.__colours.colorize('[blue]Script config vars[/blue]'))
        print(self.__config)


class UnsuccessfulProcess(Exception):
    """
    Exception to catch unsuccessful process execution
    """
    pass


class ColorPrint:
    """
    Class allowing colorize python string outputs
    """
    def __init__(self):
        self.__colours = {
            'red': '\x1b[1;31m',
            'green': '\x1b[1;32m',
            'yellow': '\x1b[1;33m',
            'blue': '\x1b[1;34m',
            'default': '\x1b[0m'
        }
        __regex = r'(\[\/?({})\])'.format('|'.join(key for key, value in self.__colours.items()))
        __regex_replace = r'(\[\/({})\])'.format('|'.join(key if key != 'default' else '' for
                                                          key, value in self.__colours.items()))
        self.__colors_regex = re.compile(__regex, re.MULTILINE)
        self.__colors_regex_replace = re.compile(__regex_replace, re.MULTILINE)

    def colorize(self, message):
        """
        add colors to defined message, to pass color use [color_name][/color_name] tags
        :param message: str message
        :return: str colorized
        """
        ending_tags_to_replace = '|'.join(re.escape(entity[0]) for entity in
                                          self.__colors_regex_replace.findall(message))
        message = re.sub(ending_tags_to_replace, '[default]', message)
        for colour_entity in list(set(self.__colors_regex.findall(message))):
            message = re.sub(re.escape(colour_entity[0]), self.__colours.get(colour_entity[1], ''),
                             message)

        return message

    def available_colors(self):
        """
        list colors available to use in colorize method in tags [color_name][/color_name]
        :return: dict
        """
        print(self.__colours)


def run():
    """
    Parse args and call proper function
    """
    parser = argparse.ArgumentParser(description='Script to autogenerate OPENvpn '
                                                 'config alongside with certs')
    parser.add_argument('-c', '--config', help='Path to script config',
                        default='/usr/share/ovccg/config.yaml')
    parser.add_argument('-o', '--output', help='Path to save output [full, inc. filename]')
    args = parser.parse_args()

    ovccg = OVCCG(args)
    ovccg.cfg_get()


if __name__ == "__main__":
    run()
