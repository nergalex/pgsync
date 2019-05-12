# -*- coding: utf-8 -*-
"""
--- Object ---
Encrypt/decrypt configuration file

--- Usage ---
Run 'python nuage_pgsync_configuration.py -h' for an overview

--- Documentation ---

--- Author ---
DA COSTA Alexis <alexis.dacosta@bt.com>

--- Examples ---

--- Roadmap ---

--- Request For Feature ---
"""

import argparse
import configparser
import base64
import os
import getpass
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def main():
    # Handling arguments
    """
    args                = get_args()
    debug               = args.debug
    verbose             = args.verbose
    log_file            = args.logfile
    ini_file            = args.inifile
    password            = args.password
    seed                = args.seed

    """
    # Bouchonnage arguments
    debug = True
    verbose = True
    log_file = 'logs/configuration_encryption.log'
    ini_file = 'nuage-pgsync.ini'

    # Logging settings
    logger = setup_logging(debug, verbose, log_file)

    # Get parameters from INI file
    my_config = Enterprise(ini_file, logger)
    """
    password = "cyber"
    my_config._generate_seed()
    my_config._generate_master_key(password=password.encode())
    message = "hello world"
    token64_byte = my_config._encrypt_message(message)
    token64_txt = str(token64_byte).split('\'')[1]
    print("encrypted message: %s" % token64_txt)

    token64_byte = token64_txt.encode()
    message = my_config._decrypt_message(token64_byte).decode()
    print("decrypted message: %s" % message)
    """
    my_config.fetch()


def get_args():
    """ Supports the command-line arguments listed below.

    """
    parser = argparse.ArgumentParser(description="Encrypt/decrypt configuration file.")
    parser.add_argument('-d', '--debug',
                        required=False,
                        help='Enable debug output',
                        dest='debug',
                        action='store_true')
    parser.add_argument('-v', '--verbose',
                        required=False,
                        help='Enable verbose output',
                        dest='verbose',
                        action='store_true')
    parser.add_argument('-l', '--log-file',
                        required=False,
                        help='File to log to (default = stdout)',
                        dest='logfile',
                        type=str,
                        default="configuration_encryption.log")
    parser.add_argument('-p', '--ini-file',
                        required=False,
                        help='File that contain parameters',
                        dest='inifile',
                        type=str,
                        default="nuage-pgsync.ini")
    parser.add_argument('-P', '--password',
                        required=False,
                        help='Password to encrypt/decrypt file',
                        dest='password',
                        type=str)
    parser.add_argument('-s', '--seed',
                        required=False,
                        help='Seed to encrypt/decrypt file',
                        dest='seed',
                        type=str)
    args = parser.parse_args()
    return args


def setup_logging(debug, verbose, log_file):
    """ Setup logging level

    """
    import logging
    if debug:
        log_level = logging.DEBUG
    elif verbose:
        log_level = logging.INFO
    else:
        log_level = logging.WARNING

    logging.basicConfig(filename=log_file, format='%(asctime)s %(levelname)s %(message)s', level=log_level)
    logger = logging.getLogger(__name__)
    return logger


class Enterprise (object):
    def __init__(self, ini_file, logger):
        self.logger = logger
        self.ini_file = ini_file
        self.config = None
        self.seed = None
        self.master_key = None
        self.fernet_object = None

    def _get_interactive_password(self):
        self.logger.info('Requesting password from user')
        password = getpass.getpass(prompt='Enter password to encrypt/decrypt configuration')
        password_byte = password.encode()
        return password_byte

    def _get_interactive_seed(self):
        self.logger.info('Requesting seed from user')
        seed64_txt = getpass.getpass(prompt='Enter seed to decrypt configuration')
        seed64_byte = seed64_txt.encode()
        try:
            self.seed = base64.urlsafe_b64decode(seed64_byte)
        except Exception as e:
            self.logger.error("%s: Incorrect given seed: %s" % (__class__, e))
            raise

    def _generate_seed(self):
        # generate seed
        self.seed = os.urandom(16)
        self.logger.info('Encryption started')
        print("Please store your seed (seed.txt file) in a reliable location "
              "in order to derive the same key from the password in the future:")

        # save seed
        with open("seed.txt", mode='w+t') as seed_file:
            seed_file.write(str(base64.urlsafe_b64encode(self.seed)).split('\'')[1])

    def _generate_master_key(self, password):
        """
        Generate seed if seed not in parameter. Prompt user to store it
        Generate Master Key based on key and password
        :param password: format : byte in base64
        :return: master_key. format : byte in base64
        """
        # Generate master key
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.seed,
            iterations=100000,
            backend=default_backend()
        )
        self.master_key = base64.urlsafe_b64encode(kdf.derive(password))
        self.fernet_object = Fernet(self.master_key)

        return self.master_key

    def _encrypt_message(self, secret_message_text):
        token = self.fernet_object.encrypt(secret_message_text.encode())
        return token

    def _decrypt_message(self, token):
        try:
            secret_message_byte = self.fernet_object.decrypt(token)
        except Exception as e:
            self.logger.error("Failed to decrypt configuration file with given password and seed: %s" % e)
            raise
        return secret_message_byte

    def fetch(self):
        # load file
        self.config = configparser.RawConfigParser()
        self.config.read(self.ini_file)

        if self.config['GENERAL']['Encryption'] == "yes":
            # decrypt and load configuration
            password_byte = self._get_interactive_password()
            if self.config['GENERAL']['Encryption_status'] == "clear_text":
                # encrypt file
                self._generate_seed()
                self._generate_master_key(password=password_byte)
                self._encrypt_file()
            else:
                # file already encrypted
                self._get_interactive_seed()
                self._generate_master_key(password=password_byte)
            self._load_encrypted_configuration()
        else:
            # load configuration
            if self.config['GENERAL']['Encryption_status'] != "clear_text":
                # decrypt file
                password_byte = self._get_interactive_password()
                self._get_interactive_seed()
                self._generate_master_key(password=password_byte)
                self._decrypt_file()
            else:
                self.config.read(self.ini_file)

    def _encrypt_file(self):
        """
        Encrypt value of password like parameters
        :return:
        """
        for section_title, section in self.config.items():
            for parameter, value in section.items():
                if "password" in parameter.lower():
                    token64_byte = self._encrypt_message(value)
                    token64_txt = str(token64_byte).split('\'')[1]
                    self.config[section_title][parameter] = token64_txt
        # change status
        self.config['GENERAL']['Encryption_status'] = "encrypted"
        # save
        self.save()

    def save(self):
        # save
        ini_file = open(self.ini_file, mode='w+t')
        self.config.write(ini_file, space_around_delimiters=True)
        ini_file.close()

    def _load_encrypted_configuration(self):
        for section_title, section in self.config.items():
            for parameter, value in section.items():
                if "password" in parameter.lower():
                    token64_txt = value
                    token64_byte = token64_txt.encode()
                    message = self._decrypt_message(token64_byte).decode()
                    self.config[section_title][parameter] = message

    def _decrypt_file(self):
        """
        Decrypt value of password like parameters
        :return:
        """
        self._load_encrypted_configuration()
        # change status
        self.config['GENERAL']['Encryption_status'] = "clear_text"
        self.save()


# Start program
if __name__ == "__main__":
    main()



