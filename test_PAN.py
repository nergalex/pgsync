#!/usr/bin/env python

import urllib
import urllib3
import ssl
import argparse
import re
# from jinja2 import Environment, FileSystemLoader
# import yaml
import sys
import os
import getpass


def api_request(url, values):
    data = urllib.urlencode(values)
    context = ssl._create_unverified_context()

    try:
        request = urllib3.Request(url, data)
        return urllib3.urlopen(request, context=context).read()

    except urllib3.URLError:
        print("\n\033[1;31;40m[Error] : Connecting to {url}. Check IP address.".format(url=url) + "\033[0m")
        return None


def keygen(username, password, ip):
    url = "https://" + ip + "/api/?type=keygen&user=" + username + "&password=" + password
    context = ssl._create_unverified_context()

    try:
        request = urllib3.Request(url)
        response = urllib3.urlopen(request, context=context)
        data = response.read()
        key = re.search(r"(<key>)(.*)</key>", data)
        return key.group(2)

    except urllib3.URLError:
        print(
            "\n\033[1;31;40m[Error] : Connecting to " + ip + " to get API KEY failed. Check URL/IP/Login/Password.\033[0m")
        return None


if __name__ == '__main__':

    usage = 'panorama-create-tags -pi <panorama_ip> -pl <panorama_login>\n'
    fw_api_login = ''
    fw_api_password = ''

    parser = argparse.ArgumentParser(usage=usage)
    parser.add_argument('-pi', action='store', required=True, help='Panorama FQDN/IP. Example : 192.168.1.1')
    parser.add_argument('-pl', action='store', required=True, help='Panorama API Login. Example : admin')
    results = parser.parse_args()

    fw_api_ip = results.pi
    url = "https://" + fw_api_ip + "/api"
    fw_api_login = results.pl

    fw_api_password = getpass.getpass('Password: ')
    api_key = keygen(fw_api_login, fw_api_password, fw_api_ip)

    element = ""
    for x in range(1, 21):
        for y in range(1, 26):
            tag = 'PAN-domain_dmz_' + str(y) + '-pge_' + str(x)
            element = element + "<entry name=" + '"' + tag + '"' + "></entry>"

    api_call = {'type': 'config', 'action': 'set', 'Key': api_key, 'xpath': '/config/shared/tag', 'element': element}

    print("The API call might take several minutes to execute. Be patient ....")
    response = api_request(url, api_call)
    print(response)





