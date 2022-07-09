#!/usr/bin/env python
# Program: DNS Domain Expiration Checker
# Author: Matty < matty at prefetch dot net >
# Current Version: 9.1
# Date: 01-27-2020
# License:
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
#  GNU General Public License for more details.

import sys
import time
import dateutil.parser
import subprocess
import yaml
from datetime import datetime

from utils.helper import debug
from utils.notifications import send_completion_zulip_message, send_completion_discord_message, send_error_zulip_message, send_error_discord_message, send_expire_email, send_expire_zulip_message, send_zabbix_script_monitoring, send_expire_discord_message

EXPIRE_STRINGS = [ b"Registry Expiry Date:",
                   b"Expiration:",
                   b"Domain Expiration Date",
                   b"Registrar Registration Expiration Date:",
                   b"expire:",
                   b"expires:",
                   b"Expiry date"
                 ]

REGISTRAR_STRINGS = [
                      b"Registrar:"
                    ]


def print_heading():
    """
       Print a formatted heading when called interactively
    """
    print("%-25s  %-20s  %-30s  %-4s" % ("Domain Name", "Registrar",
          "Expiration Date", "Days Left"))


def print_domain(domain, registrar, expiration_date, days_remaining):
    """
       Pretty print the domain information on stdout
    """
    print("%-25s  %-20s  %-30s  %-d" % (domain, registrar,
          expiration_date, days_remaining))


def make_whois_query(domain, config_options):
    """
       Execute whois and parse the data to extract specific data
    """
    debug("Sending a WHOIS query for the domain %s" % domain, config_options)
    try:
        p = subprocess.Popen(['whois', domain],
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    except Exception as e:
        if 'ZulipAPI' in config_options['APP']['NOTIFICATIONS']:
            send_error_zulip_message("Unable to Popen() the whois binary. Exception %s" % e, config_options)
        if 'Discord' in config_options['APP']['NOTIFICATIONS']:
            send_error_discord_message("Unable to Popen() the whois binary. Exception %s" % e, config_options)
        if 'Zabbix' in config_options['APP']['SCRIPT_MONITORING']:
            send_zabbix_script_monitoring(1, config_options)
        print("Unable to Popen() the whois binary. Exception %s" % e)
        sys.exit(1)

    try:
        whois_data = p.communicate()[0]
    except Exception as e:
        if 'ZulipAPI' in config_options['APP']['NOTIFICATIONS']:
            send_error_zulip_message("Unable to read from the Popen pipe. Exception %s" % e, config_options)
        if 'Discord' in config_options['APP']['NOTIFICATIONS']:
            send_error_discord_message("Unable to read from the Popen pipe. Exception %s" % e, config_options)
        if 'Zabbix' in config_options['APP']['SCRIPT_MONITORING']:
            send_zabbix_script_monitoring(1, config_options)
        print("Unable to read from the Popen pipe. Exception %s" % e)
        sys.exit(1)

    # TODO: Work around whois issue #55 which returns a non-zero
    # exit code for valid domains.
    # if p.returncode != 0:
    #    print("The WHOIS utility exit()'ed with a non-zero return code")
    #    sys.exit(1)

    return(parse_whois_data(whois_data, config_options))


def parse_whois_data(whois_data, config_options):
    """
       Grab the registrar and expiration date from the WHOIS data
    """
    debug("Parsing the whois data blob %s" % whois_data.splitlines(), config_options)
    expiration_date = "00/00/00 00:00:00"
    registrar = "Unknown"

    for line in whois_data.splitlines():
        if any(expire_string in line for expire_string in EXPIRE_STRINGS):
            expiration_date = dateutil.parser.parse((line.partition(b": ")[2]).rstrip(b"[UTC]"), ignoretz=True)

        if any(registrar_string in line for registrar_string in
               REGISTRAR_STRINGS):
            registrar = line.split(b"Registrar:")[1].strip()

    return expiration_date, registrar


def calculate_expiration_days(expire_days, expiration_date, config_options, domain):
    """
       Check to see when a domain will expire
    """
    debug("Expiration date %s Time now %s" % (expiration_date, datetime.now()),config_options)

    try:
        domain_expire = expiration_date - datetime.now()
    except:
        if 'ZulipAPI' in config_options['APP']['NOTIFICATIONS']:
            send_error_zulip_message(f"Unable to calculate the expiration days for {domain}", config_options)
        if 'Discord' in config_options['APP']['NOTIFICATIONS']:
            send_error_discord_message(f"Unable to calculate the expiration days for {domain}", config_options)
        print("Unable to calculate the expiration days")
        return "Unable to calculate the expiration days"

    if domain_expire.days < expire_days:
        return domain_expire.days
    else:
        return 0


def check_expired(expiration_days, days_remaining):
    """
       Check to see if a domain has passed the expiration
       day threshold. If so send out notifications
    """
    if int(days_remaining) < int(expiration_days):
        return days_remaining
    else:
        return 0


def domain_expire_notify(domain, config_options, days):
    """
       Functions to call when a domain is about to expire. Adding support
       for Nagios, SNMP, etc. can be done by defining a new function and
       calling it here.
    """
    debug("Triggering notifications for the DNS domain %s" % domain, config_options)

    # Send outbound e-mail if a rcpt is passed in
    if 'Email' in config_options['APP']['NOTIFICATIONS']:
        send_expire_email(domain, days, config_options)

    if 'ZulipAPI' in config_options['APP']['NOTIFICATIONS']:
        send_expire_zulip_message(domain, days, config_options)
    
    if 'Discord' in config_options['APP']['NOTIFICATIONS']:
        send_expire_discord_message(domain, days, config_options)

def process_config_file():

    with open("config.yaml", 'r') as stream:
        config_options = yaml.safe_load(stream)

    return(config_options)


def main():
    """
        Main loop
    """
    days_remaining = 0
    conf_options = process_config_file()
    expiration_days = conf_options['APP']['EXPIRE_DAYS_THRESHOLD']

    if conf_options['APP']['INTERACTIVE']:
        print_heading()

    for domain in conf_options['APP']['DOMAINS']:
        print("Checking %s" % domain)
        expiration_date, registrar = make_whois_query(domain, conf_options)
        days_remaining = calculate_expiration_days(expiration_days, expiration_date, conf_options, domain)
        if days_remaining == "Unable to calculate the expiration days":
            pass
        else:
            if check_expired(expiration_days, days_remaining):
                domain_expire_notify(domain, conf_options, days_remaining)

            if conf_options['APP']['INTERACTIVE']:
                print_domain(domain, registrar, expiration_date, days_remaining)

        # Need to wait between queries to avoid triggering DOS measures like so:
        # Your IP has been restricted due to excessive access, please wait a bit
        time.sleep(conf_options['APP']['WHOIS_SLEEP_TIME'])

    if 'ZulipAPI' in conf_options['APP']['NOTIFICATIONS']:
        send_completion_zulip_message(conf_options)
    if 'Discord' in conf_options['APP']['NOTIFICATIONS']:
        send_completion_discord_message(conf_options)
    if 'Zabbix' in conf_options['APP']['SCRIPT_MONITORING']:
        send_zabbix_script_monitoring(0, conf_options)
 
if __name__ == "__main__":
    main()
