#!/usr/bin/python3

""" License

    Copyright (C) 2019 YunoHost

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published
    by the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program; if not, see http://www.gnu.org/licenses

"""

import sys
import getopt
import os
import requests
from subprocess import Popen, PIPE
import json
import yaml
import smtplib
import logging
import glob
import time
import socket
import ssl
import dns.resolver
import dbus
import shutil
import hashlib
import re
import urllib
from requests_toolbelt.adapters import host_header_ssl
from threading import Thread
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5 as Cipher_PKCS1_v1_5
from datetime import datetime, timedelta

# =============================================================================
# SCRIPT CONFIG VARS
# =============================================================================

# Every 8 minutes
CRON_FREQUENCY = 8

MONITORING_ERRORS = {
    'NO_PING': {'level': 'critical', 'first': 3, 'frequency': 3, 
                'user': 'Le serveur est éteint ou injoignable',
                'admin': "Le serveur '{domain}' est éteint ou injoignable"},
    'NO_IPV4_PING': {'level': 'critical', 'first': 3, 'frequency': 3, 
                'user': "Le serveur est injoignable pour certains équipements",
                'admin': "Le serveur '{domain}' est injoignable en ipv4"},
    'NO_IPV6_PING': {'level': 'critical', 'first': 3, 'frequency': 3, 
                'user': 'Le serveur est injoignable pour certains équipements',
                'admin': "Le serveur '{domain}' est injoignable en ipv6"},
    'DOMAIN_UNCONFIGURED': {'level': 'critical', 'first': 2, 'frequency': 3, 
                'user': "Le service n’est pas joignable car le nom de domaine {domain} n’est pas correctement configuré.",
                'admin': "Le nom de domaine {domain} n’est pas configuré."},
    'DOMAIN_UNCONFIGURED_IN_IPV4': {'level': 'critical', 'first': 2, 'frequency': 3, 
                'user': "Le service n’est pas joignable par certains équipements car le nom de domaine {domain} n’est pas correctement configuré.",
                'admin': "Le nom de domaine {domain} n’est pas configuré pour ipv4. Beaucoup d’équipements ne pourront pas y accéder."},
    'DOMAIN_UNCONFIGURED_IN_IPV6': {'level': 'info', 'first': 2, 'frequency': 3, 
                'user': "",
                'admin': "Le service n'est pas configuré en IPv6."},
    'CERT_RENEWAL_FAILED': {'level': 'error', 'first': 1, 'frequency': 3, 
                'user': "Le renouvellement du certificat {protocol} de {domain} a échoué ou n’est pas pris en compte, sans intervention le service tombera en panne dans {days} jours",
                'admin': "Le renouvellement du certificat {protocol} de {domain} a échoué ou n’est pas pris en compte, sans intervention le service tombera en panne dans {days} jours"},
    'CERT_INVALID': {'level': 'critical', 'first': 1, 'frequency': 3, 
                'user': "Le service n’est pas joignable car le certificat de sécurité a expiré ou n’est pas accepté. Note: si l’adresse web auquel vous voulez accéder est une page publique (sans authentification), il est possible d’y accéder en navigation privée, en ajoutant une exception.",
                'admin': "Le service n’est pas joignable car le certificat de sécurité a expiré ou n’est pas accepté. Note: si l’adresse web auquel vous voulez accéder est une page publique (sans authentification), il est possible d’y accéder en navigation privée, en ajoutant une exception."},
    'PORT_CLOSED_OR_SERVICE_DOWN': {'level': 'critical', 'first': 2, 'frequency': 3, 
                'user': "Le service n’est pas joignable",
                'admin': "Le service n’est pas joignable"},
    'TIMEOUT': {'level': 'critical', 'first': 3, 'frequency': 3, 
                'user': "Le service n’est pas joignable",
                'admin': "Le service n’est pas joignable"},
    'TOO_MANY_REDIRECTS': {'level': 'critical', 'first': 2, 'frequency': 3, 
                'user': "Le service semble en panne",
                'admin': "Le service est en panne suite à une erreur de redirection."},
    'SSO_CAPTURE': {'level': 'critical', 'first': 2, 'frequency': 3, 
                'user': "Le service semble en panne",
                'admin': "Le service semble protégé par le SSO"},
    'HTTP_403': {'level': 'critical', 'first': 2, 'frequency': 3, 
                'user': "Le service semble en panne",
                'admin': "Le service est interdit d'accès"},
    'HTTP_404': {'level': 'critical', 'first': 2, 'frequency': 3, 
                'user': "Le service semble en panne",
                'admin': "Le service renvoie une erreur 404 page non trouvée"},
    'HTTP_500': {'level': 'critical', 'first': 2, 'frequency': 3, 
                'user': "Le service semble en panne",
                'admin': "Le service est en panne suite à une erreur logicielle."},
    'HTTP_502': {'level': 'critical', 'first': 2, 'frequency': 3, 
                'user': "Le service semble en panne",
                'admin': "Le service s’est eteint"},
    'DOMAIN_EXPIRATION_NOT_FOUND': {'level': 'info', 'first': 1, 'frequency': 180, 
                'user': "",
                'admin': ""},
    'DOMAIN_WILL_EXPIRE': {'level': 'warning', 'first': 1, 'frequency': 180, 
                'user': "Le nom de domaine {domain} expire dans {days} jours. Ne pas oublier de le renouveller.",
                'admin': "Le nom de domaine {domain} expire dans {days} jours. Ne pas oublier de le renouveller."},
    'DOMAIN_NEARLY_EXPIRE': {'level': 'error', 'first': 1, 'frequency': 180, 
                'user': "Le nom de domaine {domain} expire dans {days} jours. Sans renouvellement le service ne fonctionnera plus.",
                'admin': "Le nom de domaine {domain} expire dans {days} jours. Sans renouvellement le service ne fonctionnera plus."},
    'DOMAIN_EXPIRE': {'level': 'critical', 'first': 3, 'frequency': 30, 
                'user': "Le nom de domaine {domain} expire aujourd’hui ou demain. Sans renouvellement le service ne fonctionnera plus.",
                'admin': "Le nom de domaine {domain} expire aujourd’hui ou demain. Sans renouvellement le service ne fonctionnera plus."},
    'BROKEN_NAMESERVER': {'level': 'critical', 'first': 3, 'frequency': 3, 
                'user': "Un problème de connectivité interne pourrait créer des dysfonctionnements",
                'admin': "Le serveur de nom à l’adresse {ip} est injoignable"},
    'TIMEOUT': {'level': 'critical', 'first': 3, 'frequency': 3, 
                'user': "Un problème de connectivité interne pourrait créer des dysfonctionnements",
                'admin': "Le serveur de nom à l’adresse {ip} est trop lent"},
    'NO_ANSWER': {'level': 'critical', 'first': 2, 'frequency': 3, 
                'user': "Le service n’est pas joignable car le nom de domaine {domain} n’est pas correctement configuré.",
                'admin': "Le nom de domaine {domain} n’est pas configuré."},
    'UNEXPECTED_ANSWER': {'level': 'critical', 'first': 1, 'frequency': 3, 
                'user': "",
                'admin': ""},
    'NO_MX_RECORD': {'level': 'error', 'first': 1, 'frequency': 3, 
                'user': "Un problème de configuration des mails a été détecté. Certains mails pourraient tombés en SPAM.",
                'admin': "Aucune configuration MX pour le domaine {domain}. Certains mails pourraient être calssé en SPAM."},
    'REVERSE_MISSING': {'level': 'critical', 'first': 1, 'frequency': 3, 
                'user': "Un problème de configuration des mails a été détecté. Certains mails pourraient tombés en SPAM.",
                'admin': "Le DNS inversé n’a pas été configuré pour l’ip {ip} et le domaine {domain}. Le serveur pourraient être blacklisté et certains mails pourraient être classé en SPAM"},
    'REVERSE_MISMATCH': {'level': 'critical', 'first': 1, 'frequency': 3, 
                'user': "Un problème de configuration des mails a été détecté. Certains mails pourraient tombés en SPAM.",
                'admin': "Le DNS inversé pour l’ip {ip} est configuré pour le domaine {domain1} au lieu de domaine {domain2}. Le serveur pourraient être blacklisté et certains mails pourraient être classé en SPAM"},
    'BLACKLISTED': {'level': 'critical', 'first': 1, 'frequency': 3, 
                'user': "L’ip du serveur a été blacklistée par {rbl}. Certains mails pourraient tombés en SPAM.",
                'admin': "L’ip du serveur a été blacklistée par {rbl}. Certains mails pourraient tombés en SPAM."},
    'NOT_FOUND': {'level': 'critical', 'first': 1, 'frequency': 3, 
                'user': "Un des programmes est en panne, des dysfonctionnements sur le service peuvent subvenir.",
                'admin': "Le service {service} n’existe pas"},
    'DOWN': {'level': 'critical', 'first': 2, 'frequency': 3, 
                'user': "Un des programmes est en panne, des dysfonctionnements sur le service peuvent subvenir.",
                'admin': "Le service {service} est éteint il devrait être allumé."},
    'FAILED': {'level': 'critical', 'first': 2, 'frequency': 3, 
                'user': "Un des programmes est en panne, des dysfonctionnements sur le service peuvent subvenir.",
                'admin': "Le service {service} est tombé en panne il faut le relancer et investiguer."},
    'SMART_NOT_SUPPORTED': {'level': 'warning', 'first': 1, 'frequency': 3, 
                'user': "",
                'admin': "Un disque dur ne supporte pas les fonctionnalités permétant le contrôle de son état de santé."},
    'SMART_DISABLED': {'level': 'error', 'first': 1, 'frequency': 3, 
                'user': "L’activation du contrôle de l’état de santé d’un disque dur n’a pas fonctionné.",
                'admin': "L’activation du contrôle de l’état de santé d’un disque dur n’a pas fonctionné."},
    'SMART_HALF_WORKING': {'level': 'error', 'first': 1, 'frequency': 3, 
                'user': "Le contrôle de l’état de santé d’un disque dur n’est que partiellement activé.",
                'admin': "Le contrôle de l’état de santé d’un disque dur n’est que partiellement activé."},
    'DISK_FAILURE': {'level': 'critical', 'first': 1, 'frequency': 3, 
                'user': "Un disque dur semble sur le point de tomber en panne, il faut le changer rapidement.",
                'admin': "Un disque dur semble sur le point de tomber en panne, il faut le changer rapidement."},
    'NO_FREE_SPACE': {'level': 'critical', 'first': 1, 'frequency': 3, 
                'user': "Il n’y a plus d’espace disque sur le serveur des dysfonctionnements sont à prévoir",
                'admin': "Il n’y a plus d’espace disque sur le serveur des dysfonctionnements sont à prévoir"},
    'C_FREE_SPACE': {'level': 'critical', 'first': 1, 'frequency': 3, 
                'user': "L’espace disque sur le serveur est trop faible, si rien n’est fait rapidement des dysfonctionnements sont à prévoir",
                'admin': "L’espace disque sur le serveur est trop faible, si rien n’est fait rapidement des dysfonctionnements sont à prévoir"},
    'E_FREE_SPACE': {'level': 'error', 'first': 1, 'frequency': 3, 
                'user': "L’espace disque sur le serveur est trop faible, si rien n’est fait des dysfonctionnements pourraient subvenir",
                'admin': "L’espace disque sur le serveur est trop faible, si rien n’est fait des dysfonctionnements pourraient subvenir"},
    'W_FREE_SPACE': {'level': 'warning', 'first': 1, 'frequency': 3, 
                'user': "",
                'admin': "L’espace disque sur le serveur est assez réduit."},
    'NO_BACKUP': {'level': 'error', 'first': 2, 'frequency': 3, 
                'user': "Aucune sauvegarde [de {app}] n’a été trouvée sur le serveur de [sauvegarde à paris].",
                'admin': "Aucune sauvegarde [de {app}] n’a été trouvée sur le serveur de [sauvegarde à paris]."},
    'MISSING_BACKUP': {'level': 'error', 'first': 2, 'frequency': 3, 
                'user': "La dernière sauvegarde [de {app}] sur le serveur de [sauvegarde à paris] est manquante. ",
                'admin': "La dernière sauvegarde [de {app}] sur le serveur de [sauvegarde à paris] est manquante. "},
    'BACKUP_NOT_TRIGGERED': {'level': 'error', 'first': 2, 'frequency': 3, 
                'user': "La sauvegarde vers le serveur de sauvegarde à paris n’a pas été déclenchée au cours des dernières 24h.",
                'admin': "La sauvegarde vers le serveur de sauvegarde à paris n’a pas été déclenchée au cours des dernières 24h."},
    'BACKUP_BROKEN': {'level': 'error', 'first': 2, 'frequency': 3, 
                'user': "La dernière sauvegarde [de {app}] sur le serveur de sauvegarde à paris est incomplète. Une restauration manuelle resterait peut être possible.",
                'admin': "La dernière sauvegarde [de {app}] sur le serveur de sauvegarde à paris est incomplète. Une restauration manuelle resterait peut être possible."},
    'APP_NEED_UPGRADE': {'level': 'warning', 'first': 1, 'frequency': 180, 
                'user': "",
                'admin': "Une mise à jour est disponible pour l'application {app}"},
    'PKG_NEED_UPGRADE': {'level': 'warning', 'first': 1, 'frequency': 180, 
                'user': "",
                'admin': "Une mise à jour des paquets systèmes est disponible"},
    'UNKNOWN_ERROR': {'level': 'error', 'first': 3, 'frequency': 3, 
                'user': "",
                'admin': "Une erreur non gérée par le système de monitoring est survenue"},
}

# Trigger actions every 8*3 minutes of failures
ALERT_FREQUENCY = 3

# Update monitoring configuration each hours
CACHE_DURATION_IN_MINUTES = 60

WELL_KNOWN_URI = 'https://%s/.well-known/acme-challenge/'
REMOTE_MONITORING_CONFIG_FILE = os.path.join(WELL_KNOWN_URI, '%s.to_monitor')
REMOTE_FAILURES_FILE = os.path.join(WELL_KNOWN_URI, '%s.failures')
WELL_KNOWN_DIR = '/tmp/acme-challenge-public/'
PUBLISHED_FAILURES_FILE = os.path.join(WELL_KNOWN_DIR, "%s.failures")
PUBLISHED_MONITORING_CONFIG_FILE = os.path.join(WELL_KNOWN_DIR, "%s.to_monitor")
PUBLIC_KEY_URI = os.path.join(WELL_KNOWN_URI, "ssh_host_rsa_key.pub")
"""
ping:
    some.domain.tld:
        count: 3
        messages:
            - some.domain.tld no ipv4 ping
"""
CONFIG_DIR = "/etc/yunomonitor/"
MONITORING_CONFIG_FILE = os.path.join(CONFIG_DIR, "%s.yml")
CACHE_MONITORING_CONFIG_FILE = os.path.join(CONFIG_DIR, "%s.cache.yml")
FAILURES_FILE = os.path.join(CONFIG_DIR, "%s.failures.yml")

MAIL_SUBJECT = "[{level}][{server}] {message}: {target}"
MAIL_BODY = """{admin_info}

Extra info: {extra}
"""
HTTP_TIMEOUT = 15
DEFAULT_BLACKLIST = [
        ('zen.spamhaus.org'             , 'Spamhaus SBL, XBL and PBL'        ),
        ('dnsbl.sorbs.net'              , 'SORBS aggregated'                 ),
        ('safe.dnsbl.sorbs.net'         , "'safe' subset of SORBS aggregated"),
        ('ix.dnsbl.manitu.net'          , 'Heise iX NiX Spam'                ),
        ('babl.rbl.webiron.net'         , 'Bad Abuse'                        ),
        ('cabl.rbl.webiron.net'         , 'Chronicly Bad Abuse'              ),
        ('truncate.gbudb.net'           , 'Exclusively Spam/Malware'         ),
        ('dnsbl-1.uceprotect.net'       , 'Trapserver Cluster'               ),
        ('cbl.abuseat.org'              , 'Net of traps'                     ),
        ('dnsbl.cobion.com'             , 'used in IBM products'             ),
        ('psbl.surriel.com'             , 'passive list, easy to unlist'     ),
        ('dnsrbl.org'                   , 'Real-time black list'             ),
        ('db.wpbl.info'                 , 'Weighted private'                 ),
        ('bl.spamcop.net'               , 'Based on spamcop users'           ),
        ('dyna.spamrats.com'            , 'Dynamic IP addresses'             ),
        ('spam.spamrats.com'            , 'Manual submissions'               ),
        ('auth.spamrats.com'            , 'Suspicious authentications'       ),
        ('dnsbl.inps.de'                , 'automated and reported'           ),
        ('bl.blocklist.de'              , 'fail2ban reports etc.'            ),
        ('srnblack.surgate.net'         , 'feeders'                          ),
        ('all.s5h.net'                  , 'traps'                            ),
        ('rbl.realtimeblacklist.com'    , 'lists ip ranges'                  ),
        ('b.barracudacentral.org'       , 'traps'                            ),
        ('hostkarma.junkemailfilter.com', 'Autotected Virus Senders'         ),
        ('rbl.megarbl.net'              , 'Curated Spamtraps'                ),
        ('ubl.unsubscore.com'           , 'Collected Opt-Out Addresses'      ),
        ('0spam.fusionzero.com'         , 'Spam Trap'                        ),
]
# =============================================================================


# =============================================================================
# GLOBAL VARS
# =============================================================================


# =============================================================================

# =============================================================================
# CORE FUNCTIONS
# =============================================================================
class IPMetaClass(type):
    def __getitem__(cls, x):
        return getattr(cls, x)
    @property
    def connected(self):
        return self.v4 or self.v6
class IP(object, metaclass=IPMetaClass):
    v4 = True
    v6 = True

def display_help(error=0):
    print('yunomonitor.py [YUNODOMAIN ...] [-m MAIL ...] [-s SMS_API ...] [-c CACHET_API ...]')
    print('YunoMonitor is a one file script to monitor a server and send mail,')
    print('sms or fill a cachet status page.')
    sys.exit(error)


def main(argv):
    
    # Parse arguments
    try:
        opts, monitored_servers = getopt.getopt(argv, "hm:s:c:e:", 
                                                ["mail=", "sms=", "cachet=", 
                                                 "encrypt-for="])
    except getopt.GetoptError:
        display_help(2)

    mails = set()
    sms_apis = set()
    cachet_apis = set()
    monitoring_servers = set()
    for opt, arg in opts:
        if opt == '-h':
            display_help()
        elif opt in ("-m", "--mail"):
            mails.add(arg)
        elif opt in ("-s", "--sms"):
            sms_apis.add(arg)
        elif opt in ("-c", "--cachet"):
            cachet_apis.add(arg)
        elif opt in ("-e", "--encrypt-for"):
            monitoring_servers.add(arg)

    if monitored_servers == []:
        monitored_servers = ['localhost']

    # If we are offline in IPv4 and IPv6 execute only local checks
    IP.v4 = not check_ping("wikipedia.org", ['v4'])
    IP.v6 = socket.has_ipv6 and not check_ping("wikipedia.org", ['v6'])
    if not IP.v4 and not IP.v6:
        logging.debug('No connexion')
        if 'localhost' not in monitored_servers:
            sys.exit(2)
        logging.debug('only local test will run')
        monitored_servers = ['localhost']

    # Load or download monitoring description of each server, convert
    # monitoring instructions, execute it
    threads = [ServerMonitor(server, monitoring_servers) for server in monitored_servers]
    for thread in threads:
        thread.start()
    
    alerts = {}
    # Wait for all thread
    for thread in threads:
        thread.join()
        alerts[thread.server]=thread.failures

    # Filter by reccurence
    for server, failures in alerts.items():
        for message, reports in failures.items():
            first = MONITORING_ERRORS[message]['first']
            freq = MONITORING_ERRORS[message]['frequency']
            for report in reports:
                alerts[server][message] = []
                if (report['count'] - first) % freq == 0:
                    report['level'] = MONITORING_ERRORS[message]['level']
                    alerts[server][message].append(report)
    
    # Trigger some actions
    if mails:
        mail_alert(alerts, mails)
    
    if sms_apis:
        sms_alert(alerts, sms_apis)
    #cachet_alert(alerts, ynh_maps, cachet_apis)

    #if 'localhost' in alerts:
    #    service_up(alerts['localhost'].get('service_up', []))


def detect_internet_protocol():
    global ip
    IP.v4 = not check_ping("wikipedia.org", ['v4'])

    IP.v6 = socket.has_ipv6
    no_pingv6 = check_ping("wikipedia.org", ['v6'])
    IP.v6 = IP.v6 and not no_pingv6

class ServerMonitor(Thread):
    """Thread to monitor one server."""
    ynh_maps = {}

    def __init__(self, server, monitoring_servers):
        Thread.__init__(self)
        self.server = server
        self.monitoring_servers = monitoring_servers
        self.failures = {}

    def run(self):
        self.ynh_maps[self.server] = self._load_monitoring_config()
        self._monitor()
        self._count()
        self._add_remote_failures()
        self._save()
        self._publish()
        

    def _load_monitoring_config(self):
        """ This function loads the instructions to know what to monitor
        """
        local_config = MONITORING_CONFIG_FILE % (self.server)
        cache_config = CACHE_MONITORING_CONFIG_FILE % (self.server)
        
        # If a user specific configuration is in /etc, we use it
        if os.path.exists(local_config):
            with open(local_config, 'r') as local_config_file:
                return yaml.load(local_config_file)
        else:

            # If a cache configuration younger than 1h exists, we use it
            if os.path.exists(cache_config):
                # TODO Improve cache by using HTTP cache headers
                minutes = (time.time() - os.path.getmtime(cache_config)) / 60
                if minutes < CACHE_DURATION_IN_MINUTES:
                    with open(cache_config, 'r') as cache_config_file:
                        return yaml.load(cache_config_file)
            
            # If we are on the server to monitor, generate the configuration
            if self.server == 'localhost':
                config = generate_monitoring_config()
                
                # Encrypt and publish to let the monitoring server to download it
                for mserver in self.monitoring_servers:
                    with open(PUBLISHED_MONITORING_CONFIG_FILE % get_id_host(mserver), 'wb') as publish_config_file:
                        publish_config_file.write(encrypt(yaml.dump(config), mserver))
            
            # If the server to monitor is on remote, we try to download the 
            # configuration
            else:
                config_url = REMOTE_MONITORING_CONFIG_FILE % (self.server, get_id_host())
                try:
                    r = requests.get(config_url, timeout=15)
                except Exception as e:
                    r = None
                if r is None or r.status_code != 200 and os.path.exists(cache_config):
                    logging.warning('Unable to download autoconfiguration file, the old one will be used')
                    with open(cache_config, 'r') as cache_config_file:
                        return yaml.load(cache_config_file)
                
                config = yaml.load(decrypt(r.content))
            
            # Write the configuration in cache
            with open(cache_config, 'w') as cache_config_file:
                yaml.dump(config, cache_config_file, default_flow_style=False)
            return config


    def _monitor(self):
        
        to_monitor = self.ynh_maps[self.server].copy()
        del to_monitor['__components__']
        
        # Remove checks that run on another machine
        if self.server == 'localhost':
            checks = ['ping', 'domain_renewal', 'https_200', 'dns_resolver', 'smtp', 'imap', 'xmpp']
        else:
            checks = ['dns_resolution', 'service_up', 'backuped', 'disk_health', 'free_space']

        for check in checks:
            if check in to_monitor:
                del to_monitor[check]

        # Check things to monitor
        for category, checks in to_monitor.items():
            for args in checks:
                try:
                    check_name = "check_%s" % (category)
                    reports = globals()[check_name](*args)
                except Exception as e:
                    reports = [('UNKNOWN_ERROR', {'check': category}, {'debug': str(e)})]
                for report in reports:
                    if report[0] not in self.failures:
                        self.failures[report[0]] = []
                        self.failures[report[0]].append({
                            'target': report[1],
                            'count': 1,
                            'extra': report[2] if len(report) >= 3 else {}
                        })


    def _count(self):
        # Extract recorded failures
        failures_file = FAILURES_FILE % (self.server)
        recorded_failures = {}
        if os.path.exists(failures_file):
            with open(failures_file) as f:
                recorded_failures = json.load(f)

        # Increase counter with recorded failures
        for message, reports in recorded_failures.items():
            if message not in self.failures:
                continue

            for report in reports:
                r = [x for x in self.failures[message]
                          if x['target'] == report['target']]
                if r:
                    r[0]['count'] += report['count']
        
    def _add_remote_failures(self):
        if self.server == 'localhost':
            return
        
        # Load internal failures
        url = REMOTE_FAILURES_FILE % (self.server, get_id_host())
        try:
            r = requests.get(url, timeout=15)
            if r is not None or r.status_code == 200:
                internal_failures = json.loads(decrypt(r.content))
        except Exception as e:
            logging.debug('No failures files', str(e))
            internal_failures = {}

        # Add internal recorded failures
        for message, reports in internal_failures.items():
            if message not in self.failures:
                self.failures[message] = reports
            else:
                self.failures[message] += reports
    
    
    def _save(self):
        failures_file = FAILURES_FILE % (self.server)
        # Save failures in /etc file
        with open(failures_file, "w") as f:
            json.dump(self.failures, f)


    def _publish(self):
        # Publish failures
        for mserver in self.monitoring_servers:
            with open(PUBLISHED_FAILURES_FILE % get_id_host(mserver), "wb") as f:
                f.write(encrypt(json.dumps(self.failures), mserver))

def get_public_key(server):
    cache_key = '/etc/yunomonitor/%s.pub' % server
    if os.path.exists(cache_key):
        with open('/etc/yunomonitor/%s.pub' % server) as f:
            key = f.read()
    else:
        try:
            r = requests.get(PUBLIC_KEY_URI % server, timeout=15)
        except Exception as e:
            return None
        if r is None or r.status_code != 200:
            return None
        
        key = r.text
        with open('/etc/yunomonitor/%s.pub' % server, 'w') as f:
            f.write(r.text)
    return key


def get_id_host(server=None):
    if not server:
        filename = '/etc/ssh/ssh_host_rsa_key.pub'
    else:
        get_public_key(server)
        filename = '/etc/yunomonitor/%s.pub' % server
    block_size = 65536
    sha256 = hashlib.sha256()
    with open(filename, 'rb') as f:
        for block in iter(lambda: f.read(block_size), b''):
            sha256.update(block)
    return sha256.hexdigest()

def encrypt(message, mserver):
    key = get_public_key(mserver)
    return message.encode()
    #key = RSA.importKey(key)
    #cipher = Cipher_PKCS1_v1_5.new(key)
    #return cipher.encrypt(message.encode())

def decrypt(cipher_message):
    return cipher_message
    #with open('/etc/ssh/ssh_host_rsa_key') as f:
    #    key = RSA.importKey(f.read())
    #cipher = Cipher_PKCS1_v1_5.new(key)
    #return cipher.decrypt(cipher_message, None).decode()


def generate_monitoring_config():
    https_200 = set()
    service_up = set()
    backuped = set()
    domains = set()
    is_yunohost = os.path.exists("/etc/yunohost/installed")
    if is_yunohost:
        with open("/etc/yunohost/current_host") as f:
            current_host = f.read().strip()
        
        domains = glob.glob('/etc/nginx/conf.d/*.*.conf')
        domains = [path[18:-5] for path in domains]
        
        with open('/etc/resolv.dnsmasq.conf', 'r') as resolv_file:
            dns_resolver = [x[11:].replace('\n', '') for x in resolv_file.readlines()]

        # TODO personalize meta components
        apps = [
            {
                "id": "mail",
                "name": "Mail",
                "label": "Mail",
                "services": ["postfix", "rspamd", "dovecot", "postsrsd",
                             "dnsmasq", "slapd"]
            },
            {
                "id": "xmpp",
                "name": "XMPP",
                "label": "Messagerie instantannée",
                "services": ["metronome"]
            },
            {
                "id": "ssowat",
                "name": "SSOWat",
                "label": "Authentification centralisée",
                "uris": ["%s/yunohost/sso/" % (current_host)],
                "services": ["slapd", "nslcd", "nginx", 'unscd']
            },
            {
                "id": "admin",
                "name": "Admin",
                "label": "Administration",
                "uris": ["%s/yunohost/admin/" % (current_host),
                         "%s/yunohost/api/" % (current_host)],
                "services": ["nginx", "slapd", "ssh", "yunohost-api",
                             "systemd-logind"]
            },
            {
                "id": "firewall",
                "name": "Firewall",
                "label": "Parefeu",
                "services": ["yunohost-firewall", "fail2ban"]
            },
            {
                "id": "misc",
                "name": "Base",
                "label": "Système de base",
                "services": ["avahi-daemon", "cron", "dbus", "glances",
                             "haveged", "ntp", "rng-tools", "rsyslog", "syslog", 
                             "systemd-journald", "systemd-udevd"]
            }

        ]

        apps_dir = glob.glob('/etc/yunohost/apps/*')

        for app_dir in apps_dir:
            with open(os.path.join(app_dir, 'settings.yml'), 'r') as settings_file:
                app_settings = yaml.load(settings_file)
            
            uris = []
            if 'unprotected_uris' in app_settings or 'skipped_uris' in app_settings:
                if 'domain' in app_settings:
                    if 'path' in app_settings:
                        uris.append(app_settings['domain'] + app_settings['path'])
                    if 'unprotected_uris' in app_settings:
                        uris.append(app_settings['domain'] + app_settings['unprotected_uris'])
                    if 'skipped_uris' in app_settings:
                        uris.append(app_settings['domain'] + app_settings['skipped_uris'])

            with open(os.path.join(app_dir, 'manifest.json'), 'r') as manifest_file:
                app_manifest = json.load(manifest_file)

            cmd = "grep -Ehor \"yunohost service add ([^ ]+)\""
            cmd += " /etc/yunohost/apps/%s/scripts/" % app_settings['id']
            cmd += " | cut -d ' ' -f4 | sed s/\$app/%s/g" % app_settings['id']
            p = Popen(cmd.split(), stdout=PIPE, stderr=PIPE)
            out, _ = p.communicate()
            
            services = app_manifest['services'] if 'services' in app_manifest else []
            services = set(services)

            if p.returncode == 0:
                services.update(out.decode("utf-8").strip().split("\n"))

            app = {
                "id": app_settings['id'],
                "name": app_manifest['name'],
                "label": app_settings['label'],
                "uris": uris,
                "services": app_manifest['services']
            }
            if app['name'] in ["Borg", "Archivist"]:
                if app['name'] == "Archivist" or app_settings['apps'] == 'all':
                    app['backup'] = [x[19:] for x in apps_dir]
                else:
                    app['backup'] = app_settings['apps'].split(',')
            apps.append(app)
        
        for app in apps:
            if 'uris' in app:
                https_200.update(app['uris'])
            if 'services' in app:
                service_up.update(app['services'])
            if 'backup' in app:
                backuped.update([(x, app['id']) for x in app['backup']])
    
    # List all non removable disks
    devices = _get_devices()
    domains = list(set(domains))
    return {
        "ping": domains,
        "domain_renewal": domains,
        "smtp": domains,
        "imap": domains,
        "xmpp": domains,
        "dns_resolver": list(set(dns_resolver)),
        "disk_health": list(set(devices)),
        "free_space": [{}],
        "https_200": list(https_200),
        "service_up": list(service_up),
        "backuped": list(backuped),
        "__components__": apps,
    }

def _get_devices():
    devices = set()
    for path in glob.glob('/sys/block/*/device/block/*/removable'):
        disk_name = path.split('/')[3]
        with open(path) as f:
            if f.read(1) == '0':
                devices.add(disk_name)
    return list(devices)


# =============================================================================

# =============================================================================
# AUTOMATIC CONFIGURATION MODULES 
# =============================================================================
# TODO automatic configuration module
# =============================================================================

# =============================================================================
# MONITOR PLUGINS
# =============================================================================
# IDEA Check size of mysql
# IDEA Check number of processus
# IDEA Check log
# IDEA check apt
# IDEA check average load
# IDEA Check no attack

def need_connexion(func):
    def wrapper(*args, **kwargs):
        # Return no errors in case the monitoring server has no connexion
        if not IP.connected:
            return []
    
        return func(*args, **kwargs)
    return wrapper

def run_on_monitored_server(func):
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)
    return wrapper

# Remote checks
def check_ping(hostname, proto=['v4', 'v6']):
    cmd = "ping -%s -c 1 -w 500 %s >/dev/null 2>&1"
    errors = []
    ip = {'v4': IP['v4'], 'v6': IP['v6']}
    for protocol in proto:
        if IP[protocol]:
            ip[protocol] = any(os.system(cmd % (protocol[1:], hostname)) == 0 for retry in range(3))
    
    target = {'domain': hostname}
    if not ip['v4']  and not ip['v6'] and IP['v4'] and IP['v6']:
        errors.append(('NO_PING', target))
    elif not ip['v4'] and IP['v4']:
        errors.append(('NO_IPV4_PING', target))
    elif not ip['v6'] and IP['v6']:
        errors.append(('NO_IPV6_PING', target))

    return errors

cache = {}

@need_connexion
def check_ip_address(domain):
    global cache
    if domain not in cache:
        # Find all ips configured for the domain of the URL
        cache[domain] = {'v4': {}, 'v6': {}}
        try:
            addrs = socket.getaddrinfo(domain, None)
            cache[domain]['v4'] = {addr[4][0]: {}
                                for addr in addrs if addr[0] == socket.AF_INET}
            cache[domain]['v6'] = {addr[4][0]: {}
                                for addr in addrs if addr[0] == socket.AF_INET6}
        except socket.gaierror:
            pass

    addrs = cache[domain]
    if not addrs['v4'] and not addrs['v6']:
        return [('DOMAIN_UNCONFIGURED', {'domain': domain})]

    if not (IP.v4 and addrs['v4']) and not (IP.v6 and addrs['v6']):
        logging.warning('No connexion, can\'t check HTTP')
    
    # Error if no ip v4 address match with the domain
    if not addrs['v4']:
        return [('DOMAIN_MISCONFIGURED_IN_IPV4', 
                                {'domain': domain})]
    return []
@need_connexion
def check_tls(domain, port=443):
    errors = check_ip_address(domain)

    to_report = {
        'CERT_RENEWAL_FAILED': {'v4':{}, 'v6': {}},
        'CERT_INVALID': {'v4':{}, 'v6': {}},
        'PORT_CLOSED_OR_SERVICE_DOWN': {'v4':{}, 'v6': {}},
    }
    for protocol, addrs in cache[domain].items():
        if not IP[protocol] or not addrs:
            continue
        
        # Try to do the request for each ips
        for addr, ports in addrs.items():
            if port in ports:
                continue
            ports[443] = 'working'
            # Check if TLS is working correctly
            try:
                cert = _get_cert_info(domain, addr)
                notAfter = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                expire_in = notAfter - datetime.now()
                if expire_in < timedelta(days_limit):
                    to_report['CERT_RENEWAL_FAILED'][protocol][addr] = {'remaining_days': expire_in.days}
            except ssl.SSLError as e:
                to_report['CERT_INVALID'][protocol][addr] = {'debug': str(e)}
                ports[443] = 'notworking'
            except (ConnectionError, socket.timeout) as e:
                to_report['PORT_CLOSED_OR_SERVICE_DOWN'][protocol][addr] = {'debug': str(e)}
                ports[443] = 'notworking'
            except Exception as e:
                pass
    errors += _aggregate_report_by_target(to_report, domain,
                                          {'domain': domain, 'port': port})
    return errors

class MySSLContext(ssl.SSLContext):
    def __new__(cls, server_hostname):
            return super(MySSLContext, cls).__new__(cls, ssl.PROTOCOL_SSLv23)

    def __init__(self, server_hostname):
            super(MySSLContext, self).__init__(ssl.PROTOCOL_SSLv23)
            self._my_server_hostname = server_hostname

    def change_server_hostname(self, server_hostname):
            self._my_server_hostname = server_hostname

    def wrap_socket(self, *args, **kwargs):
            kwargs['server_hostname'] = self._my_server_hostname
            return super(MySSLContext, self).wrap_socket(*args, **kwargs)

@need_connexion
def check_https_200(url):
    # Find all ips configured for the domain of the URL
    split_uri = url.split('/')
    domain_port = split_uri[0].split(':')
    domain = domain_port[0]
    port = int(domain_port[1]) if len(domain_port) > 1 else 443
    path = '/' + '/'.join(split_uri[1:]) if len(split_uri) > 1 else '/'
    
    errors = check_tls(domain, port)

    to_report = {msg: {'v4':{}, 'v6': {}} for msg in [
        'CERT_INVALID',
        'PORT_CLOSED_OR_SERVICE_DOWN',
        'TIMEOUT',
        'TOO_MANY_REDIRECTS',
        'UNKNOWN_ERROR',
        'SSO_CAPTURE'] + \
        ['HTTP_%d' % code for code in range(400, 499)] + \
        ['HTTP_%d' % code for code in range(500, 599)]
    }
    if not IP.v4 and not addrs['v6']:
        logging.warning('No connexion, can\'t check HTTP')
        return []
    
    for protocol, addrs in cache[domain].items():
        if not IP[protocol] or not addrs:
            continue
        
        # Try to do the request for each ips
        for addr, ports in addrs.items():
            if ports[port] == 'notworking':
                continue
            
            if protocol == 'v6':
                addr = '[' + addr + ']'
            try:

                session = requests.Session()
                adapter = host_header_ssl.HostHeaderSSLAdapter()
                context = MySSLContext(domain)
                adapter.init_poolmanager(10, 10, ssl_context=context)
                session.mount('https://', adapter)
                r = session.get("https://" + addr + path, 
                                    headers={'Host': domain}, 
                                    timeout=HTTP_TIMEOUT)
            except requests.exceptions.SSLError as e:
                to_report['CERT_INVALID'][protocol][addr] = {'debug': str(e)}
            except (requests.exceptions.ConnectionError,
                    requests.exceptions.ConnectTimeout) as e:
                to_report['PORT_CLOSED_OR_SERVICE_DOWN'][protocol][addr] = {'debug': str(e)}
            except (requests.exceptions.Timeout,
                    requests.exceptions.ReadTimeout) as e:
                to_report['TIMEOUT'][protocol][addr] = {'debug': str(e)}
            except requests.exceptions.TooManyRedirects as e:
                to_report['TOO_MANY_REDIRECTS'][protocol][addr] = {'debug': str(e)}
            except Exception as e:
                to_report['UNKNOWN_ERROR'][protocol][addr] = {'debug': str(e)}
            else:
                if r.status_code != 200:
                    to_report['HTTP_%d' % r.status_code][protocol][addr] = {}
                elif r.history[0].status_code == 302 and 'yunohost/sso' in r.url:
                    to_report['SSO_CAPTURE'][protocol][addr] = {}
            finally:
                session.close()

    errors += _aggregate_report_by_target(to_report, domain, {'url': url})
    return errors

@need_connexion
def check_domain_renewal(domain, critical_limit=2, error_limit=7, warning_limit=30):
    expire_date = _get_domain_expiration(domain)
    
    if not expire_date:
        return [('DOMAIN_EXPIRATION_NOT_FOUND', {'domain': domain})]

    expire_in = expire_date - datetime.now()
    if expire_in <= timedelta(critical_limit):
        return [('DOMAIN_EXPIRE', {'domain': domain}, {'remaining_days': expire_in.days})]
    elif expire_in <= timedelta(error_limit):
        return [('DOMAIN_NEARLY_EXPIRE', {'domain': domain}, {'remaining_days': expire_in.days})]
    elif expire_in <= timedelta(warning_limit):
        return [('DOMAIN_WILL_EXPIRE', {'domain': domain}, {'remaining_days': expire_in.days})]
    return []

@need_connexion
def check_dns_resolver(resolver=None, hostname='wikipedia.org', qname='A', expected_results=None):
    # TODO reduce errors
    if resolver is None:
        my_resolver = dns.resolver
    elif (not IP.v4 and '.' in resolver) or \
         (not IP.v6 and ':' in resolver):
        logging.debug('No connexion in this protocol to test the resolver')
        return []
    else:
        my_resolver = dns.resolver.Resolver()
        my_resolver.nameservers = [resolver]
        my_resolver.timeout = 10
    
    try:
        answers = my_resolver.query(hostname, qname)
    except dns.exception.Timeout as e:
        return [('TIMEOUT', {'resolver': resolver}, {'debug': str(e)})]
    except dns.resolver.NXDOMAIN as e:
        return [('DOMAIN_UNCONFIGURED', {'domain': hostname}, {'debug': str(e)})]
    except dns.resolver.NoAnswer as e:
        return [('NO_ANSWER', {'domain': hostname}, {'debug': str(e)})]
    if expected_results is not None:
        answers = [answer.to_text() for answer in answers]
        if set(answers) ^ set(expected_results):
            return [('UNEXPECTED_ANSWER', {'domain': hostname}, 
                     {'get': set(answers), 'expected': set(expected_results)})]
    return []

@need_connexion
def check_blacklisted(addr, hostname):
    errors = []
    for bl, description in DEFAULT_BLACKLIST:
        try:
            rev = dns.reversename.from_address(addr)
            query = str(rev.split(3)[0]) + '.' + bl
            # TODO add timeout lifetime
            dns.resolver.query(query, "A")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.resolver.NoAnswer, 
                dns.exception.Timeout):
            continue
        reason_or_link = None
        try:
            reason_or_link = dns.resolver.query(query, "TXT")[0]
        except Exception:
            pass
        errors.append(('BLACKLISTED', {'domain': hostname, 'ip': addr}, {'rbl': bl, 'rbl_description': description, 'txt': reason_or_link}))
    return errors

@need_connexion
def check_smtp(hostname, ports=[25, 587], blacklist=True):
    # TODO check spf
    # TODO check dkim
    errors = []
    
    # Do check for all ips of all MX
    mx_domains = {mx.preference: mx.exchange.to_text(True) 
                  for mx in dns.resolver.query(hostname, 'MX')}
    mx_domains = [mx_domains[key] for key in sorted(mx_domains)]
    
    if not mx_domains:
        errors.append(('NO_MX_RECORD', {'domain': hostname}))
        # If no MX consider A and AAAA records
        mx_domains = [hostname]

    for mx_domain in mx_domains:
        errors += check_ip_address(mx_domain)

        for protocol, addrs in cache[mx_domain].items():
            if not IP[protocol] or not addrs:
                continue
        
            # Try to do the request for each ips
            for addr, _ports in addrs.items():

                # Check Reverse DNS
                try:
                    name, _, _ = socket.gethostbyaddr(addr)
                except socket.herror as e:
                    errors.append(('REVERSE_MISSING', {'domain': hostname, 'ip': addr}))
                else:
                    if name != mx_domain:
                        errors.append(('REVERSE_MISMATCH', {'domain': hostname, 'ip': addr}, {'get': name, 'expected': mx_domain}))
                
                # Check rbl
                if blacklist:
                    errors += check_blacklisted(addr, hostname)

                if not IP.v4 and '.' in addr:
                    logging.debug('No IPv4 connexion, can\'t check SMTP %s' % addr)
                    continue
                
                if not IP.v6 and ':' in addr:
                    logging.debug('No IPv6 connexion, can\'t check SMTP %s' % addr)
                    continue

    # Check SMTP works
    for port in ports:
        for mx_domain in mx_domains:
            to_report = {msg: {'v4':{}, 'v6': {}} for msg in [
                'CERT_RENEWAL_FAILED',
                'PORT_CLOSED_OR_SERVICE_DOWN'
            ]}

            for protocol, addrs in cache[mx_domain].items():
                if not IP[protocol] or not addrs:
                    continue
            
                # Try to do the request for each ips
                for addr, _ports in addrs.items():
                    if port in _ports and _ports[port] == 'notworking':
                        continue

                    server = None
                    try:
                        server = smtplib.SMTP(addr, port, timeout=10) 
                        server.ehlo()
                        server.starttls()

                        # Check certificate
                        pem = ssl.DER_cert_to_PEM_cert(server.sock.getpeercert(binary_form=True))
                        cert = x509.load_pem_x509_certificate(pem.encode(), default_backend())
                        notAfter = cert.not_valid_after
                        expire_in = notAfter - datetime.now()
                        if expire_in < timedelta(14):
                            to_report['CERT_RENEWAL_FAILED'][protocol][addr] = {'remaining_days': expire_in.days}
                    except OSError:
                        to_report['PORT_CLOSED_OR_SERVICE_DOWN'][protocol][addr] = {}
                        _ports[port] = 'notworking'
                    finally:
                        if server:
                            server.quit()

            errors += _aggregate_report_by_target(to_report, mx_domain,
                                              {'domain': hostname, 'port': port})
    return errors


@need_connexion
def check_imap():
    return []


@need_connexion
def check_pop():
    return []


@need_connexion
def check_xmpp():
    return []


@run_on_monitored_server
def check_dns_resolution():
    return check_dns_resolver(None)


@run_on_monitored_server
def check_service_up(service):
    d = dbus.SystemBus()

    systemd = d.get_object('org.freedesktop.systemd1', '/org/freedesktop/systemd1')
    manager = dbus.Interface(systemd, 'org.freedesktop.systemd1.Manager')

    # c.f. https://zignar.net/2014/09/08/getting-started-with-dbus-python-systemd/
    # Very interface, much intuitive, wow
    service_unit = manager.LoadUnit(service + '.service')
    service_proxy = d.get_object('org.freedesktop.systemd1', str(service_unit))
    properties_interface = dbus.Interface(service_proxy, 'org.freedesktop.DBus.Properties')

    properties = properties_interface.GetAll('org.freedesktop.systemd1.Unit')

    if properties.get("LoadState", "not-found") == "not-found":
        # Service doesn't really exist
        return [('NOT_FOUND', {'service': service})]
    elif properties['SubState'] == 'running':
        return []
    elif properties['SubState'] == 'exited':
        return [('DOWN', {'service': service})]
    else:
        return [('FAILED', {'service': service})]


@run_on_monitored_server
def check_disk_health(device):
    # TODO short/long test and scsi error
    errors = []
    # Check device smart capabilities
    p = Popen(['smartctl', '-i', "/dev/%s" % device], stdout=PIPE, stderr=PIPE)
    out, err = p.communicate()
    out = out.decode("utf-8").strip()
    if "SMART support is: Available" not in out:
        return [('SMART_NOT_SUPPORTED', {'device': device})]

    # Activate SMART 
    p = Popen(['smartctl', '--smart=on', "--offlineauto=on", "--saveauto=on", "/dev/%s" % device], stdout=PIPE, stderr=PIPE)
    out, err = p.communicate()
    out = out.decode("utf-8").strip()
    if "SMART Enabled." not in out:
        return [('SMART_DISABLED', {'device': device})]

    if "SMART Automatic Offline Testing Enabled" not in out:
        errors.append(('SMART_HALF_WORKING', {'device': device}))
    
    # Check Health status
    p = Popen(['smartctl', '-H', "/dev/%s" % device], stdout=PIPE, stderr=PIPE)
    out, err = p.communicate()
    out = out.decode("utf-8").strip()
    if "SMART overall-health self-assessment test result: PASSED" not in out:
        errors.append(('DISK_FAILURE', {'device': device}))

    return errors


@run_on_monitored_server
def check_free_space(warning=1500, error=600, critical=200, paths=None):
    if not paths:
        paths = ['/', '/home', '/var', '/etc', '/var/log', '/boot', '/usr',
                 '/bin', '/home/yunohost.backup/archives', '/opt']

    errors = []
    for path in paths:
        if not os.path.ismount(path):
            continue
        total, used, free = shutil.disk_usage(path)
        disk_usage = {'path': path, 'total': total, 'free': free}
        if free == 0:
            errors.append(('NO_FREE_SPACE', disk_usage))
        if free < critical * 1024 * 1024:
            errors.append(('C_FREE_SPACE', disk_usage))
        elif free < error * 1024 * 1024:
            errors.append(('E_FREE_SPACE', disk_usage))
        elif free < warning * 1024 * 1024:
            errors.append(('W_FREE_SPACE', disk_usage))
    return errors


@run_on_monitored_server
def check_backuped(app, backup_app):
    # TODO protect passphrase
    if 'borg' in backup_app:
        param = yaml.load(open('/etc/yunohost/apps/%s/settings.yml' % backup_app))
        cmd = [
            "BORG_RSH='ssh -i /root/.ssh/id_%s_ed25519 '" % backup_app,
            "BORG_PASSPHRASE='%s'" % param['passphrase'], "borg", "list", '-P',
            "auto_%s" % app, '--last', '1', '--format', '"{archive|time}"',
            "ssh://%s@%s/~/backup" % (param['ssh_user'], param['server'])
        ]
        p = Popen(cmd, stdout=PIPE, stderr=PIPE)
        out, err = p.communicate()
        out = out.decode("utf-8").strip().split('|')
        if len(out) == 0:
            return [('NEVER_BACKUP', {'app': app, 'backup_app': backup_app})]
        archive = out[0]
        
        last_backup = datetime.strptime(out[1], '%a, %Y-%m-%d %H:%M:%S')
        theorical_date = datetime.now()
        cmd = ['systemctl', 'show', backup_app + '.service', '-p',
               'ExecMainExitTimestamp', '--value']
        p = Popen(cmd, stdout=PIPE, stderr=PIPE)
        out, err = p.communicate()
        out = out.decode("utf-8").strip()
        theorical_date = datetime.strptime(out[1], '%a %Y-%m-%d %H:%M:%S %Z')
        
        if last_backup < theorical_date:
            return [('MISSING_BACKUP', {'app': app, 'backup_app': backup_app}, 
                     {'last_backup': last_backup, 'theorical_date': theorical_date})]
        delays = {
            'hourly': 1,
            'daily': 1,
            '*-*-*': 1,
            'weekly': 7,
            'monthly': 31
        }
        param['on_calendar'] = param['on_calendar'].split(' ')[0]
        if param['on_calendar'] in delays.keys() and \
            theorical_date <  datetime.now() - timedelta(delays[param['on_calendar']]):
            return [('BACKUP_NOT_TRIGGERED', {'app': app, 'backup_app': backup_app}, 
                     {'last_backup':last_backup, 'theorical_date':theorical_date})]

        cmd = [
            "BORG_RSH='ssh -i /root/.ssh/id_%s_ed25519 '" % backup_app,
            "BORG_PASSPHRASE='%s'" % param['passphrase'], "borg", "list",
            '--pattern', '"Rinfo.json"', '--pattern', '"Rbackup.csv"',
            "ssh://%s@%s/~/backup::%s" % (param['ssh_user'], param['server'], archive)
        ]
        p = Popen(cmd, stdout=PIPE, stderr=PIPE)
        out, err = p.communicate()
        out = out.decode("utf-8").strip().split("\n")
        if len(out) < 2:
            return [('BACKUP_BROKEN', {'app': app, 'backup_app': backup_app})]
    elif 'archivist' in backup_app:
        # TODO
        pass

    return []

@run_on_monitored_server
def check_ynh_upgrade():
    errors = []
    # Check device smart capabilities
    p = Popen(['yunohost', 'tools', "update", '--quiet', '--timeout', '30'], stdout=PIPE, stderr=PIPE)
    out, err = p.communicate()
    out = out.decode("utf-8").strip()
    out = yaml.load(out)
   
    if 'apps' not in out:
        logging.debug('No output for yunohost tools update')
        return []

    if len(out['apps']) > 0:
        for app in out['apps'].values():
            errors.append(('APP_NEED_UPGRADE', {'app': app['id']}))
    if len(out['system']) > 0:
        errors.append(('PKG_NEED_UPGRADE', {}, {'number': len(out['system']), 
                                            'packages': [x['name'] for x in out['system'].values()]}))
    return errors
    

def _get_domain_expiration(domain):
    domain = '.'.join(domain.split('.')[-2:])
    p1 = Popen(['whois', domain], stdout=PIPE)
    p2 = Popen(['grep', 'Expir'], stdin=p1.stdout, stdout=PIPE)
    out, err = p2.communicate()
    out = out.decode("utf-8").split('\n')
    p1.terminate()
    p2.terminate()
    if len(out) > 1:
        match = re.search(r'\d{4}-\d{2}-\d{2}', out[0])
        return datetime.strptime(match.group(), '%Y-%m-%d')
    else:
        return False

def _get_cert_info(hostname, ip=None, port=443):
    if ip is None:
        ip = hostname
    context = ssl.create_default_context()
    #context.check_hostname = False
    conn = context.wrap_socket(
        socket.socket(socket.AF_INET),
        server_hostname=hostname,
    )
    # 3 second timeout because Lambda has runtime limitations
    conn.settimeout(3.0)
    conn.connect((ip, port))
    peercert = conn.getpeercert()
    conn.close()
    return peercert

def _aggregate_report_by_target(to_report, domain, base_target):
    errors = []
    # Agregate target
    for message, reports in to_report.items():
        if len(reports['v4']) == len(cache[domain]['v4']) and \
           len(reports['v6']) == len(cache[domain]['v6']):
            extra = reports['v4'][list(reports['v4'].keys())[0]] if reports['v4'] else reports['v6'][list(reports['v6'].keys())[0]]
            errors.append((message, base_target, extra))
            reports = {'v4':{}, 'v6': {}}
        elif len(reports['v4']) == len(cache[domain]['v4']) and reports['v4']:
            extra = reports['v4'][list(reports['v4'].keys())[0]]
            errors.append((message, {**base_target, 'protocol': 'v4'}, extra))
            reports['v4'] = {}
        elif len(reports['v6']) == len(cache[domain]['v6']) and reports['v6']:
            extra = reports['v6'][list(reports['v6'].keys())[0]]
            errors.append((message, {**base_target, 'protocol': 'v6'}, extra))
            reports['v6'] = {}
        
        for ip, report in reports['v4'].items():
            errors.append((message, {**base_target, 'ip': ip}, report))
        for ip, report in reports['v6'].items():
            errors.append((message, {**base_target, 'ip': ip}, report))
    return errors

def _reset_cache():
    global cache
    cache = {}

# =============================================================================
# ACTIONS PLUGINS
# =============================================================================


def service_up(alerts):
    # TODO service up
    for service, message in alerts:
        pass

@need_connexion
def mail_alert(alerts, mails):
    for server, failures in alerts.items():
        for message, reports in failures.items():
            for report in reports:
                info = {**report['target'], **report['extra']}
                context = {
                    'server': server, 
                    'level': report['level'], 
                    'message': message, 
                    'target': ', '.join([str(x) for x in report['target'].values()]),
                    'extra': yaml.dump(report['extra']),
                }
                context['user_info'] = MONITORING_ERRORS[message]['user'].format(**info)
                context['admin_info'] = MONITORING_ERRORS[message]['admin'].format(**info)
                

                subject = MAIL_SUBJECT.format(**context)
                body = MAIL_BODY.format(**context)

                open("/tmp/monitoring-body", "w").write(body)
                os.system("mail -s '%s' %s < /tmp/monitoring-body" % (subject, ' '.join(mails)))


@need_connexion
def sms_alert(alerts, sms_apis):
    body = []
    for server, failures in alerts.items():
        body += ["[%s]" % (server)]
        for message, reports in failures.items():
            if MONITORING_ERRORS[message]['level'] == 'critical':
                body.append(message)
                for report in reports:
                    body.append('- ' + ', '.join([str(x) for x in report['target'].values()]))
        for message, reports in failures.items():
            if MONITORING_ERRORS[message]['level'] == 'error':
                body.append(message)
                for report in reports:
                    body.append('- ' + ', '.join([str(x) for x in report['target'].values()]))
    if len(body) > 1:
        body = "\n".join(body)
        body = urllib.parse.quote(body, safe='')
        for sms_api in sms_apis:
            try:
                requests.get(sms_api % (body), timeout=15)
            except Exception as e:
                print(str(e))
                pass

"""
def cachet_alert(alerts, ynh_maps, cachet_apis):
    for cachet_api in cachet_apis:
        cachet = Cachet(cachet_api, ynh_maps)
        cachet.create_missing_components()
        for category, reports in alerts.items():
            for target, infos in reports:
                message = cachet_message(category, target)
                cachet.create_or_update_incident(category, target, message)

class Cachet(object):
    # TODO Cachet
    def __init__(cachet_api, server, ynh_map):
        pass

    def create_missing_components(self):
        pass

    def create_or_update_incident(self, category, target, message):
        pass

    def _get_group_id(self):
        pass

    def _create_group(self):
        pass

    def _get_component_id(self):
        pass

    def _create_component(self):
        pass

    def _get_incident_id(self):
        pass

    def _create_incident(self):
        pass

    def _update_incident(self):
        pass
"""

if __name__ == "__main__":
    main(sys.argv[1:])
