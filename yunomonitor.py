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
import csv
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
import spf
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
    'NO_PING': {'level': 'critical', 'first': 3, 'minutes': 30, 
                'user': 'Le serveur est éteint ou injoignable',
                'admin': "Le serveur '{domain}' est éteint ou injoignable"},
    'NO_IPV4_PING': {'level': 'critical', 'first': 3, 'minutes': 30, 
                'user': "Le serveur est injoignable pour certains équipements",
                'admin': "Le serveur '{domain}' est injoignable en ipv4"},
    'NO_IPV6_PING': {'level': 'critical', 'first': 3, 'minutes': 30, 
                'user': 'Le serveur est injoignable pour certains équipements',
                'admin': "Le serveur '{domain}' est injoignable en ipv6"},
    'DOMAIN_UNCONFIGURED': {'level': 'critical', 'first': 2, 'minutes': 30, 
                'user': "Le service n’est pas joignable car le nom de domaine {domain} n’est pas correctement configuré.",
                'admin': "Le nom de domaine {domain} n’est pas configuré."},
    'DOMAIN_UNCONFIGURED_IN_IPV4': {'level': 'critical', 'first': 2, 'minutes': 30, 
                'user': "Le service n’est pas joignable par certains équipements car le nom de domaine {domain} n’est pas correctement configuré.",
                'admin': "Le nom de domaine {domain} n’est pas configuré pour ipv4. Beaucoup d’équipements ne pourront pas y accéder."},
    'DOMAIN_UNCONFIGURED_IN_IPV6': {'level': 'info', 'first': 2, 'minutes': 30, 
                'user': "",
                'admin': "Le service n'est pas configuré en IPv6."},
    'CERT_RENEWAL_FAILED': {'level': 'error', 'first': 1, 'minutes': 30, 
                'user': "Le renouvellement du certificat {protocol} de {domain} a échoué ou n’est pas pris en compte, sans intervention le service tombera en panne dans {days} jours",
                'admin': "Le renouvellement du certificat {protocol} de {domain} a échoué ou n’est pas pris en compte, sans intervention le service tombera en panne dans {days} jours"},
    'CERT_INVALID': {'level': 'critical', 'first': 1, 'minutes': 30, 
                'user': "Le service n’est pas joignable car le certificat de sécurité a expiré ou n’est pas accepté. Note: si l’adresse web auquel vous voulez accéder est une page publique (sans authentification), il est possible d’y accéder en navigation privée, en ajoutant une exception.",
                'admin': "Le service n’est pas joignable car le certificat de sécurité a expiré ou n’est pas accepté. Note: si l’adresse web auquel vous voulez accéder est une page publique (sans authentification), il est possible d’y accéder en navigation privée, en ajoutant une exception."},
    'PORT_CLOSED_OR_SERVICE_DOWN': {'level': 'critical', 'first': 2, 'minutes': 30, 
                'user': "Le service n’est pas joignable",
                'admin': "Le service n’est pas joignable"},
    'TIMEOUT': {'level': 'critical', 'first': 3, 'minutes': 30, 
                'user': "Le service n’est pas joignable",
                'admin': "Le service n’est pas joignable"},
    'TOO_MANY_REDIRECTS': {'level': 'critical', 'first': 2, 'minutes': 30, 
                'user': "Le service semble en panne",
                'admin': "Le service est en panne suite à une erreur de redirection."},
    'SSO_CAPTURE': {'level': 'critical', 'first': 2, 'minutes': 30, 
                'user': "Le service semble en panne",
                'admin': "Le service semble protégé par le SSO"},
    'HTTP_403': {'level': 'critical', 'first': 2, 'minutes': 30, 
                'user': "Le service semble en panne",
                'admin': "Le service est interdit d'accès"},
    'HTTP_404': {'level': 'critical', 'first': 2, 'minutes': 30, 
                'user': "Le service semble en panne",
                'admin': "Le service renvoie une erreur 404 page non trouvée"},
    'HTTP_500': {'level': 'critical', 'first': 2, 'minutes': 30, 
                'user': "Le service semble en panne",
                'admin': "Le service est en panne suite à une erreur logicielle."},
    'HTTP_502': {'level': 'critical', 'first': 2, 'minutes': 30, 
                'user': "Le service semble en panne",
                'admin': "Le service s’est eteint"},
    'HTTP_503': {'level': 'critical', 'first': 2, 'minutes': 30, 
                'user': "Le service semble en panne",
                'admin': "Le service est injoignable"},
    'DOMAIN_EXPIRATION_NOT_FOUND': {'level': 'info', 'first': 1, 'minutes': 1440, 
                'user': "",
                'admin': ""},
    'DOMAIN_WILL_EXPIRE': {'level': 'warning', 'first': 1, 'minutes': 1440, 
                'user': "Le nom de domaine {domain} expire dans {days} jours. Ne pas oublier de le renouveller.",
                'admin': "Le nom de domaine {domain} expire dans {days} jours. Ne pas oublier de le renouveller."},
    'DOMAIN_NEARLY_EXPIRE': {'level': 'error', 'first': 1, 'minutes': 1440, 
                'user': "Le nom de domaine {domain} expire dans {days} jours. Sans renouvellement le service ne fonctionnera plus.",
                'admin': "Le nom de domaine {domain} expire dans {days} jours. Sans renouvellement le service ne fonctionnera plus."},
    'DOMAIN_EXPIRE': {'level': 'critical', 'first': 3, 'minutes': 300, 
                'user': "Le nom de domaine {domain} expire aujourd’hui ou demain. Sans renouvellement le service ne fonctionnera plus.",
                'admin': "Le nom de domaine {domain} expire aujourd’hui ou demain. Sans renouvellement le service ne fonctionnera plus."},
    'BROKEN_NAMESERVER': {'level': 'critical', 'first': 3, 'minutes': 30, 
                'user': "Un problème de connectivité interne pourrait créer des dysfonctionnements",
                'admin': "Le serveur de nom à l’adresse {ip} est injoignable"},
#    'TIMEOUT': {'level': 'critical', 'first': 3, 'minutes': 30, 
#                'user': "Un problème de connectivité interne pourrait créer des dysfonctionnements",
#                'admin': "Le serveur de nom à l’adresse {ip} est trop lent"},
    'NO_ANSWER': {'level': 'critical', 'first': 2, 'minutes': 30, 
                'user': "Le service n’est pas joignable car le nom de domaine {domain} n’est pas correctement configuré.",
                'admin': "Le nom de domaine {domain} n’est pas configuré."},
    'UNEXPECTED_ANSWER': {'level': 'critical', 'first': 1, 'minutes': 30, 
                'user': "",
                'admin': ""},
    'NO_MX_RECORD': {'level': 'error', 'first': 1, 'minutes': 30, 
                'user': "Un problème de configuration des mails a été détecté. Certains mails pourraient tombés en SPAM.",
                'admin': "Aucune configuration MX pour le domaine {domain}. Certains mails pourraient être calssé en SPAM."},
    'REVERSE_MISSING': {'level': 'critical', 'first': 1, 'minutes': 30, 
                'user': "Un problème de configuration des mails a été détecté. Certains mails pourraient tombés en SPAM.",
                'admin': "Le DNS inversé n’a pas été configuré pour l’ip {ip} et le domaine {ehlo_domain}. Le serveur pourraient être blacklisté et certains mails en@{domain} pourraient être classé en SPAM"},
    'REVERSE_MISMATCH': {'level': 'critical', 'first': 1, 'minutes': 30, 
                'user': "Un problème de configuration des mails a été détecté. Certains mails pourraient tombés en SPAM.",
                'admin': "Le DNS inversé pour l’ip {ip} est configuré pour le domaine {reverse_dns} au lieu de domaine {ehlo_domain}. Le serveur pourraient être blacklisté et certains mails en @{domain} pourraient être classé en SPAM"},
    'BLACKLISTED': {'level': 'critical', 'first': 1, 'minutes': 30, 
                'user': "L’ip du serveur a été blacklistée par {rbl}. Certains mails pourraient tombés en SPAM.",
                'admin': "L’ip du serveur a été blacklistée par {rbl}. Certains mails pourraient tombés en SPAM."},
    'NOT_FOUND': {'level': 'critical', 'first': 1, 'minutes': 30, 
                'user': "Un des programmes est en panne, des dysfonctionnements sur le service peuvent subvenir.",
                'admin': "Le service {service} n’existe pas"},
    'DOWN': {'level': 'critical', 'first': 2, 'minutes': 30, 
                'user': "Un des programmes est en panne, des dysfonctionnements sur le service peuvent subvenir.",
                'admin': "Le service {service} est éteint il devrait être allumé."},
    'FAILED': {'level': 'critical', 'first': 2, 'minutes': 30, 
                'user': "Un des programmes est en panne, des dysfonctionnements sur le service peuvent subvenir.",
                'admin': "Le service {service} est tombé en panne il faut le relancer et investiguer."},
    'SMART_NOT_SUPPORTED': {'level': 'warning', 'first': 1, 'minutes': 1440, 
                'user': "",
                'admin': "Un disque dur ne supporte pas les fonctionnalités permétant le contrôle de son état de santé."},
    'SMART_DISABLED': {'level': 'error', 'first': 1, 'minutes': 1440, 
                'user': "L’activation du contrôle de l’état de santé d’un disque dur n’a pas fonctionné.",
                'admin': "L’activation du contrôle de l’état de santé d’un disque dur n’a pas fonctionné."},
    'SMART_HALF_WORKING': {'level': 'error', 'first': 1, 'minutes': 1440, 
                'user': "Le contrôle de l’état de santé d’un disque dur n’est que partiellement activé.",
                'admin': "Le contrôle de l’état de santé d’un disque dur n’est que partiellement activé."},
    'DISK_FAILURE': {'level': 'critical', 'first': 1, 'minutes': 30, 
                'user': "Un disque dur semble sur le point de tomber en panne, il faut le changer rapidement.",
                'admin': "Un disque dur semble sur le point de tomber en panne, il faut le changer rapidement."},
    'NO_FREE_SPACE': {'level': 'critical', 'first': 1, 'minutes': 30, 
                'user': "Il n’y a plus d’espace disque sur le serveur des dysfonctionnements sont à prévoir",
                'admin': "Il n’y a plus d’espace disque sur le serveur des dysfonctionnements sont à prévoir"},
    'C_FREE_SPACE': {'level': 'critical', 'first': 1, 'minutes': 30, 
                'user': "L’espace disque sur le serveur est trop faible, si rien n’est fait rapidement des dysfonctionnements sont à prévoir",
                'admin': "L’espace disque sur le serveur est trop faible, si rien n’est fait rapidement des dysfonctionnements sont à prévoir"},
    'E_FREE_SPACE': {'level': 'error', 'first': 1, 'minutes': 1440, 
                'user': "L’espace disque sur le serveur est trop faible, si rien n’est fait des dysfonctionnements pourraient subvenir",
                'admin': "L’espace disque sur le serveur est trop faible, si rien n’est fait des dysfonctionnements pourraient subvenir"},
    'W_FREE_SPACE': {'level': 'warning', 'first': 1, 'minutes': 1440, 
                'user': "",
                'admin': "L’espace disque sur le serveur est assez réduit."},
    'NO_BACKUP': {'level': 'error', 'first': 2, 'minutes': 30, 
                'user': "Aucune sauvegarde [de {app}] n’a été trouvée sur le serveur de [sauvegarde à paris].",
                'admin': "Aucune sauvegarde [de {app}] n’a été trouvée sur le serveur de [sauvegarde à paris]."},
    'MISSING_BACKUP': {'level': 'error', 'first': 2, 'minutes': 30, 
                'user': "La dernière sauvegarde [de {app}] sur le serveur de [sauvegarde à paris] est manquante. ",
                'admin': "La dernière sauvegarde [de {app}] sur le serveur de [sauvegarde à paris] est manquante. "},
    'BACKUP_NOT_TRIGGERED': {'level': 'error', 'first': 2, 'minutes': 30, 
                'user': "La sauvegarde vers le serveur de sauvegarde à paris n’a pas été déclenchée au cours des dernières 24h.",
                'admin': "La sauvegarde vers le serveur de sauvegarde à paris n’a pas été déclenchée au cours des dernières 24h."},
    'BACKUP_BROKEN': {'level': 'error', 'first': 2, 'minutes': 30, 
                'user': "La dernière sauvegarde [de {app}] sur le serveur de sauvegarde à paris est incomplète. Une restauration manuelle resterait peut être possible.",
                'admin': "La dernière sauvegarde [de {app}] sur le serveur de sauvegarde à paris est incomplète. Une restauration manuelle resterait peut être possible."},
    'APP_NEED_UPGRADE': {'level': 'warning', 'first': 1, 'minutes': 1440, 
                'user': "",
                'admin': "Une mise à jour est disponible pour l'application {app}"},
    'PKG_NEED_UPGRADE': {'level': 'warning', 'first': 1, 'minutes': 1440, 
                'user': "",
                'admin': "Une mise à jour des paquets systèmes est disponible"},
    'UNKNOWN_ERROR': {'level': 'error', 'first': 3, 'minutes': 30, 
                'user': "",
                'admin': "Une erreur non gérée par le système de monitoring est survenue"},
}

# Trigger actions every 8*3 minutes of failures
ALERT_FREQUENCY = 3

# Update monitoring configuration each hours
CACHE_DURATION_IN_MINUTES = 60

WORKING_DIR = os.path.abspath(os.path.dirname(__file__))
WELL_KNOWN_URI = 'https://%s/.well-known/yunomonitor/'
REMOTE_MONITORING_CONFIG_FILE = os.path.join(WELL_KNOWN_URI, '%s.to_monitor')
REMOTE_FAILURES_FILE = os.path.join(WELL_KNOWN_URI, '%s.failures')
WELL_KNOWN_DIR = os.path.join(WORKING_DIR, 'well-known/')
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
CONFIG_DIR = os.path.join(WORKING_DIR, "conf/")
IGNORE_ALERT_CSV = os.path.join(CONFIG_DIR, "ignore_alert.csv")
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

# Import user settings
try:
    from settings_local import *
except:
    pass
# =============================================================================
# GLOBAL VARS
# =============================================================================


#logging.basicConfig(level=logging.WARNING)
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
    start_time = time.time()    
    # Parse arguments
    try:
        opts, monitored_servers = getopt.getopt(argv, "hm:s:C:e:c:", 
                                                ["mail=", "sms=", "cachet=", 
                                                 "encrypt-for=", "config="])
    except getopt.GetoptError:
        display_help(2)
    
    logging.debug("Given options: %s" % (opts))
    logging.debug("Servers to monitor: %s" % (monitored_servers))
    
    config_file = None
    for opt, arg in opts:
        if opt == '-h':
            display_help()
        elif opt in ("-c", "--config"):
            config_file = arg

    if config_file:
        with open(config_file, 'r') as local_config_file:
            config = yaml.load(local_config_file)
    else:
        config = {
            'mails': [],
            'sms_apis': [],
            'cachet_apis': [],
            'monitoring_servers': [],
            'monitored_servers': monitored_servers,
        }

    for param in ['mails', 'sms_apis', 'cachet_apis', 'monitoring_servers', 'monitored_servers']:
        config[param] = set(config[param]) if param in config else set()

    for opt, arg in opts:
        if opt in ("-m", "--mail"):
            config['mails'].add(arg)
        elif opt in ("-s", "--sms"):
            config['sms_apis'].add(arg)
        elif opt in ("-C", "--cachet"):
            config['cachet_apis'].add(arg)
        elif opt in ("-e", "--encrypt-for"):
            config['monitoring_servers'].add(arg)


    if config['monitored_servers'] == set():
        config['monitored_servers'] = ['localhost']
    
    levels = {
        'CRITICAL': logging.CRITICAL, 
        'ERROR': logging.ERROR, 
        'WARNING': logging.WARNING, 
        'INFO':logging.INFO, 
        'DEBUG':logging.DEBUG
    }
    if config.get('logging_level', 'WARNING') in levels.keys():
        logging.basicConfig(level=levels[config.get('logging_level', 'WARNING')])

    logging.debug("Config: %s" % (config))

    # If we are offline in IPv4 and IPv6 execute only local checks
    IP.v4 = not check_ping("wikipedia.org", ['v4'])
    IP.v6 = socket.has_ipv6 and not check_ping("wikipedia.org", ['v6'])
    if not IP.v4 and not IP.v6:
        logging.debug('NO CONNECTION')
        if 'localhost' not in config['monitored_servers']:
            sys.exit(2)
        logging.warning('ONLY LOCAL TEST WILL BE RUN')
        config['monitored_servers'] = set(['localhost'])
    elif  not IP.v6:
        logging.info('NO IPV6 ON THIS MONITORING SERVER')

    # Create well-known dir
    try:
        os.mkdir(WELL_KNOWN_DIR)
    except:
        # The dir may already exist
        pass

    # Publish ssh pub key into well-known
    publish_ssh_public_key()

    # Load or download monitoring description of each server, convert
    # monitoring instructions, execute it
    logging.info("CHECKING EACH SERVERS...")
    logging.debug('Load or download monitoring description of each server, convert monitoring instructions, execute it')
    threads = [ServerMonitor(server, config['monitoring_servers']) for server in config['monitored_servers']]
    for thread in threads:
        thread.start()
    
    alerts = {}
    # Wait for all thread
    logging.debug('Waiting for all threads')
    for thread in threads:
        thread.join()
        alerts[thread.server]=thread.failures

    # Filter by reccurence or ignored status
    logging.info('FILTERING...')
    filtered = {}
    for server, failures in alerts.items():
        filtered[server] = {}
        for message, reports in failures.items():
            if not message in MONITORING_ERRORS:
                logging.error("ERROR MESSAGE MISSING %s" %(message))
                message = 'UNKNOWN_ERROR'
            first = MONITORING_ERRORS[message]['first']
            freq = round(MONITORING_ERRORS[message]['minutes'] / CRON_FREQUENCY)
            filtered[server][message] = []
            
            for report in reports:
                logging.debug(report)
                logging.debug("first: %d freq: %d" %(first, freq))
                if (report['count'] - first) % freq == 0:
                    report['level'] = MONITORING_ERRORS[message]['level']
                    filtered[server][message].append(report)
            if not filtered[server][message]:
                del filtered[server][message]
    
    # Trigger some actions
    if config['mails']:
        logging.info('MAILING...')
        mail_alert(filtered, config['mails'])
    
    if config['sms_apis']:
        logging.info('ALERTING BY SMS...')
        sms_alert(filtered, config['sms_apis'])
    #cachet_alert(alerts, ynh_maps, config['cachet_apis'])

    #if 'localhost' in alerts:
    #    logging.info('FILLING CACHET...')
    #    service_up(alerts['localhost'].get('service_up', []))
    logging.debug("===================> %f s" % (start_time - time.time()))

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
        logging.info("[%s] CONFIGURING..." % (self.server))
        self.ynh_maps[self.server] = self._load_monitoring_config()
        logging.info("[%s] MONITORING..." % (self.server))
        self._monitor()
        logging.info("[%s] COUNTING FAILURES..." % (self.server))
        self._count()
        logging.info("[%s] ADDING FAILURES REPORTED BY MONITORED SERVER ITSELF..." % (self.server))
        self._add_remote_failures()
        logging.info("[%s] SAVING FAILURES..." % (self.server))
        self._save()
        if self.server == "localhost":
            logging.info("[%s] PUBLISHING FAILURES..." % (self.server))
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
                        config = yaml.load(cache_config_file)
                    
                    # In case the cache config is in a bad format (404 content...)
                    if not isinstance(config, str):
                        return config
            
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
                logging.info("Try to download the remote config : %s" % (config_url))
                try:
                    r = requests.get(config_url, timeout=15)
                    assert r.status_code == 200, "Fail to download the configuration"
                    config = yaml.load(decrypt(r.content))
                    assert not isinstance(config, str), "Misformed downloaded configuration"
                except Exception as e:
                    logging.warning('Unable to download autoconfiguration file, the old one will be used')
                    try:
                        with open(cache_config, 'r') as cache_config_file:
                            cconfig = yaml.load(cache_config_file)
                    except FileNotFoundError as e:
                        cconfig = ''

                    assert not isinstance(cconfig, str), "Unable to load an old config too, yunomonitor is not able to monitor %s" % (self.server)

                    return cconfig

            # Write the configuration in cache
            with open(cache_config, 'w') as cache_config_file:
                yaml.dump(config, cache_config_file, default_flow_style=False)
            return config


    def _monitor(self):
        to_monitor = self.ynh_maps[self.server].copy()
        del to_monitor['__components__']
        
        # Remove checks that run on another machine
        if self.server == 'localhost':
            checks = ['dns_resolution', 'service_up', 'backuped', 'disk_health', 'free_space']
        else:
            checks = ['ping', 'dns_resolver', 'domain_renewal', 'https_200', 'smtp', 'smtp_sender', 'imap', 'xmpp']
        
        to_monitor = [(check, to_monitor[check]) for check in checks if check in to_monitor]

        # Check things to monitor
        for category, checks in to_monitor:
            for args in checks:
                try:
                    check_name = "check_%s" % (category)
                    if isinstance(args, str):
                        args = [args]
                    logging.debug("[%s] Running check: %s(%s)" % (self.server, check_name, args))
                    start_time = time.time()
                    if isinstance(args, dict):
                        reports = globals()[check_name](**args)
                    else:
                        reports = globals()[check_name](*args)
                except Exception as e:
                    reports = [('UNKNOWN_ERROR', {'check': category}, {'debug': str(e)})]
                logging.debug("===> %f s" % (time.time() - start_time))
                if reports:
                    logging.warning("[%s] Check: %s(%s)" % (self.server, check_name, args))
                    logging.warning(reports)
                for report in reports:
                    if report[0] not in self.failures:
                        self.failures[report[0]] = self.failures.get(report[0], [])
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

def publish_ssh_public_key():
    if not os.path.exists(WELL_KNOWN_DIR + '/ssh_host_rsa_key.pub'):
        from shutil import copyfile
        copyfile('/etc/ssh/ssh_host_rsa_key.pub', WELL_KNOWN_DIR + '/ssh_host_rsa_key.pub')

def get_public_key(server):
    cache_key = os.path.join(CONFIG_DIR, '%s.pub' % server)
    if os.path.exists(cache_key):
        with open(cache_key) as f:
            key = f.read()
    else:
        try:
            r = requests.get(PUBLIC_KEY_URI % server, timeout=15)
        except Exception as e:
            return None
        if r is None or r.status_code != 200:
            return None
        
        key = r.text
        with open(cache_key, 'w') as f:
            f.write(r.text)
    return key


def get_id_host(server=None):
    if not server:
        filename = '/etc/ssh/ssh_host_rsa_key.pub'
    else:
        get_public_key(server)
        filename = os.path.join(CONFIG_DIR, '%s.pub' % server)
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
    return cipher_message.decode()
    #with open('/etc/ssh/ssh_host_rsa_key') as f:
    #    key = RSA.importKey(f.read())
    #cipher = Cipher_PKCS1_v1_5.new(key)
    #return cipher.decrypt(cipher_message, None).decode()


def get_local_dns_resolver():
    if get_local_dns_resolver.dns_resolvers is None:
        with open('/etc/resolv.dnsmasq.conf', 'r') as resolv_file:
            get_local_dns_resolver.dns_resolvers = [x[11:].replace('\n', '') 
                                                    for x in resolv_file.readlines()]
    return get_local_dns_resolver.dns_resolvers
get_local_dns_resolver.dns_resolvers = None

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
        
        dns_resolver = get_local_dns_resolver()

        # TODO personalize meta components
        apps = [
            {
                "id": "mail",
                "name": "Mail",
                "label": "Mail",
                "services": ["rspamd", "dovecot", "postsrsd",
                             "dnsmasq", "slapd"] # postfix
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
                         "%s/yunohost/api/installed" % (current_host)],
                "services": ["nginx", "slapd", "ssh", "yunohost-api",
                             "systemd-logind"]
            },
            {
                "id": "firewall",
                "name": "Firewall",
                "label": "Parefeu",
                "services": ["fail2ban"] #yunohost-firewall
            },
            {
                "id": "misc",
                "name": "Base",
                "label": "Système de base",
                "services": ["avahi-daemon", "cron", "dbus",
                             "haveged", "ntp", "rsyslog", "syslog", 
                             "systemd-journald", "systemd-udevd"]
            }

        ]

        apps_dir = glob.glob('/etc/yunohost/apps/*')

        for app_dir in apps_dir:
            try:
                with open(os.path.join(app_dir, 'settings.yml'), 'r') as settings_file:
                    app_settings = yaml.load(settings_file)
                with open(os.path.join(app_dir, 'manifest.json'), 'r') as manifest_file:
                    app_manifest = json.load(manifest_file)
            except:
                continue

            uris = []
            if 'unprotected_uris' in app_settings or 'skipped_uris' in app_settings:
                if 'domain' in app_settings:
                    if 'path' in app_settings:
                        uris.append(app_settings['domain'] + app_settings['path'])
                    if 'unprotected_uris' in app_settings:
                        uris.append(app_settings['domain'] + app_settings['unprotected_uris'])
                    if 'skipped_uris' in app_settings:
                        uris.append(app_settings['domain'] + app_settings['skipped_uris'])

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
                "services": []
            }
            if 'services' in app_manifest:
                app["services"] = app_manifest['services']
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
        "smtp_sender": [[domain, [25,587]] for domain in domains],
        "imap": domains,
        "xmpp": domains,
        "dns_resolver": list(set(dns_resolver)),
        "disk_health": list(set(devices)),
        "free_space": [{}],
        "https_200": list(https_200),
        "service_up": list({x if x!='' and x!='php5-fpm' else 'php7.0-fpm' for x in service_up}),
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

def need_connection(func):
    def wrapper(*args, **kwargs):
        # Return no errors in case the monitoring server has no connection
        if not IP.connected:
            return []
    
        return func(*args, **kwargs)
    return wrapper

def run_on_monitored_server(func):
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)
    return wrapper

cache = {}

# Remote checks
def check_ping(hostname, proto=['v4', 'v6']):
    cmd = "timeout 4 ping -%s -c 1 -w 500 %s >/dev/null 2>&1"
    errors = []
    ip = {'v4': None, 'v6': None}
    if hostname in check_ping.cache:
        ip = check_ping.cache[hostname]

    for protocol in proto:
        if IP[protocol] and ip[protocol] is None:
            ip[protocol] = any(os.system(cmd % (protocol[1:], hostname)) == 0 for retry in range(3))
    
    check_ping.cache[hostname] = ip

    target = {'domain': hostname}
    if ip['v4'] == False and ip['v6'] == False and IP['v4'] and IP['v6']:
        errors.append(('NO_PING', target))
    elif ip['v4'] == False and IP['v4']:
        errors.append(('NO_IPV4_PING', target))
    elif ip['v6'] == False and IP['v6']:
        errors.append(('NO_IPV6_PING', target))

    return errors
check_ping.cache = {}

@need_connection
def check_ip_address(domain):
    global cache
    if domain not in cache:
        # Find all ips configured for the domain of the URL
        cache[domain] = {'v4': {}, 'v6': {}}
        status, answers = dig(domain, 'A', resolvers="force_external")
        if status == "ok":
            cache[domain]['v4'] = {addr:{} for addr in answers}
        status, answers = dig(domain, 'AAAA', resolvers="force_external")
        if status == "ok":
            cache[domain]['v6'] = {addr:{} for addr in answers}

    addrs = cache[domain]
    if not addrs['v4'] and not addrs['v6']:
        return [('DOMAIN_UNCONFIGURED', {'domain': domain})]

    if not (IP.v4 and addrs['v4']) and not (IP.v6 and addrs['v6']):
        logging.warning('No connection, can\'t check HTTP')
    
    # Error if no ip v4 address match with the domain
    if not addrs['v4']:
        return [('DOMAIN_MISCONFIGURED_IN_IPV4', 
                                {'domain': domain})]
    return []
@need_connection
def check_tls(domain, port=443):
    global cache
    errors = check_ip_address(domain)

    to_report = {
        'CERT_RENEWAL_FAILED': {'v4':{}, 'v6': {}},
        'CERT_INVALID': {'v4':{}, 'v6': {}},
        'PORT_CLOSED_OR_SERVICE_DOWN': {'v4':{}, 'v6': {}},
    }
    for protocol, addrs in cache[domain].items():
        if not IP[protocol] or not addrs or check_ping(domain, [protocol]) != []:
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

@need_connection
def check_https_200(url):
    global cache
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
        logging.warning('No connection, can\'t check HTTP')
        return []
    
    for protocol, addrs in cache[domain].items():
        if not IP[protocol] or not addrs or check_ping(domain, [protocol]) != []:
            continue
        
        # Try to do the request for each ips
        for addr, ports in addrs.items():
            if ports[port] == 'notworking':
                continue
            
            if protocol == 'v6':
                addr = '[' + addr + ']'
            try:

                session = requests.Session()
                
                # We want to test HTTPS response on a specific IP, to achieve
                # that we replace the domain name by the IP, but it cause
                # several issue related SNI and certificate hostname comparison
                
                # Fix hostname comparison issue, by using Host header
                adapter = host_header_ssl.HostHeaderSSLAdapter()

                # Fix SNI issue when we use IP instead of domain
                # https://github.com/requests/toolbelt/issues/159
                context = MySSLContext(domain)
                adapter.init_poolmanager(10, 10, ssl_context=context)
                
                # Use this specific adapter only for the first request, we
                # don't want to use it with redirected request.
                session.mount('https://' + addr + path, adapter)
               
                req = requests.Request('GET', "https://" + addr + path,
                                       headers={'Host': domain,
                                                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                                                'User-Agent': 'YunoMonitor'})
                r = req.prepare()
                res = session.send(r, allow_redirects=False)
                # Remove Host headers to avoid TOO MANY REDIRECTIONS bug
                del r.headers['Host']
                sso = False
                for redirected_res in session.resolve_redirects(res,r):
                    sso |= res.status_code == '302'  and '/yunohost/sso' in res.headers['location']
                    res = redirected_res
            
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
                if not res.ok:
                    to_report['HTTP_%d' % res.status_code][protocol][addr] = {}
                elif sso:
                    to_report['SSO_CAPTURE'][protocol][addr] = {}
            finally:
                session.close()

    errors += _aggregate_report_by_target(to_report, domain, {'url': url})
    return errors

@need_connection
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

@need_connection
def check_dns_resolver(resolver=None, hostname='wikipedia.org', qname='A', expected_results=None):
    # TODO reduce errors
    if resolver is None:
        my_resolver = dns.resolver
    elif (not IP.v4 and '.' in resolver) or \
         (not IP.v6 and ':' in resolver):
        logging.debug('No connection in this protocol to test the resolver')
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

@need_connection
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

def check_one_smtp_hostname(hostname, port, receiver_only=False):
    global cache
    errors = []
    to_report = {msg: {'v4':{}, 'v6': {}} for msg in [
        'CERT_RENEWAL_FAILED',
        'PORT_CLOSED_OR_SERVICE_DOWN'
    ]}
    for protocol, addrs in cache[hostname].items():
        if not IP[protocol] or not addrs or check_ping(hostname, [protocol]) != []:
            continue
    
        # Try to do the request for each ips
        for addr, _ports in addrs.items():
            if port in _ports and _ports[port] == 'notworking':
                continue

            server = None
            try:
                server = smtplib.SMTP(addr, port, timeout=10) 
                ehlo = server.ehlo()
                if not receiver_only:
                    ehlo_domain = ehlo[1].decode("utf-8").split("\n")[0]

                    rev = dns.reversename.from_address(addr)
                    subdomain = str(rev.split(3)[0])
                    query = subdomain
                    if "." in addr:
                        query += '.in-addr.arpa'
                    else:
                        query += '.ip6.arpa'

                    # Do the DNS Query
                    status, value = dig(query, 'PTR')
                    rdns_domain = ''
                    if status == "ok" and len(value) > 0:
                        rdns_domain = value[0][:-1] if value[0].endswith('.') else value[0]
                        if rdns_domain != ehlo_domain:
                            errors.append(('REVERSE_MISMATCH', {'domain': hostname, 'ip': addr}, {'reverse_dns': rdns_domain, 'ehlo_domain': ehlo_domain}))
                    else:
                        errors.append(('REVERSE_MISSING', {'domain': hostname, 'ip': addr}, {'ehlo_domain': ehlo_domain}))
        
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
        errors += _aggregate_report_by_target(to_report, hostname,
                                            {'domain': hostname, 'port': port})
    return errors

@need_connection
def check_smtp(hostname, ports=[25], blacklist=True):
    errors = []
    
    # Do check for all ips of all MX, check only reception capabilities
    mx_domains = {mx.preference: mx.exchange.to_text(True) 
                  for mx in dns.resolver.query(hostname, 'MX', raise_on_no_answer=False)}
    mx_domains = [mx_domains[key] for key in sorted(mx_domains)]
    
    if not mx_domains:
        errors.append(('NO_MX_RECORD', {'domain': hostname}))

    for mx_domain in mx_domains:
        errors += check_ip_address(mx_domain)
    
    for mx_domain in mx_domains:
        for port in ports:
            errors += check_one_smtp_hostname(mx_domain, port, receiver_only=True)
    
    return errors

@need_connection
def check_spf(smtp_sender, mail_domain):
    errors = []
    errors += check_ip_address(smtp_sender)
    for addrs in cache[smtp_sender].values():
        for addr in addrs.keys():
            try:
                status, message = spf.check2(i=addr, s='root@'+mail_domain, h=mail_domain)
            except spf.PermError as e:
                status = 'permerror'
                message = str(e)
            except spf.TempError as e:
                status = 'temperror'
                message = str(e)

            if status == 'none':
                errors += [('SPF_MISSING', {'domain': mail_domain}, {})]
                break
            elif status != 'pass':
                errors += [('SPF_ERROR', {'domain': mail_domain, 'ip': addr}, 
                            {'smtp_sender': smtp_sender, 'status': status, 'message': message})]
    return errors

@need_connection
def check_smtp_sender(hostname, ports=[25], blacklist=True):
    errors = []
    errors += check_ip_address(hostname)
        
    # Check rbl
    if blacklist:
        logging.debug('Start check rbl')
        for protocol, addrs in cache[hostname].items():
            if not IP[protocol] or not addrs:
                continue
        
            # Try to do the request for each ips
            for addr in addrs.keys():
                #errors += check_blacklisted(addr, hostname)
                pass

        logging.debug('End check rbl')

    # Check SPF
    check_spf(hostname, hostname)

    for port in ports:
        errors += check_one_smtp_hostname(hostname, port)
    
    return errors


@need_connection
def check_imap(domain):
    return []


@need_connection
def check_pop(domain):
    return []


@need_connection
def check_xmpp(domain):
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
        disk_usage = {'path': path, 'total': "%d MB" % (int(total) / 1024 / 1024), 'free': "%d MB" % (int(free) / 1024 / 1024)}
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
    # Disable this check
    return []
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
    if domain not in _get_domain_expiration.cache.keys():
        p1 = Popen(['whois', domain], stdout=PIPE)
        p2 = Popen(['grep', 'Expir'], stdin=p1.stdout, stdout=PIPE)
        out, err = p2.communicate()
        out = out.decode("utf-8").split('\n')
        p1.terminate()
        p2.terminate()
        _get_domain_expiration.cache[domain] = False
        for line in out:
            match = re.search(r'\d{4}-\d{2}-\d{2}', out[0])
            if match is not None:
                _get_domain_expiration.cache[domain] = datetime.strptime(match.group(), '%Y-%m-%d')
                break
    
    return _get_domain_expiration.cache[domain]
_get_domain_expiration.cache = {}

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

def dig(qname, rdtype="A", timeout=5, resolvers="local", edns_size=1500, full_answers=False):
    """
    Do a quick DNS request and avoid the "search" trap inside /etc/resolv.conf
    """

    # It's very important to do the request with a qname ended by .
    # If we don't and the domain fail, dns resolver try a second request
    # by concatenate the qname with the end of the "hostname"
    if not qname.endswith("."):
        qname += "."

    if resolvers == "local":
        resolvers = ["127.0.0.1"]
    elif resolvers == "force_external":
        resolvers = get_local_dns_resolver()
    else:
        assert isinstance(resolvers, list)

    resolver = dns.resolver.Resolver(configure=False)
    resolver.use_edns(0, 0, edns_size)
    resolver.nameservers = resolvers
    resolver.timeout = timeout
    try:
        answers = resolver.query(qname, rdtype)
    except (dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers,
            dns.resolver.NoAnswer,
            dns.exception.Timeout) as e:
        return ("nok", (e.__class__.__name__, e))

    if not full_answers:
        answers = [answer.to_text() for answer in answers]

    return ("ok", answers)

# =============================================================================
# ACTIONS PLUGINS
# =============================================================================

def is_ignored(method, level, server, message, target):
    if is_ignored.cache is None:
        try:
            with open(IGNORE_ALERT_CSV, newline='') as csvfile:
                ignore_csv = csv.DictReader(csvfile, delimiter=' ')
                is_ignored.cache = [ignore_instruction for ignore_instruction in ignore_csv]
        except:
            is_ignored.cache = []

    logging.debug("-> %s %s %s" % (server, message, target))
    for inst in is_ignored.cache:
        logging.debug("%s %s %s" % (inst['server'], inst['message'], inst['target']))
        if (inst['method'] == '*' or inst['method'] == method) \
           and (inst['level'] == '*' or inst['level'] == level) \
           and (inst['server'] == '*' or inst['server'] == server) \
           and (inst['message'] == '*' or inst['message'] == message) \
           and (inst['target'] == '*' or set(inst['target'].split(',')) == set(target.values())):
            return True

    
    return False
is_ignored.cache = None

def service_up(alerts):
    # TODO service up
    for service, message in alerts:
        pass

def mail_alert(alerts, mails):
    logging.debug(alerts)
    for server, failures in alerts.items():
        for message, reports in failures.items():
            for report in reports:
                if is_ignored('mail', report['level'], server, message, report['target']):
                    logging.info("Ignore %s %s %s %s %s" % ('mail', report['level'], server, message, report['target']))
                    continue
                info = {**report['target'], **report['extra']}
                context = {
                    'server': server, 
                    'level': report['level'], 
                    'message': message, 
                    'target': ', '.join([str(x) for x in report['target'].values()]),
                    'extra': yaml.dump(report['extra']),
                }
                try:
                    context['user_info'] = MONITORING_ERRORS[message]['user'].format(**info)
                    context['admin_info'] = MONITORING_ERRORS[message]['admin'].format(**info)
                except:
                    context['user_info'] = "An error occured during message creation"
                    context['admin_info'] = "An error occured during message creation"

                subject = MAIL_SUBJECT.format(**context)
                body = MAIL_BODY.format(**context)

                open("/tmp/monitoring-body", "w", encoding="utf-8").write(body)
                os.system("mail -a 'Content-Type: text/plain; charset=UTF-8' -s '%s' %s < /tmp/monitoring-body" % (subject, ' '.join(mails)))


def sms_alert(alerts, sms_apis):
    logging.debug(sms_apis)
    body = []
    for server, failures in alerts.items():
        body += ["[%s]" % (server)]
        for message, reports in failures.items():
            if MONITORING_ERRORS[message]['level'] == 'critical':
                body.append(message)
                for report in reports:
                    if is_ignored('sms', report['level'], server, message, report['target']):
                        logging.info("Ignore %s %s %s %s %s" % ('mail', report['level'], server, message, report['target']))
                        continue
                    body.append('- ' + ', '.join([str(x) for x in report['target'].values()]))
                if not body[-1].startswith('- '):
                    del body[-1]
        
        for message, reports in failures.items():
            if MONITORING_ERRORS[message]['level'] == 'error':
                body.append(message)
                for report in reports:
                    if is_ignored('sms', report['level'], server, message, report['target']):
                        logging.info("Ignore %s %s %s %s %s" % ('mail', report['level'], server, message, report['target']))
                        continue
                    body.append('- ' + ', '.join([str(x) for x in report['target'].values()]))
                if not body[-1].startswith('- '):
                    del body[-1]
        if body[-1].startswith('['):
            del body[-1]
    if len(body) > 0:
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
