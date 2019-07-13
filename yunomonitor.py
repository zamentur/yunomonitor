#!/usr/bin/python3

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

# Trigger actions every 8*3 minutes of failures
ALERT_FREQUENCY = 3

# Update monitoring configuration each hours
CACHE_DURATION_IN_MINUTES = 60

WELL_KNOWN_URI = 'https://%s/.well-known/yunomonitor/'
REMOTE_MONITORING_CONFIG_FILE = os.path.join(WELL_KNOWN_URI, '%s.to_monitor')
REMOTE_FAILURES_FILE = os.path.join(WELL_KNOWN_URI, '%s.failures')
WELL_KNOWN_DIR = '/var/www/.well-known/yunomonitor/'
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
CONFIG_DIR = "/etc/yunomonitor"
MONITORING_CONFIG_FILE = os.path.join(CONFIG_DIR, "/%s.yml")
CACHE_MONITORING_CONFIG_FILE = os.path.join(CONFIG_DIR, "/%s.cache.yml")
FAILURES_FILE = os.path.join(CONFIG_DIR, "/%s.failures.yml")

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

# Find the current host
ip = {'v4': True, 'v6': True}
monitoring_servers = set()

# =============================================================================

# =============================================================================
# CORE FUNCTIONS
# =============================================================================


def display_help(error=0):
    print('yunomonitor.py [YUNODOMAIN ...] [-m MAIL ...] [-s SMS_API ...] [-c CACHET_API ...]')
    print('YunoMonitor is a one file script to monitor a server and send mail,')
    print('sms or fill a cachet status page.')
    sys.exit(error)


def main(argv):
    
    # Parse arguments
    try:
        opts, monitored_servers = getopt.getopt(argv, "hm:s:c:e:", ["mail=", "sms=", "cachet=", "encrypt-for="])
    except getopt.GetoptError:
        display_help(2)

    mails = set()
    sms_apis = set()
    cachet_apis = set()
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
    ip['v4'] = not check_ping("wikipedia.org", ['v4'])
    ip['v6'] = socket.has_ipv6 and not check_ping("wikipedia.org", ['v6'])
    if not ip['v4'] and not ip['v6']:
        logging.debug('No connexion')
        if 'localhost' not in monitored_servers:
            sys.exit(2)
        logging.debug('only local test will run')
        monitored_servers = ['localhost']

    # Load or download monitoring description of each server, convert
    # monitoring instructions, execute it
    threads = [ServerMonitor(server) for server in monitored_servers]
    for thread in threads:
        thread.start()
   
    # Wait for all thread
    for thread in threads:
        thread.join()

    # Filter by reccurence and trigger some actions
    trigger_actions(ServerMonitor.failures_report, ServerMonitor.ynh_maps,
                    mails, sms_apis, cachet_apis)


class ServerMonitor(Thread):
    """Thread to monitor one server."""
    ynh_maps = {}
    failures_report = {}

    def __init__(self, server):
        Thread.__init__(self)
        self.server = server
        self.failures = {}

    def run(self):
        self.ynh_maps[self.server] = self._load_monitoring_config()
        self._monitor()
        self._save()
        

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
                for mserver in monitoring_servers:
                    with open(PUBLISHED_MONITORING_CONFIG_FILE % get_id_host(mserver), 'wb') as publish_config_file:
                        publish_config_file.write(encrypt(config, mserver))
            
            # If the server to monitor is on remote, we try to download the 
            # configuration
            else:
                config_url = REMOTE_MONITORING_CONFIG_FILE % (self.server, get_id_host())
                try:
                    r = requests.get(config_url, timeout=15)
                except Exception as e:
                    pass
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
            del to_monitor['ping']
            del to_monitor['https_200']
            del to_monitor['dns_resolver']
            del to_monitor['smtp']
            del to_monitor['imap']
            del to_monitor['xmpp']
            del to_monitor['no_blacklist']
        else:
            del to_monitor['dns_resolution']
            del to_monitor['service_up']
            del to_monitor['backuped']
            del to_monitor['disk_health']
            del to_monitor['free_space']

        # Download remove failures report
        if self.server != 'localhost':
            # Load internal failures
            url = REMOTE_FAILURES_FILE % (self.server, get_id_host())
            try:
                r = requests.get(url, timeout=15)
            except Exception as e:
                logging.debug('No failures files', str(e))
            
            if r is not None or r.status_code == 200:
                self.failures = json.load(decrypt(r.content))

        # Check things to monitor
        for category, checks in to_monitor.items():
            if category not in self.failures:
                self.failures[category] = []
            for args in checks:
                reports = globals()["check_%s" % (category)](*args)
                for report in reports:
                    if isinstance(report, basestring):
                        self.failures[category].append((args[0], report, {}))
                    elif len(report) == 1:
                        self.failures[category].append((args[0],) + report + ({},))
                    else:
                        self.failures[category].append((args[0],) + report)


    def _save(self):
        failures_file = FAILURES_FILE % (self.server)
        if os.path.exists(failures_file):
            existing_failures = json.loads(open(failures_file).read())
        else:
            existing_failures = {}

        updated_failures = {k: {} for k in self.failures.keys()}

        for category, reports in self.failures.items():
            for target, error, data in reports:
                existing_failure = existing_failures.get(category, {}).get(target, {})
                count = existing_failure.get("count", 0) + 1
                messages = existing_failure.get("errors", [])
                messages = set(messages)
                messages.add((error, data))
                updated_failures[category][target] = {
                    "count": count,
                    "errors": list(messages)
                }

        with open(failures_file, "w") as f:
            json.dump(updated_failures, f)

        # Publish failures
        for mserver in monitoring_servers:
            with open(PUBLISHED_FAILURES_FILE % get_id_host(mserver), "wb") as f:
                f.write(encrypt(json.dumps(updated_failures), mserver))

        self.failures_report[self.server] = updated_failures

def get_id_host(server=None):
    if not server:
        filename = '/etc/ssh/ssh_host_rsa_key.pub'
    else:
        filename = '/etc/yunomonitor/%s.pub' % server
    block_size = 65536
    sha256 = hashlib.sha256()
    with open(filename, 'rb') as f:
        for block in iter(lambda: f.read(block_size), b''):
            sha256.update(block)
    return sha256.hexdigest()

def encrypt(message, mserver):
    cache_key = '/etc/yunomonitor/%s.pub' % mserver
    if os.path.exists(cache_key):
        with open('/etc/yunomonitor/%s.pub' % mserver) as f:
            key = RSA.importKey(f.read())
    else:
        try:
            r = requests.get(PUBLIC_KEY_URI % mserver, timeout=15)
        except Exception as e:
            return None
        if r is None or r.status_code != 200:
            return None
        
        key = r.text
        with open('/etc/yunomonitor/%s.pub' % mserver, 'w') as f:
            f.write(r.text)

    key = RSA.importKey(key)
    cipher = Cipher_PKCS1_v1_5.new(key)
    return cipher.encrypt(message.encode())

def decrypt(cipher_message):
    with open('/etc/ssh/ssh_host_rsa_key') as f:
        key = RSA.importKey(f.read())
    cipher = Cipher_PKCS1_v1_5.new(key)
    return cipher.decrypt(cipher_message, None).decode()


def generate_monitoring_config():
    https_200 = set()
    service_up = set()
    backuped = set()
    domains = set()
    is_yunohost = os.path.exists("/etc/yunohost/installed")
    if is_yunohost:
        current_host = open("/etc/yunohost/current_host").read().strip()
        
        domains = glob.glob('/etc/nginx/conf.d/*.*.conf')
        domains = [path[18:-5] for path in domains]
        
        with open('/etc/resolv.dnsmasq.conf', 'r') as resolv_file:
            dns_resolver = [x[11:] for x in resolv_file.readlines()]

        # TODO personalize meta components
        apps = [
            {
                "id": "mail",
                "name": "Mail",
                "label": "Mail",
                "services": ["postfix", "rspamd", "dovecot", "postsrsd", "dnsmasq", "slapd"]
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
                "services": ["nginx", "slapd", "ssh", "yunohost-api", "systemd-logind"]
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
                "services": ["avahi-daemon", "cron", "dbus", "glances", "haveged", 
                             "ntp", "rng-tools", "rsyslog", "syslog", 
                             "systemd-journald", "systemd-udevd"]
            }

        ]

        apps_dir = glob.glob('/etc/yunohost/apps')

        for app_dir in apps_dir:
            with open(os.path.join(app_dir, 'settings.yml'), 'r') as settings_file:
                app_settings = yaml.load(settings_file)
            
            uris = []
            if 'unprotected_uris' in app_settings or 'skipped_uris' in app_settings:
                if 'domain' in app_settings:
                    uri = []
                    uri.append(app_settings['domain'])
                    if 'path' in app_settings:
                        uri.append(app_settings['path'])
                    if 'unprotected_uris' in app_settings:
                        uri.append(app_settings['unprotected_uris'])
                    if 'skipped_uris' in app_settings:
                        uri.append(app_settings['skipped_uris'])
                    uris.append(os.path.join(*uri))

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
                "name": app_settings['name'],
                "label": app_settings['label'],
                "uris": uris,
                "services": app_manifest['services']
            }
            if app_settings['name'] in ["Borg", "Archivist"]:
                if app_settings['name'] == "Archivist" or app_settings['apps'] == 'all':
                    app['backup'] = [x[19:] for x in apps_dir]
                else:
                    app['backup'] = app_settings['apps'].split(',')
                backuped.update([(x, app['id']) for x in app['backup']])
            https_200.update(uris)
            service_up.update(services)
            apps.append(app)
    
    # List all non removable disks
    devices = set()
    for path in glob('/sys/block/*/device/block/*/removable'):
        disk_name = path.split('/')[2]
        with open(path) as f:
            if f.read(1) == '0':
                devices.add(disk_name)

    
    return {
        "ping": set(domains),
        "smtp": set(domains),
        "domain_renewed": set(domains),
        "imap": set(domains),
        "xmpp": set(domains),
        "dns_resolver": set(dns_resolver),
        "dns_resolution": True,
        "disk_health": set(devices),
        "free_space": {"warning": 1500, "danger": 500},
        "https_200": https_200,
        "service_up": service_up,
        "backuped": backuped,
        "__components__": apps,
    }


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

# Remote checks
def check_ping(hostname, proto=['v4', 'v6']):
    cmd = "ping -%s -c 1 -w 500 %s >/dev/null 2>&1"
    errors = []
    for protocol in proto:
        if ip[protocol]:
            if all(os.system(cmd % (protocol[1:], hostname)) != 0 for retry in range(3)):
                errors.append('NO_IPV%d_PING' % protocol[1:])
        elif protocol == 'v6':
            logging.debug('No IPv6 connexion, can\'t check HTTP on IPv6')
    return errors

def check_https_200(url, accept_redirection=False):
    # Return no errors in case the monitoring server has no connexion
    if not ip['v4'] and not ip['v6']:
        logging.debug('No connexion, can\'t check HTTP')
        return []
    
    # Find all ips configured for the domain of the URL
    split_uri = url.split('/')
    domain = split_uri[0]
    path = '/' + '/'.join(split_uri[1:]) if len(split_uri) > 1 else '/'
    try:
        addrs = socket.getaddrinfo(domain, 443)
    except socket.gaierror:
        return ['DOMAIN_UNCONFIGURED']
    addrs = {
        'v4': {addr[4][0] for addr in addrs if addr[0] == socket.AF_INET},
        'v6': {addr[4][0] for addr in addrs if addr[0] == socket.AF_INET6}
    }
    
    if not ip['v4'] and not addrs['v6']:
        logging.debug('No connexion, can\'t check HTTP')
        return []
    
    # Error if no ip v4 address match with the domain
    errors = []
    if not addrs['v4']:
        errors.append('DOMAIN_MISCONFIGURED_IN_IPV4')
    
    for protocol in ip.keys():
        if ip[protocol] and addrs[protocol]:

            # Try to do the request for each ips
            for addr in addrs[protocol]:
                try:
                    r = requests.get("https://" + addr + path, 
                                     headers={'Host': domain}, 
                                     timeout=HTTP_TIMEOUT)
                except requests.exceptions.SSLError as e:
                    errors.append(('CERTIFICATE_VERIFY_FAILED', {'msg': str(e)}))
                except (requests.exceptions.ConnectionError,
                        requests.exceptions.ConnectionTimeout) as e:
                    errors.append(('PORT_CLOSED_OR_SERVICE_DOWN', {'ip': addr, 'msg': str(e)}))
                except (requests.exceptions.Timeout,
                        requests.exceptions.ReadTimeout) as e:
                    errors.append(('TIMEOUT', {'ip': addr, 'msg': str(e)}))
                except requests.exceptions.TooManyRedirects as e:
                    errors.append(('TOO_MANY_REDIRECTS', {'ip': addr, 'msg': str(e)}))
                except Exception as e:
                    errors.append(('UNKNOWN_ERROR', {'ip': addr, 'msg': str(e)}))
                else:
                    if r.status_code != 200 and \
                       (not accept_redirection or str(r.status_code)[:1] != '3'):
                        errors.append(('HTTP_%d' % r.status_code, {'msg': addr}))
        
        elif protocol == 'v6' and addrs[protocol]:
            logging.debug('No IPv6 connexion, can\'t check HTTP on IPv6')

    return errors
#HTTP>LABEL

def check_domain_renewed(hostname, port=443):
    context = ssl.create_default_context()

    with socket.create_connection((hostname, port)) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            data = ssock.getpeercert()
            notAfter = datetime.strptime(data['notAfter'], '%b %d %H:%M:%S %Y %Z')
            expire_in = notAfter - datetime.now()
            if expire_in < timedelta(14):
                return ['CERT_RENEWED_FAILED', {'remaining_days': expire_in.days}]
    return []
#CERT>LABEL|DOMAIN


def check_dns_resolver(resolver=None, hostname='wikipedia.org', qname='A', expected_results=None):
    if resolver is None:
        my_resolver = dns.resolver
    elif (not ip['v4'] and '.' in resolver) or \
         (not ip['v6'] and ':' in resolver):
        logging.debug('No connexion in this protocol to test the resolver')
        return []
    else:
        my_resolver = dns.resolver.Resolver()
        my_resolver.nameservers = [resolver]
    
    try:
        answers = my_resolver.query(hostname)
    except dns.exception.NoNameservers as e:
        return [('BROKEN_NAMESERVER', {'msg': str(e)})]
    except dns.exception.Timeout as e:
        return [('TIMEOUT', {'msg': str(e)})]
    except dns.exception.NXDOMAIN as e:
        return [('DOMAIN_UNCONFIGURED', {'msg': str(e)})]
    except dns.exception.NoAnswer as e:
        return [('NO_ANSWER', {'msg': str(e)})]
    if expected_results is not None:
        answers = [answer.to_text() for answer in answers]
        if set(answers) ^ set(expected_results):
            return [('UNEXPECTED_ANSWER', {'get': set(answers), 'expected': set(expected_results)})]
    return []
#DNS RESOLVER

def check_smtp(hostname, ports=[25, 587], blacklist=True):
    # TODO check spf
    # TODO check dkim
    # Return no errors in case the monitoring server has no connexion
    if not ip['v4'] and not ip['v6']:
        logging.debug('No connexion, can\'t check HTTP')
        return []
    
    errors = []

    # Do check for all ips of all MX
    mx_domains = {mx.preference: mx.exchange.to_text(True) 
                  for mx in dns.resolver.query(hostname, 'MX')}
    mx_domains = [mx_domains[key] for key in sorted(mx_domains)]
    
    if not mx_domains:
        errors.append('NO_MX_RECORD')
        # If no MX consider A and AAAA records
        mx_domains = [hostname]

    for mx_domain in mx_domains:
        try:
            addrs = socket.getaddrinfo(mx_domain, None)
        except socket.gaierror:
            errors.append(('DOMAIN_UNCONFIGURED', {'mx': mx_domain}))

        mx_ips = {addr[4][0] for addr in addrs if addr[0] == socket.AF_INET}
        mx_ips |= {addr[4][0] for addr in addrs if addr[0] == socket.AF_INET6}
        
        for mx_ip in mx_ips:
            # Check Reverse DNS
            try:
                name, _, _ = socket.gethostbyaddr(mx_ip)
            except socket.herror as e:
                errors.append(('REVERSE_MISSING', {'ip': mx_ip, 'mx': mx_domain}))
            else:
                if name != mx_domain:
                    errors.append(('REVERSE_MISMATCH', {'ip': mx_ip, 'get': name, 'expected': mx_domain}))
            
            # Check rbl
            if blacklist:
                for bl, description in DEFAULT_BLACKLIST:
                    try:
                        rev = dns.reversename.from_address(mx_ip)
                        query = str(rev.split(3)[0]) + '.' + bl
                        dns.resolver.query(query, "A")
                    except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.resolver.NoAnswer):
                        continue
                    reason_or_link = None
                    try:
                        reason_or_link = dns.resolver.query(query, "TXT")[0]
                    except Exception:
                        pass
                    errors.append(('BLACKLISTED', {'ip': mx_ip, 'rbl': bl, 'rbl_description': description, 'txt': reason_or_link}))

            if not ip['v4'] and '.' in mx_ip:
                logging.debug('No IPv4 connexion, can\'t check SMTP %s' % mx_ip)
                continue
            
            if not ip['v6'] and ':' in mx_ip:
                logging.debug('No IPv6 connexion, can\'t check SMTP %s' % mx_ip)
                continue

            # Check SMTP works
            for port in ports:
                try:
                    server = smtplib.SMTP(mx_ip, port) 
                    server.ehlo()
                    server.starttls()

                    # Check certificate
                    pem = ssl.DER_cert_to_PEM_cert(server.sock.getpeercert(binary_form=True))
                    cert = x509.load_pem_x509_certificate(pem.encode(), default_backend())
                    notAfter = cert.not_valid_after
                    expire_in = notAfter - datetime.now()
                    if expire_in < timedelta(14):
                        errors.append(('CERT_RENEWED_FAILED', {'ip': mx_ip, 'mx': mx_domain}))
                except OSError:
                    return [('PORT_CLOSED_OR_SERVICE_DOWN', {'ip': mx_ip, 'mx': mx_domain})]
                finally:
                    if server:
                        server.quit()

    return errors


def check_imap():
    return []


def check_pop():
    return []


def check_xmpp():
    return []


# Internal checks
def check_dns_resolution():
    return check_dns_resolver(None)
# DNS RESOLUTION


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
        return [('NOT_FOUND')]
    elif properties['SubState'] == 'running':
        return []
    elif properties['SubState'] == 'exited':
        return [('DOWN')]
    else:
        return [('FAILED')]
# SERVICE>LABEL|SERVICE


def check_disk_health(device):
    # TODO short/long test and scsi error
    errors = []
    # Check device smart capabilities
    p = Popen(['smartctl', '-i', "/dev/%s" % device], stdout=PIPE, stderr=PIPE)
    out, err = p.communicate()
    out = out.decode("utf-8").strip()
    if "SMART support is: Available" not in out:
        logging.debug("/dev/%s doesn't support SMART" % device)
        return []

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
        errors.append(('IMMINENT_DISK_FAILURE', {'device': device}))

    return errors
#DISK>DISK_NAME


def check_free_space(warning_limit=1500, error_limit=500, paths=None):
    if not paths:
        paths = ['/', '/home', '/var', '/etc', '/var/log', '/boot', '/usr',
                 '/bin', '/home/yunohost.backup/archives']

    errors = []
    for path in paths:
        total, used, free = shutil.disk_usage("/")
        if free < error_limit * 1024 * 1024:
            errors.append(('CRITICAL_FREE_SPACE', {'path': path, 'total': total, 'free': free}))
        elif free < warning_limit * 1024 * 1024:
            errors.append(('WARN_FREE_SPACE', {'path': path, 'total': total, 'free': free}))
    return errors
#DISK>FREE_SPACE


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
            return [('MISSING_BACKUP', {'last_backup': last_backup,
                                        'theorical_date': theorical_date})]
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
            return [('BACKUP_NOT_TRIGGERED', {'last_backup': last_backup,
                                              'theorical_date': theorical_date})]

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
#BACKUP>LABEL

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
        errors.append(('APP_NEED_UPGRADE', {'number': len(out['apps']), 
                                            'apps': [x['id'] for x in out['apps']]}))
    if len(out['system']) > 0:
        errors.append(('PKG_NEED_UPGRADE', {'number': len(out['system']), 
                                            'packages': [x['id'] for x in out['system']]}))
    return errors
    

# =============================================================================
# ACTIONS PLUGINS
# =============================================================================
# TODO sms_message/cachet_message create custom message

def trigger_actions(failures, ynh_maps, mails, sms_apis, cachet_apis):

    alerts = {}
    for server, failure in failures.items():
        alerts[server] = {}
        for category, targets in failures.items():
            alerts[server][category] = {}
            for target, reports in targets.items():
                alerts[server][category][target] = [r for r in reports.items() if r[1]["count"] % ALERT_FREQUENCY == 0]
    
    if ip['v4'] or ip['v6']:
        mail_alert(alerts, ynh_maps, mails)
        #sms_alert(alerts, ynh_maps, sms_apis)
        #cachet_alert(alerts, ynh_maps, cachet_apis)

    if 'localhost' in alerts:
        service_up(alerts['localhost']['service_up'])

def service_up(alerts):
    # TODO service up
    for service, message in alerts:
        pass

def mail_alert(alerts, ynh_map, mails):
    for server, failures in alerts.items():
        for category, reports in failures.items():
            for target, infos in reports:

                subject = "[monitoring][%s][%s] %s is failing" % (server, category, target)
                body = target + " :\n" + "\n".join(infos["messages"])

                open("/tmp/monitoring-body", "w").write(body)
                os.system("mail -s '%s' %s < /tmp/monitoring-body" % (subject, ' '.join(mails)))

"""
def sms_alert(server, alerts, ynh_maps, sms_apis):
    for server, failures in alerts.items():
        body = ["%s:" % (server)]
        for category, reports in failures.items():
            for target, infos in reports:
                body.append(sms_message(category, target, ynh_maps[server], infos))
                body += target + "%s>\n" + "\n".join(infos["messages"])

    if len(body) > 1:
        body = "\n".join(body)
        for sms_api in sms_apis:
            try:
                requests.get(sms_api % (body), timeout=15)
            except Exception as e:
                logging.debug(sms_api, str(e))


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
