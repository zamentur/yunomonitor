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

import unittest
import mock
from requests.exceptions import TooManyRedirects
from yunomonitor import IP, detect_internet_protocol, _reset_cache, _get_devices
from yunomonitor import encrypt, decrypt, get_id_host
from yunomonitor import mail_alert, sms_alert
from yunomonitor import ServerMonitor
from yunomonitor import generate_monitoring_config, check_ping, check_https_200, \
                        check_tls, check_dns_resolver, check_smtp, check_ip_address, \
                        check_imap, check_pop, check_xmpp, check_dns_resolution, \
                        check_service_up, check_disk_health, check_free_space, \
                        check_backuped, check_ynh_upgrade, check_domain_renewal, \
                        check_blacklisted
ipvx = True
SKIP_NO_CONNEXION_MESSAGE = 'No connexion, skip this test'


class TestCheck(unittest.TestCase):

    def setUp(self):
        global ipvx
        IP.v4 = True
        IP.v6 = True
        _reset_cache()
        detect_internet_protocol()
        ipvx = IP.v4 or IP.v6

class TestEncryption(TestCheck):
    def test_encrypt_decrypt(self):
        from shutil import copyfile

        copyfile('/etc/ssh/ssh_host_rsa_key.pub', '/etc/yunomonitor/ynh.local.pub')
        cipher_message = encrypt('trololo', 'ynh.local')
        self.assertNotEqual(cipher_message, 'trololo')
        message = decrypt(cipher_message)
        self.assertEqual(message, 'trololo')
    
    def test_get_id_host(self):
        self.assertEqual(get_id_host(), get_id_host('ynh.local'))

class TestGenerateMonitoringConfig(TestCheck):
    def test_ok(self):
        print(generate_monitoring_config())

class TestMailAlert(TestCheck):
    @mock.patch('yunomonitor.os')
    def test_ok(self, mock_os):
        alerts = {
            'ynh.local': {
                'NO_PING': [{
                    'level': 'critical',
                    'count': 3,
                    'target': {'domain': 'ynh.local'},
                    'extra': {}
                }],
                'PORT_CLOSED_OR_SERVICE_DOWN': [{
                    'level': 'critical',
                    'count': 3,
                    'target': {'domain': 'ynh.local', 'port': 443},
                    'extra': {}
                }]
            }
        }
        mails = ['root@ynh.local']
        calls = []
        def register(cmd):
            calls.append(cmd)
        mock_os.system.side_effect = register
        mail_alert(alerts, mails)
        self.assertEqual(set(calls), set([
            "mail -s '[critical][ynh.local] NO_PING: ynh.local' root@ynh.local < /tmp/monitoring-body",
            "mail -s '[critical][ynh.local] PORT_CLOSED_OR_SERVICE_DOWN: 443, ynh.local' root@ynh.local < /tmp/monitoring-body"
        ]))

class TestSMSAlert(TestCheck):
    def test_ok(self):
        alerts = {
            'ynh.local': {
                'NO_PING': [{
                    'level': 'critical',
                    'count': 3,
                    'target': {'domain': 'ynh.local'},
                    'extra': {}
                }],
                'PORT_CLOSED_OR_SERVICE_DOWN': [{
                    'level': 'critical',
                    'count': 3,
                    'target': {'domain': 'ynh.local', 'port': 443},
                    'extra': {}
                }]
            },
            'ynh2.local': {
                'NO_PING': [{
                    'level': 'critical',
                    'count': 3,
                    'target': {'domain': 'ynh.local'},
                    'extra': {}
                }],
                'PORT_CLOSED_OR_SERVICE_DOWN': [{
                    'level': 'critical',
                    'count': 3,
                    'target': {'domain': 'ynh.local', 'port': 443},
                    'extra': {}
                }]
            }
        }
        sms = ["https://smsapi.free-mobile.fr/sendmsg?user=10638778&pass=cWzyR3moNjsD0K&msg=%s"]
        sms_alert(alerts, sms)


class TestCheckPing(unittest.TestCase):
    @mock.patch('yunomonitor.os')
    def test_no_connexion(self, mock_os):
        mock_os.system.return_value = 2
        errors = check_ping('wikipedia.org')
        self.assertEqual(errors, [('NO_PING', {'domain': 'wikipedia.org'})])
        
    @mock.patch('yunomonitor.os')
    def test_full_connexion(self, mock_os):
        mock_os.system.return_value = 0
        errors = check_ping('wikipedia.org')
        self.assertEqual(errors, [])
        
    @mock.patch('yunomonitor.os')
    def test_only_ipv4(self, mock_os):
        def only_ipv4(cmd):
            return 0 if '-4' in cmd else 2
        mock_os.system.side_effect = only_ipv4
        errors = check_ping('wikipedia.org')
        self.assertEqual(errors, [('NO_IPV6_PING', {'domain': 'wikipedia.org'})])
        
    @mock.patch('yunomonitor.os')
    def test_only_ipv6(self, mock_os):
        def only_ipv6(cmd):
            return 0 if '-6' in cmd else 2
        mock_os.system.side_effect = only_ipv6
        errors = check_ping('wikipedia.org')
        self.assertEqual(errors, [('NO_IPV4_PING', {'domain': 'wikipedia.org'})])
        
    @mock.patch('yunomonitor.os')
    def test_packet_loss(self, mock_os):
        mock_os.system.side_effect = [2, 2, 0, 2, 0, 0]
        errors = check_ping('wikipedia.org')
        self.assertEqual(errors, [])


class TestCheckIPAddress(TestCheck):
    def test_no_connexion(self):
        IP.v4 = False
        IP.v6 = False
        errors = check_ip_address('wikipedia.org')
        self.assertEqual(errors, [])
    
    @unittest.skipIf(not ipvx, SKIP_NO_CONNEXION_MESSAGE)
    def test_domain_unconfigured(self):
        errors = check_ip_address('nodomain.local')
        self.assertEqual(errors, [('DOMAIN_UNCONFIGURED', {'domain': 'nodomain.local'})])

    @unittest.skipIf(not ipvx, SKIP_NO_CONNEXION_MESSAGE)
    def test_ip4only_no_ipv6(self):
        IP.v4 = True
        IP.v6 = False
        errors = check_ip_address('ip.yunohost.org')
        self.assertEqual(errors, [])

    @unittest.skipIf(not ipvx, SKIP_NO_CONNEXION_MESSAGE)
    def test_domain_misconfigured_in_ipv4(self):
        IP.v4 = True
        IP.v6 = False
        errors = check_ip_address('ipv6.yunohost.org')
        self.assertEqual(errors, [('DOMAIN_MISCONFIGURED_IN_IPV4', {'domain': 'ipv6.yunohost.org'})])


class TestCheckTLS(TestCheck):
    @unittest.skipIf(not ipvx, SKIP_NO_CONNEXION_MESSAGE)
    def test_certificate_verify_failed(self):
        errors = check_tls('expired.badssl.com')
        self.assertEqual(errors[0][0], 'CERT_INVALID')

        errors = check_tls('wrong.host.badssl.com')
        self.assertEqual(errors[0][0], 'CERT_INVALID')

        errors = check_tls('self-signed.badssl.com')
        self.assertEqual(errors[0][0], 'CERT_INVALID')
    
    @unittest.skipIf(not ipvx, SKIP_NO_CONNEXION_MESSAGE)
    def test_port_closed_or_service_down(self):
        errors = check_tls('smtp.gmail.com')
        self.assertEqual(errors[0][0], 'PORT_CLOSED_OR_SERVICE_DOWN')


class TestCheckHTTPS_200(TestCheck):
    @unittest.skipIf(not ipvx, SKIP_NO_CONNEXION_MESSAGE)
    def test_timeout(self):
        errors = check_https_200('httpstat.us/200?sleep=16000')
        self.assertEqual(errors[0][0], 'TIMEOUT')
    
    @unittest.skipIf(not ipvx, SKIP_NO_CONNEXION_MESSAGE)
    @mock.patch('yunomonitor.MySSLContext')
    def test_too_many_redirects(self, mock_MySSLContext):
        def error(domain):
            raise TooManyRedirects()
        mock_MySSLContext.side_effect = error

        errors = check_https_200('yunohost.org')
        self.assertEqual(errors[0][0], 'TOO_MANY_REDIRECTS')
    
    @unittest.skipIf(not ipvx, SKIP_NO_CONNEXION_MESSAGE)
    def test_http_status(self):
        errors = check_https_200('httpstat.us/500')
        self.assertEqual(errors[0][0], 'HTTP_500')
        
        errors = check_https_200('httpstat.us/403')
        self.assertEqual(errors[0][0], 'HTTP_403')
        
        errors = check_https_200('httpstat.us/301')
        self.assertEqual(errors, [])
        
    @unittest.skipIf(not ipvx, SKIP_NO_CONNEXION_MESSAGE)
    def test_sso_capture(self):
        errors = check_https_200('reflexlibre.net/yunohost/sso_capture')
        self.assertEqual(errors[0][0], 'SSO_CAPTURE')
    
    @unittest.skipIf(not ipvx, SKIP_NO_CONNEXION_MESSAGE)
    @mock.patch('yunomonitor.MySSLContext')
    def test_multiple_A_AAAA(self, mock_MySSLContext):
        def error(domain):
            raise TooManyRedirects()
        mock_MySSLContext.side_effect = error

        errors = check_https_200('osm.org')
        self.assertEqual(len(errors), 1)
        
        def various_errors(domain):
            various_errors.count += 1
            if various_errors.count < 3:
                raise TooManyRedirects()
            else:
                raise Exception()
        various_errors.count = 0
        mock_MySSLContext.side_effect = various_errors
        errors = check_https_200('osm.org')
        self.assertEqual(len(errors), 3)


class TestCheckDomainRenewal(TestCheck):
    @unittest.skipIf(not ipvx, SKIP_NO_CONNEXION_MESSAGE)
    def test_ok(self):
        errors = check_domain_renewal('netlib.re')
        self.assertEqual(len(errors), 0)
    
    @unittest.skipIf(not ipvx, SKIP_NO_CONNEXION_MESSAGE)
    def test_not_found(self):
        errors = check_domain_renewal('projetvert.eu')
        self.assertEqual(errors[0][0], 'DOMAIN_EXPIRATION_NOT_FOUND')
    
    @mock.patch('yunomonitor._get_domain_expiration')
    @unittest.skipIf(not ipvx, SKIP_NO_CONNEXION_MESSAGE)
    def test_expire(self, mock_expire):
        import datetime
        
        def expire(domain):
            if domain == 'expire.local':
                return datetime.datetime.now()
            elif domain == 'expiresoon.local':
                return datetime.datetime.now() + datetime.timedelta(days=5)
            elif domain == 'willexpire.local':
                return datetime.datetime.now() + datetime.timedelta(days=20)
        mock_expire.side_effect = expire
        errors = check_domain_renewal('expire.local')
        self.assertEqual(errors[0][0], 'DOMAIN_EXPIRE')

        errors = check_domain_renewal('expiresoon.local')
        self.assertEqual(errors[0][0], 'DOMAIN_NEARLY_EXPIRE')

        errors = check_domain_renewal('willexpire.local')
        self.assertEqual(errors[0][0], 'DOMAIN_WILL_EXPIRE')


class TestCheckDNSResolver(TestCheck):
    @unittest.skipIf(not ipvx, SKIP_NO_CONNEXION_MESSAGE)
    def test_ok(self):
        errors = check_dns_resolver('89.234.141.66')
        self.assertEqual(len(errors), 0)

        errors = check_dns_resolver('89.234.141.66', 'arn-fai.net', 'A', ['89.234.141.68'])
        self.assertEqual(len(errors), 0)

    @unittest.skipIf(not ipvx, SKIP_NO_CONNEXION_MESSAGE)
    def test_timeout(self):
        errors = check_dns_resolver('192.168.55.12')
        self.assertEqual(errors[0][0], 'TIMEOUT')

    @unittest.skipIf(not ipvx, SKIP_NO_CONNEXION_MESSAGE)
    def test_unconfigured(self):
        errors = check_dns_resolver('89.234.141.66', 'domainthatnotexists7895322.fr')
        self.assertEqual(errors[0][0], 'DOMAIN_UNCONFIGURED')

    @unittest.skipIf(not ipvx, SKIP_NO_CONNEXION_MESSAGE)
    def test_noanswer(self):
        errors = check_dns_resolver('89.234.141.66', 'ip.yunohost.org', 'AAAA')
        self.assertEqual(errors[0][0], 'NO_ANSWER')

    @unittest.skipIf(not ipvx, SKIP_NO_CONNEXION_MESSAGE)
    def test_resolution(self):
        errors = check_dns_resolution()
        self.assertEqual(errors, [])


class TestCheckSMTP(TestCheck):
    @unittest.skipIf(not ipvx, SKIP_NO_CONNEXION_MESSAGE)
    def test_ok(self):
        errors = check_smtp('reflexlibre.net')
        self.assertEqual(errors, [])
    
    @unittest.skipIf(not ipvx, SKIP_NO_CONNEXION_MESSAGE)
    def test_blacklisted(self):
        errors = check_blacklisted('195.154.59.133', 'fake.local')
        self.assertEqual(errors[0][0], 'BLACKLISTED')
    
    @unittest.skipIf(not ipvx, SKIP_NO_CONNEXION_MESSAGE)
    def test_nok(self):
        errors = check_smtp('hackstub.netlib.re')
        self.assertEqual(len(errors), 3)

class TestCheckServiceUp(TestCheck):
    def test_ok(self):
        errors = check_service_up('nginx')
        self.assertEqual(errors, [])
    
    def test_down(self):
        errors = check_service_up('fake-hwclock')
        self.assertEqual(errors[0][0], 'DOWN')
    
    def test_failed(self):
        errors = check_service_up('apache2')
        self.assertEqual(errors[0][0], 'FAILED')
    
    def test_not_found(self):
        errors = check_service_up('trololo')
        self.assertEqual(errors[0][0], 'NOT_FOUND')


class TestCheckDiskHealth(TestCheck):
    def test_not_supported(self):
        devices = _get_devices()
        errors = check_disk_health(devices[0])
        self.assertEqual(errors[0][0], 'SMART_NOT_SUPPORTED')

class TestCheckFreeSpace(TestCheck):
    def test_ok(self):
        errors = check_free_space()
        self.assertEqual(errors, [])

    @mock.patch('yunomonitor.shutil')
    def test_alert(self, mock_shutil):
        MB = 1024 * 1024
        mock_shutil.disk_usage.side_effect = [
            (5000 * MB, (5000 - free) * MB, free * MB)
            for free in [1400, 300, 100, 0]
        ]
        errors = check_free_space(paths=['/'])
        self.assertEqual(errors[0][0], 'W_FREE_SPACE')

        errors = check_free_space(paths=['/'])
        self.assertEqual(errors[0][0], 'E_FREE_SPACE')

        errors = check_free_space(paths=['/'])
        self.assertEqual(errors[0][0], 'C_FREE_SPACE')

        errors = check_free_space(paths=['/'])
        self.assertEqual(errors[0][0], 'NO_FREE_SPACE')


class TestCheckYNHUpgrade(TestCheck):
    def test_ok(self):
        errors = check_ynh_upgrade()
        self.assertNotEqual(errors, [])


if __name__ == '__main__':
    unittest.main()
