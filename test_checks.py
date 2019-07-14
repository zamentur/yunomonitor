#!/usr/bin/python3
import unittest
from yunomonitor import IP, detect_internet_protocol
from yunomonitor import generate_monitoring_config, check_ping, check_https_200, \
                        check_domain_renewal, check_dns_resolver, check_smtp, \
                        check_imap, check_pop, check_xmpp, check_dns_resolution, \
                        check_service_up, check_disk_health, check_free_space, \
                        check_backuped, check_ynh_upgrade
ipvx = True
SKIP_NO_CONNEXION_MESSAGE = 'No connexion, skip this test'


class TestCheck(unittest.TestCase):

    def setUp(self):
        global ipvx
        IP.v4 = True
        IP.v6 = True
        detect_internet_protocol()
        ipvx = IP.v4 or IP.v6


class TestCheckPing(TestCheck):
    def test_check_ping(self):
        errors = check_ping('wikipedia.org')
        if not IP.v4 and not IP.v6:
            self.assertEqual(errors, ['NO_IPV4_PING', 'NO_IPV6_PING'])
        elif IP.v4 and not IP.v6:
            self.assertEqual(errors, ['NO_IPV6_PING'])
        elif not IP.v4 and IP.v6:
            self.assertEqual(errors, ['NO_IPV4_PING'])
        else:
            self.assertEqual(errors, [])


class TestCheckHttps200(TestCheck):
    def test_check_https_200_no_connexion(self):
        IP.v4 = False
        IP.v6 = False
        errors = check_https_200('wikipedia.org')
        print(errors)
        self.assertEqual(errors, [])
    
    @unittest.skipIf(not ipvx, SKIP_NO_CONNEXION_MESSAGE)
    def test_check_https_200_domain_unconfigured(self):
        errors = check_https_200('nodomain.local')
        self.assertEqual(errors, ['DOMAIN_UNCONFIGURED'])

    @unittest.skipIf(not ipvx, SKIP_NO_CONNEXION_MESSAGE)
    def test_check_https_200_ip4only_no_ipv6(self):
        IP.v4 = True
        IP.v6 = False
        errors = check_https_200('ip.yunohost.org')
        self.assertEqual(errors, [])

    @unittest.skipIf(not ipvx, SKIP_NO_CONNEXION_MESSAGE)
    def test_check_https_200_domain_misconfigured_in_ipv4(self):
        IP.v4 = True
        IP.v6 = False
        errors = check_https_200('ipv6.yunohost.org')
        self.assertEqual(errors, ['DOMAIN_MISCONFIGURED_IN_IPV4'])
    
    @unittest.skipIf(not ipvx, SKIP_NO_CONNEXION_MESSAGE)
    def test_check_https_200_certificate_verify_failed(self):
        errors = check_https_200('expired.badssl.com')
        self.assertEqual(errors[0][0], 'CERTIFICATE_VERIFY_FAILED')

        errors = check_https_200('wrong.host.badssl.com')
        self.assertEqual(errors[0][0], 'CERTIFICATE_VERIFY_FAILED')

        errors = check_https_200('self-signed.badssl.com')
        self.assertEqual(errors[0][0], 'CERTIFICATE_VERIFY_FAILED')
    
    @unittest.skipIf(not ipvx, SKIP_NO_CONNEXION_MESSAGE)
    def test_check_https_200_port_closed_or_service_down(self):
        errors = check_https_200('smtp.gmail.com')
        self.assertEqual(errors[0][0], 'PORT_CLOSED_OR_SERVICE_DOWN')
    
    @unittest.skipIf(not ipvx, SKIP_NO_CONNEXION_MESSAGE)
    def test_check_https_200_timeout(self):
        errors = check_https_200('smtp.gmail.com')
        self.assertEqual(errors[0][0], 'TIMEOUT')
    
    @unittest.skipIf(not ipvx, SKIP_NO_CONNEXION_MESSAGE)
    def test_check_https_200_too_many_redirects(self):
        errors = check_https_200('smtp.gmail.com')
        self.assertEqual(errors[0][0], 'TOO_MANY_REDIRECTS')
    
    @unittest.skipIf(not ipvx, SKIP_NO_CONNEXION_MESSAGE)
    def test_check_https_200_http_status(self):
        errors = check_https_200('httpstat.us/500')
        self.assertEqual(errors[0][0], 'HTTP_500')
        
        errors = check_https_200('httpstat.us/403')
        self.assertEqual(errors[0][0], 'HTTP_403')
        
        errors = check_https_200('httpstat.us/301')
        self.assertEqual(errors, [])
        
    @unittest.skipIf(not ipvx, SKIP_NO_CONNEXION_MESSAGE)
    def test_check_https_200_sso_capture(self):
        errors = check_https_200('reflexlibre.net/yunohost/sso_capture')
        self.assertEqual(errors[0][0], 'SSO_CAPTURE')
    
    @unittest.skipIf(not ipvx, SKIP_NO_CONNEXION_MESSAGE)
    def test_check_https_200_multiple_A_AAAA(self):
        errors = check_https_200('fr.pool.ntp.org')
        self.assertEqual(len(errors), 4)


class TestCheckDomainRenewal(TestCheck):
    @unittest.skipIf(not ipvx, SKIP_NO_CONNEXION_MESSAGE)
    def test_cert_ok(self):
        errors = check_domain_renewal('httpstat.us')
        self.assertEqual(len(errors), 0)
    
    @unittest.skipIf(not ipvx, SKIP_NO_CONNEXION_MESSAGE)
    def test_cert_renewal_failed(self):
        errors = check_domain_renewal('expired.badssl.com')
        self.assertEqual(errors[0][0], 'CERT_RENEWAL_FAILED')


if __name__ == '__main__':
    unittest.main()
