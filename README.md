
# python3-whois
A python3 implementation of the Linux whois command line utility, this python implementation makes it easy to use the Linux whois command line utility as python module.

```sh
$ whois google.com
```
In this module you would to something like
```py
from whois3 import Whois
m = Whois()
r = m.whois("google.com")

{'domain_name': 'GOOGLE.COM',
 'status': ['clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited',
  'clientTransferProhibited https://icann.org/epp#clientTransferProhibited',
  'clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited',
  'serverDeleteProhibited https://icann.org/epp#serverDeleteProhibited',
  'serverTransferProhibited https://icann.org/epp#serverTransferProhibited',
  'serverUpdateProhibited https://icann.org/epp#serverUpdateProhibited',
  'clientUpdateProhibited (https://www.icann.org/epp#clientUpdateProhibited)',
  'clientTransferProhibited (https://www.icann.org/epp#clientTransferProhibited)',
  'clientDeleteProhibited (https://www.icann.org/epp#clientDeleteProhibited)',
  'serverUpdateProhibited (https://www.icann.org/epp#serverUpdateProhibited)',
  'serverTransferProhibited (https://www.icann.org/epp#serverTransferProhibited)',
  'serverDeleteProhibited (https://www.icann.org/epp#serverDeleteProhibited)'],
 'nameservers': ['ns4.google.com',
  'ns3.google.com',
  'ns1.google.com',
  'ns2.google.com'],
 'registry_domain_id': '2138514_DOMAIN_COM-VRSN',
 'registrar_whois_server': 'whois.markmonitor.com',
 'registrar_url': 'http://www.markmonitor.com',
 'updated_date': '2019-09-09T15:39:04Z',
 'creation_date': ': 1997-09-15T04:00:00Z',
 'registry_expiry_date': '2028-09-14T04:00:00Z',
 'registrar': 'MarkMonitor Inc.',
 'registrar_iana_id': '292',
 'registrar_abuse_contact_email': 'abusecomplaints@markmonitor.com',
 'registrar_abuse_contact_phone': '+1.2086851750',
 'domain_dnssec': 'unsigned',
 'registrant_organization': 'Google LLC',
 'registrant_state': 'CA',
 'registrant_country': 'US',
 'registrant_email': 'Select Request Email Form at https://domains.markmonitor.com/whois/google.com',
 'admin_organization': 'Google LLC',
 'admin_state_province': 'CA',
 'admin_country': 'US',
 'admin_email': 'Select Request Email Form at https://domains.markmonitor.com/whois/google.com',
 'tech_organization': 'Google LLC',
 'tech_state_province': 'CA',
 'tech_country': 'US',
 'tech_email': 'Select Request Email Form at https://domains.markmonitor.com/whois/google.com'}
```
The results returned are json
