import re 

class WhoisRegex(object):
    """Holds regular expression needed for parsing whois response"""
    def __init__(self):
        self.regex = [
            ['Domain Name:[ ]*(?P<domain_name>.+)'],
            ['Registry Domain ID:\s?(?P<registry_domain_id>.+)'],
            ['Registrar WHOIS Server:\s?(?P<registrar_whois_server>.+)'],
            ['Registrar URL:\s?(?P<registrar_url>.+)'],
            ['Updated Date:\s?(?P<updated_date>.+)'],
            ['Creation Date:\s?(?P<creation_date>.+)'],
            ['Registry Expiry Date:\s?(?P<registry_expiry_date>.+)'],
            ['Registrar:\s?(?P<registrar>.+)'],
            ['Registrar IANA ID:\s?(?P<registrar_iana_id>.+)'],
            ['Registrar Abuse Contact Email:\s?(?P<registrar_abuse_contact_email>.+)'],
            ['Registrar Abuse Contact Phone:\s?(?P<registrar_abuse_contact_phone>.+)'],
            ['DNSSEC:\s?(?P<domain_dnssec>.+)'],
            ['DNSSEC DS Data:\s?(?P<domain_dnssec>.+)'],
            ['Registry Registrant ID:\s?(?P<registry_registrant_id>.+)'],
            ['Registrant Name:\s?(?P<registrant_name>.+)'],
            ['Registrant Organization:\s?(?P<registrant_organization>.+)'],
            ['Registrant Street:\s?(?P<registrant_organization>.+)'],
            ['Registrant City:\s?(?P<registrant_city>.+)'],
            ['Registrant State/Province:\s?(?P<registrant_state>.+)'],
            ['Registrant Postal Code:\s?(?P<registrant_postal_code>.+)'],
            ['Registrant Country:\s?(?P<registrant_country>.+)'],
            ['Registrant Phone:\s?(?P<registrant_phone>.+)'],
            ['Registrant Phone Ext:\s?(?P<registrant_phone_ext>.+)'],
            ['Registrant Fax:\s?(?P<registrant_fax>.+)'],
            ['Registrant Email:\s?(?P<registrant_email>.+)'],
            ['Registry Admin ID:\s?(?P<registry_admin_id>.+)'],
            ['Admin Name:\s?(?P<admin_name>.+)'],
            ['Admin Organization:\s?(?P<admin_organization>.+)'],
            ['Admin Street:\s?(?P<admin_street>.+)'],
            ['Admin City:\s?(?P<admin_city>.+)'],
            ['Admin State/Province:\s?(?P<admin_state_province>.+)'],
            ['Admin Postal Code:\s?(?P<admin_postal_code>.+)'],
            ['Admin Country:\s?(?P<admin_country>.+)'],
            ['Admin Phone:\s?(?P<admin_phone>.+)'],
            ['Admin Phone Ext:\s?(?P<admin_phone_ext>.+)'],
            ['Admin Fax:\s?(?P<admin_fax>.+)'],
            ['Admin Fax Ext:\s?(?P<admin_fax_ext>.+)'],
            ['Admin Email:\s?(?P<admin_email>.+)'],
            ['Registry Tech ID:\s?(?P<registry_tech_id>.+)'],
            ['Tech Name:\s?(?P<tech_name>.+)'],
            ['Tech Organization:\s?(?P<tech_organization>.+)'],
            ['Tech Street:\s?(?P<tech_street>.+)'],
            ['Tech City:\s?(?P<tech_city>.+)'],
            ['Tech State/Province:\s?(?P<tech_state_province>.+)'],
            ['Tech Postal Code:\s?(?P<tech_postal_code>.+)'],
            ['Tech Country:\s?(?P<tech_country>.+)'],
            ['Tech Phone:\s?(?P<tech_phone>.+)'],
            ['Tech Phone Ext:\s?(?P<tech_phone_ext>.+)'],
            ['Tech Fax:\s?(?P<tech_fax>.+)'],
            ['Tech Fax Ext:\s?(?P<tech_fax_ext>.+)'],
            ['Tech Email:\s?(?P<tech_email>.+)']
        ]
        
        # This regex return list based results
        self.regex_nameserver  = ['Name Server:\s?(?P<name_servers>.+)'] # Will require using re.findall()
        self.regex_status =  ['Domain Status:\s?(?P<domain_status>.+)']  # Will require using re.findall()
        
        # Extra regex Similar to Creation Date\s?(?P<creation_date>.+)
        self.domain_record_activated = 'Domain record activated\s?(?P<creation_date>.+)'
        self.domain_record_updated = 'Domain record last updated\s?(?P<record_updated>.+)'
        self.domain_record_expired = 'Domain expires\s?(?P<record_expires>.+)'
