import re 
from typing import Dict, Callable, List

class WhoisParser:
    def __init__(self):
        self.tld_parser_map: Dict[str, Callable[[str], Dict]] = {
            ".uk": self._parse_uk,
            ".co.uk": self._parse_uk,
            ".jp": self._parse_jp,
            ".co.jp": self._parse_jp,
            ".com": self._parse_default,
            ".net": self._parse_default,
            ".org": self._parse_default,
            ".de": self._parse_default,
        }

    def parse(self, domain: str, whois_data: str) -> Dict:
        for tld, parser in self.tld_parser_map.items():
            if domain.lower().endswith(tld):
                return parser(whois_data)
        return self._parse_default(whois_data)

    # === Parser Implementations ===
    def _parse_uk(self, data: str) -> Dict:
        result = {}
        patterns = {
            "domain_name": r"^\s*Domain name:\s*(.+)",
            "registrant": r"^\s*Registrant:\s*(.+)",
            "registrar": r"^\s*Registrant:\s*(.+)",
            "registrant_type": r"^\s*Registrant type:\s*(.+)",
            "registered_on": r"^\s*Registered on:\s*(.+)",
            "creation_date": r"^\s*Registered on:\s*(.+)",
            "expiry_date": r"^\s*Expiry date:\s*(.+)",
            "registry_expiry_date": r"^\s*Expiry date:\s*(.+)",
            "expiration_date": r"^\s*Expiry date:\s*(.+)",
            "last_updated": r"^\s*Last updated:\s*(.+)",
            "updated_date": r"^\s*Last updated:\s*(.+)",
        }
        for key, pattern in patterns.items():
            match = re.search(pattern, data, re.IGNORECASE | re.MULTILINE)
            if match:
                result[key] = match.group(1).strip()

        result['name_servers'] = self._parse_name_servers(data)
        return result

    def _parse_jp(self, data: str) -> Dict:
        result = {}
        patterns = {
            "domain_name": r"a\.\s+\[Domain Name\]\s+(.+)",
            "organization": r"g\.\s+\[Organization\]\s+(.+)",
            "registrar": r"g\.\s+\[Organization\]\s+(.+)",
            "org_type": r"l\.\s+\[Organization Type\]\s+(.+)",
            "admin_contact": r"m\.\s+\[Administrative Contact\]\s+(.+)",
            "tech_contact": r"n\.\s+\[Technical Contact\]\s+(.+)",
            "state": r"\[State\]\s+(.+)",
            "registered_date": r"\[Registered Date\]\s+(.+)",
            "creation_date": r"\[Registered Date\]\s+(.+)",
            "connected_date": r"\[Connected Date\]\s+(.+)",
            "last_update": r"\[Last Update\]\s+(.+)",
            "updated_date": r"\[Last Update\]\s+(.+)",
        }
        for key, pattern in patterns.items():
            match = re.search(pattern, data)
            if match:
                result[key] = match.group(1).strip()

        result['name_servers'] = re.findall(r"p\.\s+\[Name Server\]\s+(.+)", data)
        return result

    def _parse_default(self, data: str) -> Dict:
        result = {}
        patterns = {
            "domain_name": r"Domain Name:\s*(.+)",
            "registrar": r"Registrar:\s*(.+)",
            "creation_date": r"Creation Date:\s*(.+)",
            "updated_date": r"Updated Date:\s*(.+)",
            "expiry_date": r"(?:Registry )?Expiry Date:\s*(.+)",
            "registry_expiry_date": r"(?:Registry )?Expiry Date:\s*(.+)",
        }
        for key, pattern in patterns.items():
            match = re.search(pattern, data, re.IGNORECASE)
            if match:
                result[key] = match.group(1).strip()

        result['name_servers'] = re.findall(r"Name Server:\s*(.+)", data, re.IGNORECASE)
        return result

    def _parse_name_servers(self, data: str) -> List[str]:
        return re.findall(r"^\s*(?:Name Server|Name servers?):\s*(.+)", data, flags=re.IGNORECASE | re.MULTILINE)
