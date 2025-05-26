import subprocess
import re
from typing import Optional, List, Dict, Union
from datetime import datetime

class Whois(object):
    def __init__(self, domain: str):
        self.domain = domain.lower().strip()
        self.raw_text = self._run_whois()

    def _run_whois(self) -> str:
        try:
            result = subprocess.run(["whois", self.domain], capture_output=True, text=True, timeout=10)
            return result.stdout
        except Exception as e:
            return str(e)

    def _normalize_date(self, date_str: str) -> Optional[str]:
        date_str = date_str.strip()
        for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%d", "%Y/%m/%d", "%Y-%m-%d %H:%M:%S"):
            try:
                return datetime.strptime(date_str, fmt).isoformat()
            except ValueError:
                continue
        return date_str if date_str else None
    
    def _normalize_registrar(self, registrar: Optional[str]) -> Optional[str]:
        if registrar:
            #return registrar.title().replace(", Inc", ", Inc").replace("Llc", "LLC").replace("Ltd", "Ltd").strip()
            return registrar.replace(", Inc", ", Inc").replace("Llc", "LLC").replace("Ltd", "Ltd").strip()
        return registrar

    def _dedupe_nameservers(self, ns_list: List[str]) -> List[str]:
        seen = set()
        deduped = []
        for ns in ns_list:
            if ns not in seen:
                seen.add(ns)
                deduped.append(ns)
        return deduped
        
    def get_whois(self) -> Dict[str, Union[Optional[str], List[str]]]:
        tld = self.domain.split('.')[-1]
        if self.domain.endswith(".uk"):
            result = self.parse_uk()
        elif self.domain.endswith(".jp"):
            result = self.parse_jp()
        elif self.domain.endswith(".de"):
            result = self.parse_de()
        elif self.domain.endswith(".ru"):
            result = self.parse_ru()
        elif self.domain.endswith(".cn"):
            result = self.parse_cn()
        elif self.domain.endswith(".fr"):
            result = self.parse_fr()
        elif self.domain.endswith(".br"):
            result = self.parse_br()
        elif self.domain.endswith(".it"):
            result = self.parse_it()
        elif self.domain.endswith(".ca"):
            result = self.parse_ca()
        elif self.domain.endswith(".au"):
            result = self.parse_au()
        elif self.domain.endswith(".za"):
            result = self.parse_za()
        elif self.domain.endswith(".gov") or self.domain.endswith(".co") or self.domain.endswith(".io") \
            or self.domain.endswith(".xyz") or self.domain.endswith(".edu") or self.domain.endswith(".org"):
            result = self.parse_generic()
        else:
            result = self.parse_generic()

        if result.get("registrar"):
            result["registrar"] = self._normalize_registrar(result["registrar"])
        if result.get("name_servers"):
            result["name_servers"] = self._dedupe_nameservers(result["name_servers"])

        return result

    def parse_generic(self) -> Dict[str, Union[Optional[str], List[str]]]:
        mappings = {
            "registrar": "registrar",
            "registrar url": "registrar_url",
            "registrar iana id": "registrar_iana_id",
            "whois server": "whois_server",
            "referral url": "referral_url",
            "updated date": "updated_date",
            "last updated on": "updated_date",
            "creation date": "creation_date",
            "created on": "creation_date",
            "registry expiry date": "expiry_date",
            "expiry date": "expiry_date",
            "expiration date": "expiry_date",
        }

        result = {v: None for v in set(mappings.values())}
        result["name_servers"] = []
        updated_dates = []

        for line in self.raw_text.splitlines():
            line = line.strip()
            if not line or ":" not in line:
                continue
            key, val = line.split(":", 1)
            key = key.lower().strip()
            val = val.strip()
            if key in mappings:
                normalized_key = mappings[key]
                if normalized_key == "updated_date":
                    updated_dates.append(val)
                else:
                    result[normalized_key] = self._normalize_date(val) if 'date' in normalized_key else val
            elif key.startswith("name server") or key.startswith("nserver"):
                ns_match = re.search(r"([a-zA-Z0-9.-]+)", val)
                if ns_match:
                    result["name_servers"].append(ns_match.group(1).lower())

        if updated_dates:
            latest = sorted((self._normalize_date(d) for d in updated_dates if d), reverse=True)[0]
            result["updated_date"] = latest

        return result
    
    def _extract_generic_with_date_keys(self, date_keys: List[str]) -> Dict[str, Union[Optional[str], List[str]]]:
        data = self.parse_generic()
        for key in ["creation_date", "expiry_date", "updated_date"]:
            if data.get(key):
                data[key] = self._normalize_date(data[key])
        return data
        
    def _extract_br_fields(self) -> Dict[str, Union[Optional[str], List[str]]]:
        data = {
            "registrar": None,
            "registrar_url": None,
            "creation_date": None,
            "expiry_date": None,
            "updated_date": None,
            "name_servers": [],
            "referral_url": None,
            "whois_server": None,
            "registrar_iana_id": None,
        }
        for line in self.raw_text.splitlines():
            line = line.strip()
            if line.startswith("% Created:"):
                data["creation_date"] = self._normalize_date(line.split(":", 1)[-1].strip())
            elif line.startswith("% Changed:"):
                data["updated_date"] = self._normalize_date(line.split(":", 1)[-1].strip())
            elif line.startswith("% Expires:"):
                data["expiry_date"] = self._normalize_date(line.split(":", 1)[-1].strip())
            elif line.startswith("% nserver:"):
                ns = line.split(":", 1)[-1].strip().lower()
                if ns:
                    data["name_servers"].append(ns.split()[0])
        return data
        
    def parse_br(self):
        return self._extract_br_fields()
    
    def parse_it(self):
        return self._extract_generic_with_date_keys(["created:", "last update:", "expire date:"])

    def parse_ca(self):
        return self._extract_generic_with_date_keys(["Creation Date:", "Expiry Date:", "Updated Date:"])

    def parse_au(self):
        return self._extract_generic_with_date_keys(["Created:", "Expiry:", "Last Modified:"])

    def parse_za(self):
        return self._extract_generic_with_date_keys(["Registered:", "Expiry Date:", "Last Modified:"])
        
    def parse_uk(self) -> Dict[str, Union[Optional[str], List[str]]]:
        data = {
            "registrar": "",
            "registrar_url": None,
            "creation_date": None,
            "expiry_date": None,
            "updated_date": None,
            "name_servers": [],
            "referral_url": None,
            "whois_server": None,
            "registrar_iana_id": None,
        }

        for line in self.raw_text.splitlines():
            line = line.strip()
            if line.startswith("Registrar:"):
                continue
            elif line.lower().startswith("url:"):
                data["registrar_url"] = line.split(":", 1)[-1].strip()
            elif "[tag =" in line.lower():
                data["registrar"] = line.split("[")[0].strip()
            elif line.lower().startswith("registered on:"):
                data["creation_date"] = self._normalize_date(line.split(":", 1)[-1].strip())
            elif line.lower().startswith("expiry date:"):
                data["expiry_date"] = self._normalize_date(line.split(":", 1)[-1].strip())
            elif line.lower().startswith("last updated:"):
                data["updated_date"] = self._normalize_date(line.split(":", 1)[-1].strip())
            elif line.lower().startswith("name servers:"):
                continue
            elif re.match(r"^[a-z0-9.-]+\s*", line, re.IGNORECASE):
                ns_match = re.match(r"^([a-z0-9.-]+)", line, re.IGNORECASE)
                if ns_match:
                    data["name_servers"].append(ns_match.group(1).lower())

        return data

    def parse_jp(self) -> Dict[str, Union[Optional[str], List[str]]]:
        data = {
            "registrar": None,
            "registrar_url": None,
            "creation_date": None,
            "expiry_date": None,
            "updated_date": None,
            "name_servers": [],
            "referral_url": None,
            "whois_server": None,
            "registrar_iana_id": None,
        }

        for line in self.raw_text.splitlines():
            line = line.strip()
            if not line:
                continue
            if line.startswith("g. [Organization]"):
                data["registrar"] = line.replace("g. [Organization]", "").strip()
            elif line.startswith("p. [Name Server]"):
                ns = line.replace("p. [Name Server]", "").strip().lower()
                if ns:
                    data["name_servers"].append(ns)
            elif line.startswith("[Registered Date]"):
                data["creation_date"] = self._normalize_date(line.replace("[Registered Date]", "").strip())
            elif line.startswith("[Last Update]"):
                date_str = line.replace("[Last Update]", "").strip()
                data["updated_date"] = self._normalize_date(re.sub(r"\(.*\)", "", date_str).strip())
            elif line.startswith("[State]") and "Connected" in line:
                match = re.search(r"\((\d{4}/\d{2}/\d{2})\)", line)
                if match:
                    data["expiry_date"] = self._normalize_date(match.group(1))

        return data

    def parse_de(self) -> Dict[str, Union[Optional[str], List[str]]]:
        return self.parse_generic()

    def parse_ru(self) -> Dict[str, Union[Optional[str], List[str]]]:
        data = {
            "registrar": None,
            "registrar_url": None,
            "creation_date": None,
            "expiry_date": None,
            "updated_date": None,
            "name_servers": [],
            "referral_url": None,
            "whois_server": None,
            "registrar_iana_id": None,
        }
        for line in self.raw_text.splitlines():
            line = line.strip()
            if line.startswith("created:"):
                data["creation_date"] = self._normalize_date(line.split(":", 1)[-1].strip())
            elif line.startswith("paid-till:"):
                data["expiry_date"] = self._normalize_date(line.split(":", 1)[-1].strip())
            elif line.startswith("registrar:"):
                data["registrar"] = line.split(":", 1)[-1].strip()
            elif line.startswith("nserver:"):
                ns = line.split(":", 1)[-1].strip().lower()
                if ns:
                    data["name_servers"].append(ns.split()[0])
        return data

    def parse_cn(self) -> Dict[str, Union[Optional[str], List[str]]]:
        data = {
            "registrar": None,
            "registrar_url": None,
            "creation_date": None,
            "expiry_date": None,
            "updated_date": None,
            "name_servers": [],
            "referral_url": None,
            "whois_server": None,
            "registrar_iana_id": None,
        }
        for line in self.raw_text.splitlines():
            line = line.strip()
            if line.startswith("Sponsoring Registrar"):
                data["registrar"] = line.split(":", 1)[-1].strip()
            elif line.startswith("Registration Time"):
                data["creation_date"] = self._normalize_date(line.split(":", 1)[-1].strip())
            elif line.startswith("Expiration Time"):
                data["expiry_date"] = self._normalize_date(line.split(":", 1)[-1].strip())
            elif line.startswith("Name Server"):
                ns = line.split(":", 1)[-1].strip().lower()
                if ns:
                    data["name_servers"].append(ns)
        return data

    def parse_fr(self) -> Dict[str, Union[Optional[str], List[str]]]:
        data = {
            "registrar": None,
            "registrar_url": None,
            "creation_date": None,
            "expiry_date": None,
            "updated_date": None,
            "name_servers": [],
            "referral_url": None,
            "whois_server": None,
            "registrar_iana_id": None,
        }
        for line in self.raw_text.splitlines():
            line = line.strip()
            if line.startswith("registrar:"):
                data["registrar"] = line.split(":", 1)[-1].strip()
            elif line.startswith("created:"):
                data["creation_date"] = self._normalize_date(line.split(":", 1)[-1].strip())
            elif line.startswith("Expiry Date:"):
                data["expiry_date"] = self._normalize_date(line.split(":", 1)[-1].strip())
            elif line.startswith("last-update:"):
                data["updated_date"] = self._normalize_date(line.split(":", 1)[-1].strip())
            elif line.startswith("nserver:"):
                ns = line.split(":", 1)[-1].strip().lower()
                if ns:
                    data["name_servers"].append(ns)
        return data
    
    def parse_generic(self) -> Dict[str, Union[Optional[str], List[str]]]:
        mappings = {
            "domain name": "domain_name",
            "registrar": "registrar",
            "registrar url": "registrar_url",
            "registrar iana id": "registrar_iana_id",
            "whois server": "whois_server",
            "referral url": "referral_url",
            "updated date": "updated_date",
            "last updated on": "updated_date",
            "creation date": "creation_date",
            "created on": "creation_date",
            "registry expiry date": "expiry_date",
            "expiry date": "expiry_date",
            "expiration date": "expiry_date",
        }

        result = {v: None for v in set(mappings.values())}
        result["name_servers"] = []
        updated_dates = []

        for line in self.raw_text.splitlines():
            line = line.strip()
            if not line or ":" not in line:
                continue
            key, val = line.split(":", 1)
            key = key.lower().strip()
            val = val.strip()
            if key in mappings:
                normalized_key = mappings[key]
                if normalized_key == "updated_date":
                    updated_dates.append(val)
                elif normalized_key == "registrar" and result[normalized_key] is None:
                    result[normalized_key] = val
                elif normalized_key != "registrar":
                    result[normalized_key] = self._normalize_date(val) if 'date' in normalized_key else val
            elif key.startswith("name server") or key.startswith("nserver"):
                ns_match = re.search(r"([a-zA-Z0-9.-]+)", val)
                if ns_match:
                    result["name_servers"].append(ns_match.group(1).lower())

        if updated_dates:
            latest = sorted((self._normalize_date(d) for d in updated_dates if d), reverse=True)[0]
            result["updated_date"] = latest

        return result
        
if __name__ == "__main__":
    domain = "tekkit.io"
    parser = WhoisParser(domain)
    result = parser.get_whois()
    print(result)
