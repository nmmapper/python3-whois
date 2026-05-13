import subprocess
import re
from typing import Optional, List, Dict, Union
from datetime import datetime

class Whois:
    """
    A robust WHOIS parser that handles regional formatting differences, 
    date normalization, and registrar name cleanup.
    """
    
    def __init__(self, domain: str):
        self.domain = domain.lower().strip()
        self.raw_text = self._run_whois()

    def _run_whois(self) -> str:
        """Execute the system whois command and handle potential errors."""
        try:
            result = subprocess.run(
                ["whois", self.domain],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode != 0:
                stderr_msg = result.stderr or ""
                return f"Error: whois returned code {result.returncode}\n{stderr_msg}"
            return result.stdout or ""
        except subprocess.TimeoutExpired:
            return "Error: whois command timed out after 10 seconds"
        except FileNotFoundError:
            return "Error: whois utility not found. Install it with: apt-get install whois"
        except Exception as e:
            return f"Error: {str(e)}"

    def _normalize_date(self, date_str: str) -> Optional[str]:
        """Normalize various date formats and strip timezone offsets."""
        if not date_str:
            return None
        
        date_str = date_str.strip()
        # Remove timezone offsets like +02, UTC, or text in parentheses
        date_clean = re.sub(r'(\+\d{2}:?\d{2}|[A-Z]{3}|\(.*\))$', '', date_str).strip()
        
        # Comprehensive list of date formats across registries
        formats = (
            "%Y-%m-%dT%H:%M:%SZ", 
            "%Y-%m-%dT%H:%M:%S.%fZ", 
            "%Y-%m-%d %H:%M:%S", 
            "%Y.%m.%d %H:%M:%S",
            "%d.%m.%Y %H:%M:%S",
            "%Y-%m-%d", 
            "%Y/%m/%d", 
            "%d-%m-%Y",
            "%d.%m.%Y",
            "%d-%b-%Y"  # Nominet/UK format: 13-Feb-2025
        )
        
        for fmt in formats:
            try:
                # Return standardized ISO format
                return datetime.strptime(date_clean, fmt).isoformat()
            except ValueError:
                continue
        return date_str

    def _normalize_registrar(self, registrar: Optional[str]) -> Optional[str]:
        """Clean registrar names, fix casing, and strip registry-specific tags."""
        if not registrar:
            return registrar
        
        registrar = registrar.strip()

        # Specifically for UK: strip the [Tag = ...] part
        registrar = re.sub(r'\s*\[Tag\s*=.*\]', '', registrar, flags=re.IGNORECASE).strip()

        # If it's already mixed-case or lowercase (like ua.ukraine), keep it as is
        if not registrar.isupper():
            return registrar

        # If it's ALL CAPS, convert to Title Case for readability
        registrar = registrar.title()

        # Fix specific business suffixes to be professional
        replacements = {
            " Llc": " LLC",
            " Inc": ", Inc.",
            " Ltd": " Ltd.",
            "Gmbh": "GmbH",
            "A.G.": "AG"
        }
        for old, new in replacements.items():
            registrar = registrar.replace(old, new)
        
        # Fix punctuation artifacts (like double dots or commas)
        registrar = registrar.replace("..", ".").replace(",,", ",")
        registrar = registrar.replace(", .", ", ").replace(" ,", ",")
        
        return registrar.strip().replace(",,", ",")

    def _dedupe_nameservers(self, ns_list: List[str]) -> List[str]:
        """Remove duplicates while maintaining order."""
        seen = set()
        return [x for x in ns_list if not (x in seen or seen.add(x))]

    def parse_generic(self) -> Dict[str, Union[Optional[str], List[str]]]:
        """Parse standard colon-separated WHOIS keys, including UA support."""
        mappings = {
            "domain name": "domain_name",
            "domain": "domain_name",
            "registrar": "registrar",
            "registrar url": "registrar_url",
            "whois server": "whois_server",
            "updated date": "updated_date",
            "last updated": "updated_date",
            "modified": "updated_date", # common in .ua
            "creation date": "creation_date",
            "registered on": "creation_date",
            "created": "creation_date", # common in .ua
            "registry expiry date": "expiry_date",
            "expiry date": "expiry_date",
            "expires": "expiry_date", # common in .ua
            "paid-till": "expiry_date" # common in .ru
        }

        result = {v: None for v in set(mappings.values())}
        result["name_servers"] = []
        result["status"] = None

        for line in self.raw_text.splitlines():
            line = line.strip()
            if not line or ":" not in line:
                continue
            
            key, val = line.split(":", 1)
            key = key.lower().strip()
            val = val.strip()
            
            if key in mappings:
                norm_key = mappings[key]
                if "date" in norm_key:
                    result[norm_key] = self._normalize_date(val)
                elif norm_key == "registrar" and result[norm_key] is None:
                    result[norm_key] = val
                else:
                    result[norm_key] = val
            elif key.startswith("name server") or key == "nserver":
                ns_match = re.search(r"([a-zA-Z0-9.-]+)", val)
                if ns_match:
                    result["name_servers"].append(ns_match.group(1).lower())
            elif key == "status":
                result["status"] = val

        return result

    def parse_uk(self) -> Dict[str, Union[Optional[str], List[str]]]:
        """Parse .uk domain WHOIS with support for Nominet's multi-line indented format."""
        data = {
            "registrar": None, "registrar_url": None, "creation_date": None,
            "expiry_date": None, "updated_date": None, "name_servers": [],
            "whois_server": None, "status": None, "domain_name": None
        }

        lines = self.raw_text.splitlines()
        for i, line in enumerate(lines):
            line_s = line.strip()
            
            # Nominet values are often on the NEXT line
            if line_s == "Domain name:":
                if i + 1 < len(lines): data["domain_name"] = lines[i+1].strip().lower()
            elif line_s == "Registrar:":
                if i + 1 < len(lines): data["registrar"] = lines[i+1].strip()
            elif line_s.startswith("URL:"):
                data["registrar_url"] = line_s.replace("URL:", "").strip()
            elif "Registered on:" in line:
                data["creation_date"] = self._normalize_date(line.split(":", 1)[-1])
            elif "Expiry date:" in line:
                data["expiry_date"] = self._normalize_date(line.split(":", 1)[-1])
            elif "Last updated:" in line:
                data["updated_date"] = self._normalize_date(line.split(":", 1)[-1])
            elif line_s == "Name servers:":
                j = i + 1
                while j < len(lines) and (not lines[j].strip() or lines[j].startswith(" ")):
                    ns = lines[j].strip().lower()
                    if ns and "." in ns: data["name_servers"].append(ns)
                    j += 1
        return data

    def _extract_by_keys(self, mapping: Dict[str, str]) -> Dict[str, Union[Optional[str], List[str]]]:
        """Helper to extract data based on TLD-specific keys."""
        data = self.parse_generic()
        for line in self.raw_text.splitlines():
            line = line.strip()
            if ":" not in line: continue
            k, v = line.split(":", 1)
            k, v = k.strip().lower(), v.strip()
            if k in mapping:
                target = mapping[k]
                data[target] = self._normalize_date(v) if "date" in target else v
        return data

    def parse_jp(self): return self._extract_by_keys({"[registered date]": "creation_date", "[last update]": "updated_date"})
    def parse_br(self): return self._extract_by_keys({"% created": "creation_date", "% expires": "expiry_date", "% changed": "updated_date"})
    def parse_it(self): return self._extract_by_keys({"created": "creation_date", "expire date": "expiry_date", "last update": "updated_date"})
    def parse_ca(self): return self._extract_by_keys({"creation date": "creation_date", "expiry date": "expiry_date", "updated date": "updated_date"})
    def parse_au(self): return self._extract_by_keys({"created": "creation_date", "expiry": "expiry_date", "last modified": "updated_date"})
    def parse_nz(self): return self._extract_by_keys({"domain_dateregistered": "creation_date", "domain_dateexpires": "expiry_date", "domain_datelastmodified": "updated_date"})

    def get_whois(self) -> Dict[str, Union[Optional[str], List[str]]]:
        """Route to appropriate parser based on TLD and post-process results."""
        if self.raw_text.startswith("Error:"):
            return {"error": self.raw_text}

        # Dispatcher logic
        if self.domain.endswith(".uk"): result = self.parse_uk()
        elif self.domain.endswith(".jp"): result = self.parse_jp()
        elif self.domain.endswith(".br"): result = self.parse_br()
        elif self.domain.endswith(".it"): result = self.parse_it()
        elif self.domain.endswith(".ca"): result = self.parse_ca()
        elif self.domain.endswith(".au"): result = self.parse_au()
        elif self.domain.endswith(".nz"): result = self.parse_nz()
        else: result = self.parse_generic()

        # Final cleanup for all results
        if result.get("registrar"):
            result["registrar"] = self._normalize_registrar(result["registrar"])
        if result.get("name_servers"):
            result["name_servers"] = self._dedupe_nameservers(result["name_servers"])

        return result

if __name__ == "__main__":
    # Standard test cases provided by user
    test_domains = ["advokat-zp.in.ua", "turkishfoodsuppliers.co.uk"]
    
    import json
    for d in test_domains:
        print(f"\n>>> Querying: {d}")
        w = Whois(d)
        print(json.dumps(w.get_whois(), indent=2))
