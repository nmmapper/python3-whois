import shlex
import os
import re
import subprocess
from whois3.utils import get_whois_path
from whois3.exceptions import WhoisNotInstalledError, WhoisExecutionError
from whois3.whoisregex import WhoisRegex
import json

class Whois(object):
    """Class object to help execute and parse whois results from the command whois"""
    def __init__(self, path=None):
        """
        :param path: path with whois command is located eg /usr/bin/whois
        """
        
        self.whoiscmd = path if path else get_whois_path()
        self.timeout = 10
        self.wregex = WhoisRegex()
        self.registrar_info = {}
        
    def get_default_cmd(self, domain, args=None):
        """Return default whois command"""
        if not args:
            return "{whoiscmd} {domain}".format(whoiscmd=self.whoiscmd, domain=domain)
        return "{whoiscmd} {domain} {args}".format(whoiscmd=self.whoiscmd, domain=domain, args=args)
        
    def run_command(self, cmd, timeout=None):
        """
        Runs the nmap command using popen

        @param: cmd--> the command we want run eg /usr/bin/whois nmmapper.com 
        @param: timeout--> command subprocess timeout in seconds.
        """
        if (os.path.exists(self.whoiscmd)):
            sub_proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                output, errs = sub_proc.communicate(timeout=timeout)
            except Exception as e:
                sub_proc.kill()
                raise (e)
            else:
                if 0 != sub_proc.returncode:
                    raise WhoisExecutionError('Error during command: "' + ' '.join(cmd) + '"\n\n' + errs.decode('utf8'))

                # Response is bytes so decode the output and return
                return output.decode('utf8').strip()
        else:
            raise WhoisExecutionError()
    
    def precompile_regexes(self, source, flags=0):
        return [re.compile(regex, flags) for regex in source]
    
    def whois(self, domain, args=None):
        """Runs the real whois command"""
        try:
            cmd = self.get_default_cmd(domain, args)
            scan_shlex = shlex.split(cmd)
            results = self.run_command(scan_shlex)
            
            for rg in self.wregex.regex:
                compiled = self.precompile_regexes(rg, re.IGNORECASE)
                
                for cmp_reg in compiled:
                    result = cmp_reg.search(results)
                    
                    if(result):
                        data = result.groupdict()
                        self.registrar_info.update(data)
                    
                    # Get domain status and nameserver
                    self.parse_domain_status(results)
                    self.parse_domain_nameserver(results)
                    
            return self.registrar_info
            
        except Exception as e:
            raise 
    
    def parse_domain_status(self, data):
        """Domain status tends to be list"""
        try:
            # Parse status
            compiled = self.precompile_regexes(self.wregex.regex_status, re.IGNORECASE)
            for cmp_reg in compiled:
                results = cmp_reg.findall(data)
                self.registrar_info["status"]=results
        except Exception as e:
            raise
            
            
    def parse_domain_nameserver(self, data):
        """Domain status tends to be list"""
        try:
            # Parse nameservers
            compiled = self.precompile_regexes(self.wregex.regex_nameserver, re.IGNORECASE)
            for cmp_reg in compiled:
                results = cmp_reg.findall(data)
                results = [ ns.lower() for ns in results ]
                self.registrar_info["nameservers"]=list(set(results)) # filter duplicates
        except Exception as e:
            raise
            
if __name__=="__main__":
    m = Whois()
    r = m.whois("ipv4info.com")
    print (json.dumps(r, sort_keys=True, indent=4))
