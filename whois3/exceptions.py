
class WhoisNotInstalledError(Exception):
    """Exception raised when whois is not installed"""
    
    def __init__(self, message="whois is either not installed or we couldn't locate whois path Please ensure whois is installed"):
        self.message = message 
        super().__init__(message)
        
class WhoisExecutionError(Exception):
    """Exception raised when en error occurred during whois call"""
