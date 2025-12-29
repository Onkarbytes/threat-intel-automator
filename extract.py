import re
import json

class Extractor:
    """
    High-Performance IOC Extractor using optimized regex patterns.
    
    This class extracts Indicators of Compromise (IOCs) from raw log files,
    including IPv4 addresses, domains, hashes, and URLs. It handles:
    - Obfuscated IOCs (e.g., 192[.]168[.]1[.]1)
    - De-duplication to avoid processing the same IOC multiple times
    - Large file streaming (line-by-line processing)
    - Multiple file encodings (UTF-8 with Latin-1 fallback)
    
    Attributes:
        ip_pattern (re.Pattern): Regex for IPv4 addresses (standard and obfuscated)
        hash_md5_pattern (re.Pattern): Regex for MD5 hashes (32 hex chars)
        hash_sha256_pattern (re.Pattern): Regex for SHA256 hashes (64 hex chars)
        url_pattern (re.Pattern): Regex for HTTP/HTTPS URLs
        domain_pattern (re.Pattern): Regex for fully qualified domain names
    """

    def __init__(self):
        """
        Initialize the Extractor with compiled regex patterns.
        
        Uses non-capturing groups to ensure findall() returns full matches.
        Patterns are optimized for performance and accuracy.
        """
        # IPv4: Matches standard (192.168.1.1) and obfuscated (192[.]168[.]1[.]1) formats
        # Uses non-capturing groups (?:) to return full IP match, not individual parts
        self.ip_pattern = re.compile(r'\b\d{1,3}(?:\.|\[\.\])\d{1,3}(?:\.|\[\.\])\d{1,3}(?:\.|\[\.\])\d{1,3}\b')
        
        # Hashes: MD5 (32 hex chars) and SHA256 (64 hex chars)
        # Word boundaries ensure we don't match partial strings
        self.hash_md5_pattern = re.compile(r'\b[a-fA-F0-9]{32}\b')
        self.hash_sha256_pattern = re.compile(r'\b[a-fA-F0-9]{64}\b')
        
        # URLs: Basic pattern for http/https URLs
        # Captures from protocol to first whitespace
        self.url_pattern = re.compile(r'https?://[^\s]+')
        
        # Domains/FQDNs: Pattern for fully qualified domain names
        # Matches domain.tld format, allows subdomains
        self.domain_pattern = re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b')
        
        # File paths: Windows and Unix style paths
        # Matches absolute and relative paths, including common file extensions
        self.file_path_pattern = re.compile(r'(?:[a-zA-Z]:)?(?:\\|\/)[^\s]*\.(?:exe|dll|bat|cmd|ps1|sh|py|js|html|php|asp|jsp|war|jar|zip|rar|7z|tar|gz|bz2|pdf|doc|docx|xls|xlsx|ppt|pptx|txt|log|cfg|ini|conf|xml|json|yaml|yml)[^\s]*', re.IGNORECASE)

    def extract(self, file_path):
        """
        Extract IOCs from a log file.
        
        Processes the file line-by-line for memory efficiency, handling large files.
        Attempts UTF-8 encoding first, falls back to Latin-1 if decoding fails.
        Returns a dictionary of sets containing unique IOCs.
        
        Args:
            file_path (str): Path to the log file to process
            
        Returns:
            dict: Dictionary with keys 'ips', 'domains', 'hashes', 'urls', 'files'
                  Each value is a set of unique IOC strings
                  
        Raises:
            ValueError: If file cannot be decoded with supported encodings
        """
        # Initialize sets for each IOC type - sets automatically handle de-duplication
        iocs = {
            'ips': set(),      # IPv4 addresses
            'domains': set(),  # Fully qualified domain names
            'hashes': set(),   # MD5 and SHA256 hashes
            'urls': set(),     # HTTP/HTTPS URLs
            'files': set()     # File paths
        }
        
        # Supported encodings - try UTF-8 first (most common), then Latin-1
        encodings = ['utf-8', 'latin-1']
        file_opened = False
        
        # Try each encoding until successful
        for encoding in encodings:
            try:
                with open(file_path, 'r', encoding=encoding) as f:
                    file_opened = True
                    # Process file line-by-line to handle large files without memory issues
                    for line in f:
                        # Extract IPv4 addresses (standard and obfuscated)
                        ips = self.ip_pattern.findall(line)
                        iocs['ips'].update(ips)
                        
                        # Extract hashes (combine MD5 and SHA256 results)
                        hashes = self.hash_md5_pattern.findall(line) + self.hash_sha256_pattern.findall(line)
                        iocs['hashes'].update(hashes)
                        
                        # Extract URLs
                        urls = self.url_pattern.findall(line)
                        iocs['urls'].update(urls)
                        
                        # Extract domains/FQDNs
                        domains = self.domain_pattern.findall(line)
                        iocs['domains'].update(domains)
                        
                        # Extract file paths
                        files = self.file_path_pattern.findall(line)
                        iocs['files'].update(files)
                break  # Successfully processed with this encoding
            except UnicodeDecodeError:
                continue  # Try next encoding
        
        if not file_opened:
            raise ValueError(f"Could not decode file {file_path} with supported encodings: {encodings}")
        
        return iocs