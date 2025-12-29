# enrich.py - API Orchestrator for IOC Enrichment
# Phase 2: The API Orchestrator

import time
import requests
import yaml
import logging
import datetime
from database import IOCDatabase

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class BaseAPIClient:
    """
    Base class for API clients with rate limiting and error handling.
    
    Implements exponential backoff for retries and respects API rate limits.
    """
    
    def __init__(self, config):
        """
        Initialize the API client.
        
        Args:
            config (dict): Configuration containing base_url, api_key, rate_limit, limit_type, etc.
        """
        self.base_url = config['base_url']
        self.api_key = config.get('api_key')
        self.rate_limit = config.get('rate_limit', 5)
        self.limit_type = config.get('limit_type', 'per_minute')  # 'per_minute' or 'daily'
        
        # For per_minute limits
        self.last_request = 0
        
        # For daily limits
        self.daily_requests = 0
        self.current_day = None
        
        self.max_retries = 3
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'IOC-Enrichment-Pipeline/1.0'})
        
    def _rate_limit(self):
        """
        Enforce rate limiting based on limit_type.
        """
        now = datetime.datetime.now()
        
        if self.limit_type == 'daily':
            # Reset daily counter if it's a new day
            today = now.date()
            if self.current_day != today:
                self.daily_requests = 0
                self.current_day = today
            
            # Check if we've exceeded daily limit
            if self.daily_requests >= self.rate_limit:
                # Calculate seconds until midnight
                tomorrow = today + datetime.timedelta(days=1)
                seconds_until_midnight = (tomorrow - now).total_seconds()
                logger.warning(f"Daily limit ({self.rate_limit}) exceeded. Sleeping until midnight: {seconds_until_midnight:.0f} seconds")
                time.sleep(seconds_until_midnight)
                # Reset for new day
                self.daily_requests = 0
                self.current_day = tomorrow.date()
            
            self.daily_requests += 1
            
        elif self.limit_type == 'per_minute':
            # Original per-minute logic
            elapsed = time.time() - self.last_request
            min_interval = 60 / self.rate_limit
            if elapsed < min_interval:
                sleep_time = min_interval - elapsed
                logger.info(f"Rate limiting: sleeping for {sleep_time:.2f} seconds")
                time.sleep(sleep_time)
            self.last_request = time.time()
    
    def _request_with_retry(self, method, endpoint, **kwargs):
        """
        Make HTTP request with exponential backoff retry logic.
        
        Handles rate limits (429), server errors (5xx), and timeouts.
        
        Args:
            method (str): HTTP method (GET, POST, etc.)
            endpoint (str): API endpoint path
            **kwargs: Additional arguments for requests
            
        Returns:
            dict: JSON response or error dict
        """
        url = self.base_url + endpoint
        
        # Set API key in headers if provided
        if self.api_key:
            headers = kwargs.get('headers', {})
            # API key header varies by service - subclasses should override
            kwargs['headers'] = headers
        
        for attempt in range(self.max_retries):
            try:
                self._rate_limit()
                response = self.session.request(method, url, timeout=30, **kwargs)
                
                if response.status_code == 429:
                    # Rate limited - exponential backoff
                    backoff_time = 2 ** attempt
                    logger.warning(f"Rate limited (429). Retrying in {backoff_time} seconds...")
                    time.sleep(backoff_time)
                    continue
                    
                response.raise_for_status()
                return response.json()
                
            except requests.exceptions.Timeout:
                logger.error(f"Timeout on {url}")
                if attempt < self.max_retries - 1:
                    time.sleep(2 ** attempt)
                    continue
                return {'error': 'Timeout'}
                
            except requests.exceptions.HTTPError as e:
                if 500 <= e.response.status_code < 600:
                    # Server error - retry
                    logger.error(f"Server error {e.response.status_code} on {url}")
                    if attempt < self.max_retries - 1:
                        time.sleep(2 ** attempt)
                        continue
                return {'error': f'HTTP {e.response.status_code}: {e.response.text}'}
                
            except requests.exceptions.RequestException as e:
                logger.error(f"Request error on {url}: {e}")
                if attempt < self.max_retries - 1:
                    time.sleep(2 ** attempt)
                    continue
                return {'error': str(e)}
        
        return {'error': 'Max retries exceeded'}

class VirusTotalClient(BaseAPIClient):
    """
    VirusTotal API client for IOC enrichment.
    
    Supports querying IPs, domains, hashes, and URLs.
    """
    
    def __init__(self, config):
        super().__init__(config)
        # VirusTotal uses 'x-apikey' header
        if self.api_key:
            self.session.headers.update({'x-apikey': self.api_key})
    
    def query_ip(self, ip):
        """Query VirusTotal for IP address information."""
        return self._request_with_retry('GET', f'/ip_addresses/{ip}')
    
    def query_domain(self, domain):
        """Query VirusTotal for domain information."""
        return self._request_with_retry('GET', f'/domains/{domain}')
    
    def query_hash(self, hash_value):
        """Query VirusTotal for file hash information."""
        return self._request_with_retry('GET', f'/files/{hash_value}')
    
    def query_url(self, url):
        """
        Query VirusTotal for URL information.
        
        Note: VT requires posting URLs first to get an analysis ID.
        For simplicity, this returns an error for now.
        """
        # VT URL analysis requires two steps: POST to /urls, then GET /analyses/{id}
        # This is complex to implement without storing state
        logger.warning("URL queries not fully implemented for VirusTotal")
        return {'error': 'URL analysis not implemented'}

class AbuseIPDBClient(BaseAPIClient):
    """
    AbuseIPDB API client for IP reputation checking.
    """
    
    def __init__(self, config):
        super().__init__(config)
        # AbuseIPDB uses 'Key' header
        if self.api_key:
            self.session.headers.update({'Key': self.api_key})
    
    def query_ip(self, ip):
        """Query AbuseIPDB for IP abuse information."""
        return self._request_with_retry('GET', '/check', params={'ipAddress': ip})

class APIOrchestrator:
    """
    Main orchestrator for IOC enrichment across multiple APIs.
    
    Coordinates queries to VirusTotal, AbuseIPDB, and WHOIS services.
    """
    
    def __init__(self, config_path='config.yaml'):
        """
        Initialize the orchestrator with API clients.
        
        Args:
            config_path (str): Path to YAML configuration file
        """
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
        
        # Initialize API clients
        self.vt_client = VirusTotalClient(self.config['apis']['virustotal'])
        self.abuse_client = AbuseIPDBClient(self.config['apis']['abuseipdb'])
        
        # WHOIS client not implemented yet
        self.whois_client = None
        
        # Initialize caching database
        self.db = IOCDatabase()
    
    def enrich_iocs(self, iocs):
        """
        Enrich a dictionary of IOCs using available APIs.
        
        Args:
            iocs (dict): Dictionary of IOC sets by category
            
        Returns:
            dict: Enriched IOC data with API responses
        """
        enriched = {}
        
        for category, items in iocs.items():
            enriched[category] = {}
            logger.info(f"Enriching {len(items)} {category}...")
            
            for item in items:
                enriched[category][item] = self._enrich_single_ioc(item, category)
                
        return enriched
    
    def _enrich_single_ioc(self, ioc, category):
        """
        Enrich a single IOC using appropriate APIs.
        
        Args:
            ioc (str): The IOC to enrich
            category (str): IOC category (ips, domains, hashes, urls)
            
        Returns:
            dict: Enrichment results from various APIs
        """
        result = {}
        
        try:
            if category == 'ips':
                logger.debug(f"Enriching IP: {ioc}")
                result['virustotal'] = self.vt_client.query_ip(ioc)
                result['abuseipdb'] = self.abuse_client.query_ip(ioc)
                # result['whois'] = self.whois_client.query_ip(ioc) if self.whois_client else {'error': 'WHOIS not implemented'}
                
            elif category == 'domains':
                logger.debug(f"Enriching domain: {ioc}")
                result['virustotal'] = self.vt_client.query_domain(ioc)
                # AbuseIPDB doesn't have domain API
                # result['whois'] = self.whois_client.query_domain(ioc) if self.whois_client else {'error': 'WHOIS not implemented'}
                
            elif category == 'hashes':
                logger.debug(f"Enriching hash: {ioc}")
                result['virustotal'] = self.vt_client.query_hash(ioc)
                
            elif category == 'urls':
                logger.debug(f"Enriching URL: {ioc}")
                result['virustotal'] = self.vt_client.query_url(ioc)
                
        except Exception as e:
            logger.error(f"Error enriching {ioc}: {e}")
            result['error'] = str(e)
            
        return result