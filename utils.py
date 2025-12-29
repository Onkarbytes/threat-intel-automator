# utils.py - Utility Functions for IOC Analysis Pipeline
# Phase 5: Utility Functions

import re

def defang_ioc(ioc):
    """
    Defang an IOC to make it safe for text-based reports.
    
    Replaces potentially dangerous characters with safe alternatives:
    - Dots (.) -> [.]
    - http:// -> hxxp://
    - https:// -> hxxps://
    
    Args:
        ioc (str): The IOC to defang
        
    Returns:
        str: Defanged version of the IOC
    """
    if not ioc:
        return ioc
    
    # Convert to string if not already
    ioc_str = str(ioc)
    
    # Replace dots with [.] for IPs and domains
    # But be careful not to replace dots in URLs that are already defanged
    if not ioc_str.startswith('hxxp'):
        # Replace dots, but preserve existing defanging
        ioc_str = re.sub(r'\.(?![^[]*\])', '[.]', ioc_str)
    
    # Replace http/https with hxxp/hxxps
    ioc_str = ioc_str.replace('http://', 'hxxp://')
    ioc_str = ioc_str.replace('https://', 'hxxps://')
    
    return ioc_str

def refang_ioc(ioc):
    """
    Refang a defanged IOC (reverse operation of defang_ioc).
    
    Args:
        ioc (str): The defanged IOC to refang
        
    Returns:
        str: Refanged version of the IOC
    """
    if not ioc:
        return ioc
    
    ioc_str = str(ioc)
    
    # Reverse the defanging
    ioc_str = ioc_str.replace('[.]', '.')
    ioc_str = ioc_str.replace('hxxp://', 'http://')
    ioc_str = ioc_str.replace('hxxps://', 'https://')
    
    return ioc_str

def is_defanged(ioc):
    """
    Check if an IOC appears to be defanged.
    
    Args:
        ioc (str): The IOC to check
        
    Returns:
        bool: True if the IOC appears defanged
    """
    if not ioc:
        return False
    
    ioc_str = str(ioc)
    return '[.]' in ioc_str or ioc_str.startswith('hxxp')

def format_timestamp(dt):
    """
    Format a datetime object for display.
    
    Args:
        dt: datetime object or string
        
    Returns:
        str: Formatted timestamp string
    """
    if isinstance(dt, str):
        try:
            dt = datetime.fromisoformat(dt.replace('Z', '+00:00'))
        except:
            return dt
    
    if hasattr(dt, 'strftime'):
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    
    return str(dt)