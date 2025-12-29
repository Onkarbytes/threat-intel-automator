# scanner.py - YARA/Sigma Integration for Active Detection
# Phase 7: The Hunter Module (YARA/Sigma Integration)

import os
import logging
import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

try:
    import yara_x
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
    logger.warning("YARA library not available. YARA scanning will be disabled.")

class YARAScanner:
    """
    YARA rule scanner for active threat detection.
    
    Scans files identified during IOC extraction against user-provided YARA rules.
    Integrates with the pipeline to provide additional detection capabilities.
    """
    
    def __init__(self, rules_directory=None):
        """
        Initialize the YARA scanner.
        
        Args:
            rules_directory (str): Path to directory containing .yar rule files
        """
        self.rules_directory = rules_directory
        self.compiled_rules = None
        self.yara_available = YARA_AVAILABLE
        
        if not self.yara_available:
            logger.warning("YARA scanner initialized but YARA library not available")
            return
            
        if rules_directory and os.path.exists(rules_directory):
            self.load_rules(rules_directory)
    
    def load_rules(self, rules_directory):
        """
        Load and compile YARA rules from a directory.

        Args:
            rules_directory (str): Path to directory containing .yar files

        Returns:
            bool: True if rules loaded successfully, False otherwise
        """
        if not self.yara_available:
            logger.warning("Cannot load YARA rules: YARA library not available")
            return False

        try:
            if not os.path.exists(rules_directory):
                logger.warning(f"YARA rules directory does not exist: {rules_directory}")
                return False

            # Find all .yar files in the directory
            yar_files = list(Path(rules_directory).glob("*.yar"))

            if not yar_files:
                logger.warning(f"No .yar files found in directory: {rules_directory}")
                return False

            # Read and compile all rules
            all_rules_source = ""
            rule_names = []

            for yar_file in yar_files:
                try:
                    with open(yar_file, 'r', encoding='utf-8') as f:
                        rule_content = f.read()

                    # Add a namespace comment for identification
                    rule_name = yar_file.stem
                    namespaced_rule = f"// Rule: {rule_name}\n{rule_content}\n\n"
                    all_rules_source += namespaced_rule
                    rule_names.append(rule_name)
                    logger.info(f"Loaded YARA rule: {rule_name}")

                except Exception as e:
                    logger.error(f"Error reading rule file {yar_file}: {e}")

            if all_rules_source:
                self.compiled_rules = yara_x.compile(all_rules_source)
                self.scanner = yara_x.Scanner(self.compiled_rules)
                logger.info(f"Successfully compiled {len(rule_names)} YARA rules")
                return True
            else:
                logger.warning("No valid YARA rules could be loaded")
                return False

        except Exception as e:
            logger.error(f"Error loading YARA rules: {e}")
            return False
    
    def scan_file(self, file_path):
        """
        Scan a single file against loaded YARA rules.

        Args:
            file_path (str): Path to the file to scan

        Returns:
            dict: Scan results with matched rules and metadata
        """
        if not self.yara_available:
            return {'error': 'YARA library not available', 'status': 'disabled'}

        if not self.compiled_rules:
            return {'error': 'No YARA rules loaded'}

        if not os.path.exists(file_path):
            return {'error': f'File does not exist: {file_path}'}

        try:
            # Read file as bytes
            with open(file_path, 'rb') as f:
                file_data = f.read()

            # Perform the scan
            scan_results = self.scanner.scan(file_data)

            # Format results
            result = {
                'file_path': file_path,
                'file_size': len(file_data),
                'scan_time': str(datetime.datetime.now()),
                'matches': []
            }

            if scan_results.matching_rules:
                for rule in scan_results.matching_rules:
                    rule_info = {
                        'rule_name': rule.identifier,
                        'namespace': rule.namespace if hasattr(rule, 'namespace') else '',
                        'tags': list(rule.tags) if hasattr(rule, 'tags') and rule.tags else [],
                        'metadata': dict(rule.metadata) if hasattr(rule, 'metadata') and rule.metadata else {},
                        'strings': []
                    }

                    # Add matched strings if available
                    if hasattr(rule, 'patterns'):
                        for pattern in rule.patterns:
                            if hasattr(pattern, 'matches'):
                                for match in pattern.matches:
                                    string_info = {
                                        'identifier': pattern.identifier if hasattr(pattern, 'identifier') else '',
                                        'offset': match.offset if hasattr(match, 'offset') else 0,
                                        'matched_data': match.matched_data[:100] if hasattr(match, 'matched_data') else ''
                                    }
                                    rule_info['strings'].append(string_info)

                    result['matches'].append(rule_info)

            result['total_matches'] = len(result['matches'])
            return result

        except Exception as e:
            logger.error(f"Error scanning file {file_path}: {e}")
            return {'error': str(e), 'file_path': file_path}
    
    def scan_multiple_files(self, file_paths):
        """
        Scan multiple files against YARA rules.
        
        Args:
            file_paths (list): List of file paths to scan
            
        Returns:
            dict: Results for all scanned files
        """
        results = {}
        
        for file_path in file_paths:
            logger.info(f"Scanning file: {file_path}")
            results[file_path] = self.scan_file(file_path)
        
        return results
    
    def scan_from_iocs(self, extracted_iocs, base_directory=None):
        """
        Scan files identified during IOC extraction.
        
        Args:
            extracted_iocs (dict): IOCs extracted from logs (should contain 'files' key)
            base_directory (str): Base directory to resolve relative file paths
            
        Returns:
            dict: Scan results for all found files
        """
        file_paths = extracted_iocs.get('files', set())
        
        if not file_paths:
            logger.info("No file paths found in extracted IOCs")
            return {}
        
        # Convert to list and resolve paths
        files_to_scan = []
        for file_path in file_paths:
            # Resolve relative paths if base directory provided
            if base_directory and not os.path.isabs(file_path):
                resolved_path = os.path.join(base_directory, file_path)
            else:
                resolved_path = file_path
            
            # Only scan if file exists
            if os.path.exists(resolved_path):
                files_to_scan.append(resolved_path)
            else:
                logger.warning(f"File not found for scanning: {resolved_path}")
        
        if not files_to_scan:
            logger.warning("No valid files found to scan")
            return {}
        
        logger.info(f"Scanning {len(files_to_scan)} files with YARA rules")
        return self.scan_multiple_files(files_to_scan)
    
    def get_rules_summary(self):
        """
        Get a summary of loaded YARA rules.

        Returns:
            dict: Summary of loaded rules
        """
        if not self.compiled_rules:
            return {'status': 'No rules loaded'}

        try:
            # yara-x doesn't provide easy access to rule count, so we'll provide basic info
            return {
                'status': 'Rules loaded',
                'rules_directory': self.rules_directory,
                'library': 'yara-x',
                'note': 'YARA rules are compiled and ready for scanning'
            }
        except Exception as e:
            return {'status': 'Error getting rules summary', 'error': str(e)}

# Integration function for the main pipeline
def integrate_yara_scanning(enriched_data, yara_rules_dir=None, base_scan_dir=None):
    """
    Integrate YARA scanning results into the enriched IOC data.
    
    Args:
        enriched_data (dict): Enriched IOC data from the pipeline
        yara_rules_dir (str): Directory containing YARA rules
        base_scan_dir (str): Base directory for resolving relative file paths
        
    Returns:
        dict: Enriched data with YARA scan results added
    """
    if not yara_rules_dir:
        logger.info("No YARA rules directory specified, skipping YARA integration")
        return enriched_data
    
    # Initialize scanner
    scanner = YARAScanner(yara_rules_dir)
    
    if not scanner.compiled_rules:
        logger.warning("Failed to load YARA rules, skipping YARA integration")
        return enriched_data
    
    # Extract file paths from the enriched data structure
    # The enriched_data has categories as keys, but we need to reconstruct the files
    file_paths = set()
    
    # For now, we'll assume files are passed separately or we need to modify the pipeline
    # In a full implementation, the extracted_iocs would be passed here
    
    # For demonstration, we'll add a placeholder for YARA results
    # In the actual pipeline integration, this would scan real files
    
    logger.info("YARA scanning integration ready (files would be scanned here)")
    
    # Add YARA results to enriched data
    enriched_data['_yara_scanning'] = {
        'rules_loaded': bool(scanner.compiled_rules),
        'rules_directory': yara_rules_dir,
        'scan_performed': False,  # Would be True if actual scanning occurred
        'note': 'YARA integration ready - needs file paths from extraction phase'
    }
    
    return enriched_data