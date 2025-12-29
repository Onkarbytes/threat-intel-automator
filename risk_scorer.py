# risk_scorer.py - Risk Scoring Engine for IOC Analysis
# Phase 3: The Intelligence Engine (Risk Scoring)

import logging
import yaml

logger = logging.getLogger(__name__)

class RiskScorer:
    """
    Analyzes enriched IOC data and assigns risk scores based on configurable thresholds.
    
    Risk levels: CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN
    """
    
    def __init__(self, config_path='config.yaml'):
        """
        Initialize the risk scorer with configuration thresholds.
        
        Args:
            config_path (str): Path to YAML configuration file
        """
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
        
        self.thresholds = self.config.get('risk_thresholds', {})
        
    def score_iocs(self, enriched_data):
        """
        Score all IOCs in the enriched data.
        
        Args:
            enriched_data (dict): Enriched IOC data from API orchestrator
            
        Returns:
            dict: Scored IOCs with risk levels and analysis
        """
        scored_data = {}
        
        for category, iocs in enriched_data.items():
            scored_data[category] = {}
            for ioc, enrichment in iocs.items():
                scored_data[category][ioc] = self._score_single_ioc(ioc, enrichment, category)
                
        return scored_data
    
    def _score_single_ioc(self, ioc, enrichment, category):
        """
        Score a single IOC based on its enrichment data.
        
        Args:
            ioc (str): The IOC value
            enrichment (dict): API enrichment results
            category (str): IOC category (ips, domains, hashes, urls)
            
        Returns:
            dict: Scoring result with risk level, score, and analysis
        """
        result = {
            'ioc': ioc,
            'category': category,
            'risk_level': 'UNKNOWN',
            'risk_score': 0,
            'analysis': {},
            'recommendations': []
        }
        
        try:
            # Analyze each API's data
            vt_analysis = self._analyze_virustotal(enrichment.get('virustotal', {}))
            abuse_analysis = self._analyze_abuseipdb(enrichment.get('abuseipdb', {}))
            
            result['analysis'] = {
                'virustotal': vt_analysis,
                'abuseipdb': abuse_analysis
            }
            
            # Calculate overall risk score and level
            risk_score, risk_level = self._calculate_risk_level(vt_analysis, abuse_analysis, category)
            result['risk_score'] = risk_score
            result['risk_level'] = risk_level
            
            # Generate recommendations
            result['recommendations'] = self._generate_recommendations(risk_level, vt_analysis, abuse_analysis)
            
        except Exception as e:
            logger.error(f"Error scoring IOC {ioc}: {e}")
            result['analysis']['error'] = str(e)
            
        return result
    
    def _analyze_virustotal(self, vt_data):
        """
        Analyze VirusTotal response data.
        
        Args:
            vt_data (dict): VirusTotal API response
            
        Returns:
            dict: Normalized VT analysis
        """
        analysis = {
            'malicious_detections': 0,
            'total_engines': 0,
            'detection_rate': 0.0,
            'reputation': 0,
            'last_analysis_date': None,
            'categories': [],
            'error': None
        }
        
        try:
            if 'error' in vt_data:
                analysis['error'] = vt_data['error']
                return analysis
                
            data = vt_data.get('data', {})
            attributes = data.get('attributes', {})
            
            # Extract detection statistics
            last_analysis_stats = attributes.get('last_analysis_stats', {})
            analysis['malicious_detections'] = last_analysis_stats.get('malicious', 0)
            analysis['total_engines'] = sum(last_analysis_stats.values())
            
            if analysis['total_engines'] > 0:
                analysis['detection_rate'] = analysis['malicious_detections'] / analysis['total_engines']
            
            # Reputation score (negative = malicious)
            analysis['reputation'] = attributes.get('reputation', 0)
            
            # Last analysis date
            analysis['last_analysis_date'] = attributes.get('last_analysis_date')
            
            # Popular threat categories
            analysis['categories'] = attributes.get('popular_threat_classification', {}).get('popular_threat_category', [])
            
        except Exception as e:
            analysis['error'] = f"VT analysis failed: {str(e)}"
            
        return analysis
    
    def _analyze_abuseipdb(self, abuse_data):
        """
        Analyze AbuseIPDB response data.
        
        Args:
            abuse_data (dict): AbuseIPDB API response
            
        Returns:
            dict: Normalized AbuseIPDB analysis
        """
        analysis = {
            'abuse_confidence_score': 0,
            'total_reports': 0,
            'distinct_users': 0,
            'is_whitelisted': False,
            'is_tor': False,
            'country_code': None,
            'usage_type': None,
            'last_reported': None,
            'error': None
        }
        
        try:
            if 'error' in abuse_data:
                analysis['error'] = abuse_data['error']
                return analysis
                
            data = abuse_data.get('data', {})
            
            analysis['abuse_confidence_score'] = data.get('abuseConfidenceScore', 0)
            analysis['total_reports'] = data.get('totalReports', 0)
            analysis['distinct_users'] = data.get('numDistinctUsers', 0)
            analysis['is_whitelisted'] = data.get('isWhitelisted', False)
            analysis['is_tor'] = data.get('isTor', False)
            analysis['country_code'] = data.get('countryCode')
            analysis['usage_type'] = data.get('usageType')
            analysis['last_reported'] = data.get('lastReportedAt')
            
        except Exception as e:
            analysis['error'] = f"AbuseIPDB analysis failed: {str(e)}"
            
        return analysis
    
    def _calculate_risk_level(self, vt_analysis, abuse_analysis, category):
        """
        Calculate overall risk level based on VT and AbuseIPDB analysis.
        
        Args:
            vt_analysis (dict): VirusTotal analysis
            abuse_analysis (dict): AbuseIPDB analysis
            category (str): IOC category
            
        Returns:
            tuple: (risk_score, risk_level)
        """
        risk_score = 0
        
        # Check for errors - if both APIs failed, we can't score
        vt_error = vt_analysis.get('error')
        abuse_error = abuse_analysis.get('error')
        
        if vt_error and abuse_error:
            return 0, 'UNKNOWN'
        
        # VirusTotal scoring
        if not vt_error:
            malicious = vt_analysis.get('malicious_detections', 0)
            detection_rate = vt_analysis.get('detection_rate', 0)
            reputation = vt_analysis.get('reputation', 0)
            
            # High malicious detection count
            if malicious >= 5:
                risk_score += 40
            elif malicious >= 2:
                risk_score += 20
            elif malicious >= 1:
                risk_score += 10
            
            # High detection rate
            if detection_rate >= 0.5:
                risk_score += 30
            elif detection_rate >= 0.2:
                risk_score += 15
            
            # Negative reputation (malicious)
            if reputation < -10:
                risk_score += 20
            elif reputation < 0:
                risk_score += 10
        
        # AbuseIPDB scoring
        if not abuse_error:
            abuse_score = abuse_analysis.get('abuse_confidence_score', 0)
            total_reports = abuse_analysis.get('total_reports', 0)
            is_tor = abuse_analysis.get('is_tor', False)
            
            # High abuse confidence score
            if abuse_score >= 80:
                risk_score += 40
            elif abuse_score >= 50:
                risk_score += 25
            elif abuse_score >= 20:
                risk_score += 10
            
            # Multiple reports
            if total_reports >= 10:
                risk_score += 20
            elif total_reports >= 5:
                risk_score += 10
            elif total_reports >= 1:
                risk_score += 5
            
            # Tor node
            if is_tor:
                risk_score += 30
        
        # Apply configurable thresholds
        thresholds = self.thresholds
        
        if risk_score >= 70:
            return risk_score, 'CRITICAL'
        elif risk_score >= 40:
            return risk_score, 'HIGH'
        elif risk_score >= 20:
            return risk_score, 'MEDIUM'
        elif risk_score >= 5:
            return risk_score, 'LOW'
        else:
            return risk_score, 'SAFE'
    
    def _generate_recommendations(self, risk_level, vt_analysis, abuse_analysis):
        """
        Generate actionable recommendations based on risk level and analysis.
        
        Args:
            risk_level (str): Calculated risk level
            vt_analysis (dict): VirusTotal analysis
            abuse_analysis (dict): AbuseIPDB analysis
            
        Returns:
            list: List of recommendation strings
        """
        recommendations = []
        
        if risk_level in ['CRITICAL', 'HIGH']:
            recommendations.append("🚨 IMMEDIATE ACTION REQUIRED: Block this IOC immediately")
            recommendations.append("🔍 Conduct thorough investigation of affected systems")
            recommendations.append("📋 Review related logs and network traffic")
            
        elif risk_level == 'MEDIUM':
            recommendations.append("⚠️ MONITOR CLOSELY: Add to watchlist and monitor for suspicious activity")
            recommendations.append("🔍 Review context of appearance in logs")
            
        elif risk_level == 'LOW':
            recommendations.append("👀 MONITOR: Log for awareness but no immediate action required")
            
        elif risk_level == 'SAFE':
            recommendations.append("✅ SAFE: No action required based on current intelligence")
        
        # Specific recommendations based on analysis
        if not vt_analysis.get('error'):
            malicious = vt_analysis.get('malicious_detections', 0)
            if malicious > 0:
                recommendations.append(f"🛡️ VirusTotal shows {malicious} malicious detections - consider blocking")
        
        if not abuse_analysis.get('error'):
            abuse_score = abuse_analysis.get('abuse_confidence_score', 0)
            if abuse_score > 50:
                recommendations.append(f"🚫 High abuse confidence ({abuse_score}%) - strong indicator of malicious activity")
            
            if abuse_analysis.get('is_tor'):
                recommendations.append("🌐 Tor exit node detected - monitor for anonymity-related activity")
        
        return recommendations