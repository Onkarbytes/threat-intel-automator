# ai_summary.py - AI Analyst for Human-Readable Threat Intelligence
# Phase 9: The AI Analyst (LLM Integration)

import os
import json
import logging
from datetime import datetime
from typing import Dict, List, Any
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Try to import available LLM libraries
try:
    import google.genai as genai
    GOOGLE_AVAILABLE = True
except ImportError:
    GOOGLE_AVAILABLE = False

try:
    import openai
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False

logger = logging.getLogger(__name__)

class AIAnalyst:
    """
    AI-powered analyst for generating human-readable threat intelligence summaries.
    
    Uses Large Language Models to provide contextual analysis and actionable
    insights from technical IOC data.
    """
    
    def __init__(self, api_key=None, provider="google"):
        """
        Initialize the AI analyst.
        
        Args:
            api_key (str): API key for the LLM provider
            provider (str): LLM provider ('google' or 'openai')
        """
        self.provider = provider.lower()
        self.api_key = api_key or self._get_api_key_from_env()
        
        if self.provider == "google" and GOOGLE_AVAILABLE:
            if self.api_key:
                self.client = genai.Client(api_key=self.api_key)
                self.model = "gemini-2.5-flash-lite"
            else:
                logger.warning("Google API key not provided")
                self.client = None
        elif self.provider == "openai" and OPENAI_AVAILABLE:
            if self.api_key:
                openai.api_key = self.api_key
                self.model = "gpt-3.5-turbo"
            else:
                logger.warning("OpenAI API key not provided")
                self.model = None
        else:
            logger.warning(f"Provider {provider} not available or not supported")
            self.client = None
    
    def _get_api_key_from_env(self):
        """
        Get API key from environment variables.
        
        Returns:
            str: API key or None
        """
        if self.provider == "google":
            return os.getenv('GOOGLE_API_KEY')
        elif self.provider == "openai":
            return os.getenv('OPENAI_API_KEY')
        return None
    
    def analyze_critical_iocs(self, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze critical IOCs and generate AI-powered summary.
        
        Args:
            analysis_data (dict): Complete analysis results from pipeline
            
        Returns:
            dict: Analysis results with AI summary added
        """
        # Extract critical and high-risk IOCs
        critical_iocs = self._extract_critical_iocs(analysis_data)
        
        if not critical_iocs:
            logger.info("No critical IOCs found for AI analysis")
            return analysis_data
        
        # Generate AI summary
        ai_summary = self._generate_ai_summary(critical_iocs)
        
        # Add to analysis data
        analysis_data_copy = analysis_data.copy()
        analysis_data_copy['ai_analysis'] = {
            'generated_at': datetime.now().isoformat(),
            'provider': self.provider,
            'critical_iocs_count': len(critical_iocs),
            'summary': ai_summary
        }
        
        return analysis_data_copy
    
    def _extract_critical_iocs(self, analysis_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Extract critical and high-risk IOCs from analysis data.
        
        Args:
            analysis_data (dict): Analysis results
            
        Returns:
            list: List of critical IOC dictionaries
        """
        critical_iocs = []
        risk_analysis = analysis_data.get('risk_analysis', {})
        
        for category, iocs in risk_analysis.items():
            for ioc, analysis in iocs.items():
                risk_level = analysis.get('risk_level', 'UNKNOWN')
                
                if risk_level in ['CRITICAL', 'HIGH']:
                    ioc_data = {
                        'ioc': ioc,
                        'category': category,
                        'risk_level': risk_level,
                        'risk_score': analysis.get('risk_score', 0),
                        'analysis': analysis.get('analysis', {}),
                        'recommendations': analysis.get('recommendations', [])
                    }
                    critical_iocs.append(ioc_data)
        
        return critical_iocs
    
    def _generate_ai_summary(self, critical_iocs: List[Dict[str, Any]]) -> Dict[str, str]:
        """
        Generate AI-powered summary of critical IOCs.
        
        Args:
            critical_iocs (list): List of critical IOC data
            
        Returns:
            dict: AI-generated summary with different components
        """
        if not self.model:
            return {
                'error': 'AI model not available',
                'summary': 'AI analysis not performed due to missing API key or model',
                'recommendations': []
            }
        
        # Prepare data for AI analysis
        ioc_summary = self._format_iocs_for_ai(critical_iocs)
        
        # System prompt
        system_prompt = """You are a Senior Incident Responder with 15+ years of experience in cybersecurity operations. You have extensive knowledge of threat intelligence, incident response, and security operations.

Analyze the provided JSON data containing critical and high-risk Indicators of Compromise (IOCs) detected in security logs. Provide a concise but comprehensive analysis following this structure:

1. **THREAT SUMMARY** (2-3 sentences): Describe the overall threat landscape based on the IOCs
2. **KEY FINDINGS** (3-5 bullet points): Most important technical details and patterns
3. **CONTAINMENT STEPS** (2 specific, actionable recommendations): What should be done immediately

Focus on being actionable, technical, and concise. Use professional security terminology."""
        
        try:
            if self.provider == "google" and GOOGLE_AVAILABLE:
                return self._query_google_ai(system_prompt, ioc_summary)
            elif self.provider == "openai" and OPENAI_AVAILABLE:
                return self._query_openai(system_prompt, ioc_summary)
            else:
                return {
                    'error': 'No supported AI provider available',
                    'summary': 'AI analysis could not be performed',
                    'recommendations': []
                }
                
        except Exception as e:
            logger.error(f"Error generating AI summary: {e}")
            return {
                'error': str(e),
                'summary': 'AI analysis failed due to technical error',
                'recommendations': []
            }
    
    def _format_iocs_for_ai(self, critical_iocs: List[Dict[str, Any]]) -> str:
        """
        Format IOC data for AI analysis.
        
        Args:
            critical_iocs (list): List of critical IOC data
            
        Returns:
            str: Formatted string for AI consumption
        """
        formatted = []
        
        for ioc_data in critical_iocs:
            ioc_info = f"""
IOC: {ioc_data['ioc']}
Category: {ioc_data['category']}
Risk Level: {ioc_data['risk_level']} (Score: {ioc_data['risk_score']})
"""
            
            # Add analysis details
            analysis = ioc_data.get('analysis', {})
            
            if 'virustotal' in analysis and analysis['virustotal']:
                vt = analysis['virustotal']
                if not vt.get('error'):
                    malicious = vt.get('malicious_detections', 0)
                    total = vt.get('total_engines', 0)
                    ioc_info += f"VirusTotal: {malicious}/{total} malicious detections\n"
            
            if 'abuseipdb' in analysis and analysis['abuseipdb']:
                abuse = analysis['abuseipdb']
                if not abuse.get('error'):
                    score = abuse.get('abuse_confidence_score', 0)
                    ioc_info += f"AbuseIPDB: {score}% confidence score\n"
            
            formatted.append(ioc_info.strip())
        
        return "\n\n".join(formatted)
    
    def _query_google_ai(self, system_prompt: str, ioc_data: str) -> Dict[str, str]:
        """
        Query Google Gemini AI for analysis.
        
        Args:
            system_prompt (str): System instructions
            ioc_data (str): Formatted IOC data
            
        Returns:
            dict: AI response
        """
        try:
            prompt = f"{system_prompt}\n\nIOC DATA:\n{ioc_data}"
            
            response = self.client.models.generate_content(
                model=self.model,
                contents=prompt
            )
            
            # Parse the response (assuming it follows the requested format)
            response_text = response.text
            
            return {
                'provider': 'google',
                'model': self.model,
                'summary': response_text,
                'raw_response': response_text
            }
            
        except Exception as e:
            logger.error(f"Google AI query failed: {e}")
            return {
                'error': str(e),
                'summary': 'Google AI analysis failed',
                'provider': 'google'
            }
    
    def _query_openai(self, system_prompt: str, ioc_data: str) -> Dict[str, str]:
        """
        Query OpenAI for analysis.
        
        Args:
            system_prompt (str): System instructions
            ioc_data (str): Formatted IOC data
            
        Returns:
            dict: AI response
        """
        try:
            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": f"IOC DATA:\n{ioc_data}"}
            ]
            
            response = openai.ChatCompletion.create(
                model=self.model,
                messages=messages,
                max_tokens=1000,
                temperature=0.3
            )
            
            response_text = response.choices[0].message.content
            
            return {
                'provider': 'openai',
                'model': self.model,
                'summary': response_text,
                'raw_response': response_text
            }
            
        except Exception as e:
            logger.error(f"OpenAI query failed: {e}")
            return {
                'error': str(e),
                'summary': 'OpenAI analysis failed',
                'provider': 'openai'
            }

# Integration function for the main pipeline
def generate_ai_summary(analysis_data: Dict[str, Any], provider="google", api_key=None) -> Dict[str, Any]:
    """
    Generate AI-powered summary for analysis results.
    
    Args:
        analysis_data (dict): Complete analysis results
        provider (str): AI provider ('google' or 'openai')
        api_key (str): API key for the provider
        
    Returns:
        dict: Analysis data with AI summary added
    """
    analyst = AIAnalyst(api_key=api_key, provider=provider)
    return analyst.analyze_critical_iocs(analysis_data)