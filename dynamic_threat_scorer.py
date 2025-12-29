# dynamic_threat_scorer.py - Dynamic Threat Scoring Engine
# Phases 4 & 5: Enrichment Logic and Weighted Scoring Model

import os
import json
import logging
import yaml
from typing import Dict, List, Any, Optional
from datetime import datetime
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

try:
    import google.genai as genai
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False

try:
    import google.genai as genai
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False

logger = logging.getLogger(__name__)

class DynamicThreatScorer:
    """
    Dynamic Threat Scoring Engine using Gemini API for evidence-based IOC analysis.
    
    Implements Phase 4 (Enrichment) and Phase 5 (Weighted Scoring) with no hardcoded IOCs.
    """

    def __init__(self, config_path: str = 'config.yaml'):
        """
        Initialize the scorer with configuration.
        
        Args:
            config_path: Path to YAML configuration file
        """
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
        
        self.gemini_api_key = self.config['apis']['gemini'].get('api_key') or os.getenv('GEMINI_API_KEY')
        
        if GEMINI_AVAILABLE and self.gemini_api_key:
            self.gemini_client = genai.Client(api_key=self.gemini_api_key)
        else:
            self.gemini_client = None
            logger.warning("Gemini API not available or key not provided")
        
        # Scoring weights
        self.weights = {
            'tor_exit': 100,
            'high_malicious': 50,  # >10 engines
            'behavioral_context': 20,
            'safe_list': -50
        }

    def score_iocs(self, iocs: List[str]) -> List[Dict[str, Any]]:
        """
        Score multiple IOCs using dynamic analysis.
        
        Args:
            iocs: List of IOC strings (IPs, domains, etc.)
            
        Returns:
            List of scoring results as JSON objects
        """
        results = []
        
        for ioc in iocs:
            try:
                result = self._analyze_ioc(ioc)
                results.append(result)
            except Exception as e:
                logger.error(f"Error analyzing IOC {ioc}: {e}")
                # Fallback to inferred intelligence
                result = self._fallback_analysis(ioc)
                results.append(result)
        
        return results

    def _analyze_ioc(self, ioc: str) -> Dict[str, Any]:
        """
        Analyze a single IOC using Gemini with built-in web search.
        
        Args:
            ioc: The IOC to analyze
            
        Returns:
            Scoring result dictionary
        """
        # Create prompt for Gemini with search capability
        prompt = self._build_analysis_prompt(ioc)
        
        # Get Gemini analysis with search enabled
        analysis = self._query_gemini_with_search(prompt)
        
        if not analysis:
            # Fallback if Gemini fails
            return self._fallback_analysis(ioc)
        
        # Parse Gemini response and calculate score
        evidence = self._parse_gemini_response(analysis)
        score_data = self._calculate_score(evidence)
        
        return {
            'ioc': ioc,
            'risk_score': score_data['score'],
            'risk_level': score_data['level'],
            'reasoning': score_data['reasoning']
        }

    def _build_analysis_prompt(self, ioc: str) -> str:
        """
        Build the analysis prompt for Gemini.
        
        Args:
            ioc: The IOC to analyze
            
        Returns:
            Complete prompt string
        """
        return f"""
You are a cybersecurity threat intelligence analyst with access to real-time web search capabilities. Analyze the following IOC (Indicator of Compromise) and provide evidence-based assessment.

IOC: {ioc}

Use your web search capabilities to gather current threat intelligence information about this IOC. Search for:
- Threat intelligence reports and databases
- Security vendor analyses
- Recent cyber attack reports
- Known malicious associations

Then determine the following evidence points:
1. Is this a confirmed Tor exit node? (Yes/No)
2. What is the abuse confidence score? (0-100, or Unknown)
3. For domains: What is the domain age? (in years, or Unknown)
4. How many antivirus engines detect this as malicious? (number, or Unknown)
5. Is this associated with behavioral indicators like ERROR logs or SQL injection? (Yes/No)
6. Is this found on verified safe-lists (Cloudflare, Google, etc.)? (Yes/No)
7. Any known threat actor associations? (brief description)

Provide your analysis in the following JSON format:
{{
    "tor_exit": true/false,
    "abuse_confidence": number or null,
    "domain_age_years": number or null,
    "malicious_detections": number or null,
    "behavioral_context": true/false,
    "safe_listed": true/false,
    "threat_actors": "string description or null"
}}

Be evidence-based. If information is not available, use your training knowledge but mark uncertain findings.
"""

    def _query_gemini_with_search(self, prompt: str) -> Optional[str]:
        """
        Query Gemini API with web search tool enabled.
        
        Args:
            prompt: The prompt to send
            
        Returns:
            Gemini response string or None if failed
        """
        if not self.gemini_client:
            return None
        
        try:
            # Enable Google Search tool
            search_tool = genai.types.Tool(
                google_search=genai.types.GoogleSearch()
            )
            
            response = self.gemini_client.models.generate_content(
                model="gemini-2.5-flash-lite",
                contents=prompt,
                config=genai.types.GenerateContentConfig(
                    tools=[search_tool]
                )
            )
            return response.text
        except Exception as e:
            logger.error(f"Gemini API error: {e}")
            return None

    def _parse_gemini_response(self, response: str) -> Dict[str, Any]:
        """
        Parse Gemini's JSON response into evidence dictionary.
        
        Args:
            response: Raw Gemini response
            
        Returns:
            Parsed evidence dictionary
        """
        try:
            # Extract JSON from response
            start = response.find('{')
            end = response.rfind('}') + 1
            if start != -1 and end != -1:
                json_str = response[start:end]
                return json.loads(json_str)
            else:
                logger.warning("No JSON found in Gemini response")
                return {}
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Gemini response: {e}")
            return {}

    def _calculate_score(self, evidence: Dict[str, Any]) -> Dict[str, Any]:
        """
        Calculate risk score based on evidence and weights.
        
        Args:
            evidence: Parsed evidence from Gemini
            
        Returns:
            Score data with score, level, and reasoning
        """
        score = 0
        reasons = []
        
        # Tor Exit Node
        if evidence.get('tor_exit', False):
            score += self.weights['tor_exit']
            reasons.append(f"Tor Exit Node (+{self.weights['tor_exit']})")
        
        # High-confidence malicious detections (>10 engines)
        detections = evidence.get('malicious_detections')
        if detections is not None and isinstance(detections, (int, float)) and detections > 10:
            score += self.weights['high_malicious']
            reasons.append(f"High malicious detections ({detections} engines, +{self.weights['high_malicious']})")
        
        # Behavioral context
        if evidence.get('behavioral_context', False):
            score += self.weights['behavioral_context']
            reasons.append(f"Behavioral context (+{self.weights['behavioral_context']})")
        
        # Safe-listed
        if evidence.get('safe_listed', False):
            score += self.weights['safe_list']
            reasons.append(f"Safe-listed ({self.weights['safe_list']})")
        
        # Determine risk level
        if score >= 100:
            level = "CRITICAL"
        elif score >= 40:
            level = "HIGH"
        elif score >= 15:
            level = "MEDIUM"
        else:
            level = "SAFE"
        
        reasoning = f"{score}: " + " + ".join(reasons) if reasons else f"{score}: No significant indicators found"
        
        return {
            'score': score,
            'level': level,
            'reasoning': reasoning
        }

    def _fallback_analysis(self, ioc: str) -> Dict[str, Any]:
        """
        Fallback analysis using Gemini's internal knowledge when APIs fail.
        
        Args:
            ioc: The IOC to analyze
            
        Returns:
            Fallback scoring result
        """
        prompt = f"""
You are a cybersecurity analyst. Provide a best-effort assessment of IOC: {ioc}
Based on your training knowledge, estimate threat indicators.

Return JSON:
{{
    "estimated_risk_score": number,
    "estimated_risk_level": "CRITICAL|HIGH|MEDIUM|SAFE",
    "reasoning": "string explaining estimate",
    "inferred": true
}}
"""
        
        response = self._query_gemini_with_search(prompt)
        
        if response:
            try:
                data = json.loads(response)
                return {
                    'ioc': ioc,
                    'risk_score': data.get('estimated_risk_score', 0),
                    'risk_level': data.get('estimated_risk_level', 'UNKNOWN'),
                    'reasoning': f"Inferred Intelligence: {data.get('reasoning', 'Unable to assess')}"
                }
            except:
                pass
        
        # Ultimate fallback
        return {
            'ioc': ioc,
            'risk_score': 0,
            'risk_level': 'UNKNOWN',
            'reasoning': 'Inferred Intelligence: Unable to assess - APIs unavailable'
        }


def main():
    """
    Main function for command-line usage.
    """
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python dynamic_threat_scorer.py <ioc1> <ioc2> ...")
        sys.exit(1)
    
    iocs = sys.argv[1:]
    
    scorer = DynamicThreatScorer()
    results = scorer.score_iocs(iocs)
    
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()