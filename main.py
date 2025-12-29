#!/usr/bin/env python3
"""
Main entry point for the IOC Extraction and Enrichment Pipeline.
Complete 9-Phase SOC Automation Pipeline:

Phase 1: Regex Engine (IOC Extraction)
Phase 2: API Orchestrator (IOC Enrichment)
Phase 3: Risk Scoring Engine
Phase 3.5: Dynamic Threat Scoring (Gemini)
Phase 4: Report Generation
Phase 5: Caching Layer (SQLite)
Phase 6: Threat Visualization (Network Graphs)
Phase 7: YARA Integration (Active Scanning)
Phase 8: Business Intelligence Dashboard (Streamlit)
Phase 9: AI-Powered Threat Analysis (LLM)

This script extracts IOCs from log files and enriches them using external APIs.
It outputs results in JSON format and saves enriched data to file.

Usage:
    python main.py <log_file_path>
    
Example:
    python main.py firewall.log
"""

import sys
import json
import os
import yaml
import datetime
from extract import Extractor
from enrich import APIOrchestrator
from risk_scorer import RiskScorer
from reporting import ReportGenerator
from database import IOCDatabase
from utils import defang_ioc
from visualizer import ThreatVisualizer
from scanner import YARAScanner
from ai_summary import generate_ai_summary
from dynamic_threat_scorer import DynamicThreatScorer

def _display_risk_summary(scored_data):
    """
    Display a summary of risk analysis results.
    
    Args:
        scored_data (dict): Risk scoring results
    """
    print("\n" + "="*60)
    print("🎯 RISK ANALYSIS SUMMARY")
    print("="*60)
    
    risk_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'SAFE': 0, 'UNKNOWN': 0}
    total_iocs = 0
    
    for category, iocs in scored_data.items():
        print(f"\n📁 {category.upper()}:")
        for ioc, analysis in iocs.items():
            risk_level = analysis.get('risk_level', 'UNKNOWN')
            risk_score = analysis.get('risk_score', 0)
            
            risk_counts[risk_level] += 1
            total_iocs += 1
            
            # Color coding for risk levels
            if risk_level == 'CRITICAL':
                icon = '🚨'
                color = '🔴'
            elif risk_level == 'HIGH':
                icon = '⚠️'
                color = '🟠'
            elif risk_level == 'MEDIUM':
                icon = '⚡'
                color = '🟡'
            elif risk_level == 'LOW':
                icon = '👀'
                color = '🟢'
            elif risk_level == 'SAFE':
                icon = '✅'
                color = '🟢'
            else:
                icon = '❓'
                color = '⚪'
            
            print(f"  {icon} {ioc} - {color} {risk_level} (Score: {risk_score})")
            
            # Show key findings
            vt_malicious = analysis.get('analysis', {}).get('virustotal', {}).get('malicious_detections', 0)
            abuse_score = analysis.get('analysis', {}).get('abuseipdb', {}).get('abuse_confidence_score', 0)
            
            if vt_malicious > 0 or abuse_score > 0:
                print(f"     └─ VT Malicious: {vt_malicious}, Abuse Score: {abuse_score}")
    
    print(f"\n📊 OVERALL SUMMARY:")
    print(f"   Total IOCs Analyzed: {total_iocs}")
    for level, count in risk_counts.items():
        if count > 0:
            percentage = (count / total_iocs) * 100 if total_iocs > 0 else 0
            print(f"   {level}: {count} ({percentage:.1f}%)")
    
    print("\n💡 RECOMMENDATIONS:")
    if risk_counts['CRITICAL'] > 0:
        print("   🚨 CRITICAL IOCs detected - Immediate blocking recommended")
    if risk_counts['HIGH'] > 0:
        print("   ⚠️ HIGH risk IOCs detected - Urgent review required")
    if risk_counts['MEDIUM'] > 0:
        print("   ⚡ MEDIUM risk IOCs detected - Monitor closely")
    if risk_counts['CRITICAL'] == 0 and risk_counts['HIGH'] == 0 and risk_counts['MEDIUM'] == 0:
        print("   ✅ No high-risk IOCs detected - Continue normal monitoring")

def process_iocs_with_cache(iocs, config_path):
    """
    Process IOCs using caching to avoid redundant API calls.
    
    Args:
        iocs (dict): Extracted IOCs by category
        config_path (str): Path to configuration file
        
    Returns:
        tuple: (enriched_data, scored_data, cache_stats)
    """
    db = IOCDatabase()
    orchestrator = APIOrchestrator(config_path)
    risk_scorer = RiskScorer(config_path)
    
    enriched_data = {}
    scored_data = {}
    cache_stats = {'cached': 0, 'fresh': 0, 'total': 0}
    
    # Flatten IOCs for processing
    all_iocs = []
    for category, items in iocs.items():
        for item in items:
            all_iocs.append((item, category))
    
    cache_stats['total'] = len(all_iocs)
    
    for ioc, category in all_iocs:
        # Check cache first
        cached_result = db.get_cached_ioc(ioc)
        
        if cached_result and db.is_cache_valid(ioc):
            # Use cached data
            print(f"📋 Using cached data for {ioc}")
            cache_stats['cached'] += 1
            
            # Reconstruct the data structure
            if category not in enriched_data:
                enriched_data[category] = {}
                scored_data[category] = {}
            
            # The cached result contains the final scored data
            scored_data[category][ioc] = {
                'ioc': ioc,
                'category': category,
                'risk_level': cached_result['risk_level'],
                'risk_score': cached_result['risk_score'],
                'analysis': cached_result['analysis'],
                'recommendations': cached_result['recommendations']
            }
            
            # For enriched_data, we need to reconstruct from analysis
            enriched_data[category][ioc] = cached_result['analysis']
            
        else:
            # Process fresh data
            print(f"🔄 Processing fresh data for {ioc}")
            cache_stats['fresh'] += 1
            
            if category not in enriched_data:
                enriched_data[category] = {}
                scored_data[category] = {}
            
            # Enrich the IOC
            enrichment = orchestrator._enrich_single_ioc(ioc, category)
            enriched_data[category][ioc] = enrichment
            
            # Score the IOC
            scoring_result = risk_scorer._score_single_ioc(ioc, enrichment, category)
            scored_data[category][ioc] = scoring_result
            
            # Cache the result
            db.store_ioc_data(
                ioc=ioc,
                category=category,
                analysis_data=enrichment,
                risk_score=scoring_result['risk_score'],
                risk_level=scoring_result['risk_level'],
                recommendations=scoring_result['recommendations']
            )
    
    return enriched_data, scored_data, cache_stats

def main():
    """
    Main function to handle command-line execution.
    
    Parses arguments, runs extraction and enrichment, and saves results.
    """
    # Validate command-line arguments
    if len(sys.argv) != 2:
        print("Usage: python main.py <log_file_path>")
        print("Example: python main.py sample.log")
        sys.exit(1)
    
    # Get the log file path from command line
    log_file = sys.argv[1]
    
    # Load configuration
    config_path = 'config.yaml'
    if not os.path.exists(config_path):
        print(f"Error: Configuration file {config_path} not found")
        sys.exit(1)
    
    try:
        # Phase 1: Extract IOCs from the log file
        print("Phase 1: Extracting IOCs...")
        extractor = Extractor()
        iocs = extractor.extract(log_file)
        
        # Display extraction results
        output = {k: list(v) for k, v in iocs.items()}
        print(json.dumps(output, indent=2))
        
        # Show extraction summary
        total_iocs = sum(len(v) for v in iocs.values())
        print(f"\nExtraction Summary:")
        print(f"Total unique IOCs extracted: {total_iocs}")
        for category, items in iocs.items():
            print(f"- {category.upper()}: {len(items)}")
        
        # Phase 2 & 3: Enrich and score IOCs with caching
        print("\nPhase 2 & 3: Processing IOCs with caching...")
        enriched_data, scored_data, cache_stats = process_iocs_with_cache(iocs, config_path)
        
        print(f"\n📊 CACHE STATISTICS:")
        print(f"   Total IOCs: {cache_stats['total']}")
        print(f"   From Cache: {cache_stats['cached']}")
        print(f"   Fresh API Calls: {cache_stats['fresh']}")
        if cache_stats['total'] > 0:
            cache_hit_rate = (cache_stats['cached'] / cache_stats['total']) * 100
            print(f"   Cache Hit Rate: {cache_hit_rate:.1f}%")
        
        # Phase 3.5: Dynamic Threat Scoring with Gemini
        print("\nPhase 3.5: Dynamic Threat Scoring with Gemini...")
        all_iocs = []
        for category_iocs in iocs.values():
            all_iocs.extend(category_iocs)
        
        dynamic_scorer = DynamicThreatScorer(config_path)
        dynamic_results = dynamic_scorer.score_iocs(all_iocs)
        
        # Convert to dict for easier access
        dynamic_scored_data = {result['ioc']: result for result in dynamic_results}
        
        print(f"Dynamic scoring completed for {len(dynamic_results)} IOCs")
        
        # Phase 4: Generate comprehensive reports
        print("\nPhase 4: Generating Reports...")
        report_gen = ReportGenerator()
        
        # Create defanged versions for reports
        defanged_iocs = {}
        for category, items in output.items():
            defanged_iocs[category] = [defang_ioc(ioc) for ioc in items]
        
        report_files = report_gen.generate_all_reports({
            'extracted_iocs': output,
            'defanged_iocs': defanged_iocs,
            'enriched_data': enriched_data,
            'risk_analysis': scored_data,
            'metadata': {
                'source_file': log_file,
                'total_iocs': total_iocs,
                'generated_at': str(datetime.datetime.now()),
                'cache_stats': cache_stats
            }
        })
        
        # Phase 6: Generate threat visualization
        print("\nPhase 6: Creating Threat Visualization...")
        visualizer = ThreatVisualizer()
        threat_map_file = visualizer.create_threat_map({
            'risk_analysis': scored_data,
            'enriched_data': enriched_data
        })
        if threat_map_file:
            print(f"Threat visualization saved to: {threat_map_file}")
        
        # Phase 7: YARA scanning
        print("\nPhase 7: Performing YARA Scanning...")
        scanner = YARAScanner(rules_directory="rules")
        yara_results = scanner.scan_file(log_file)
        if yara_results:
            print(f"YARA scanning completed. Results saved to: {yara_results}")
        
        # Phase 8: Launch business intelligence dashboard
        print("\nPhase 8: Launching BI Dashboard...")
        # Note: Dashboard runs in background, user can access via browser
        
        # Phase 9: Generate AI-powered threat summary
        print("\nPhase 9: Generating AI Threat Analysis...")
        ai_result = generate_ai_summary({
            'risk_analysis': scored_data,
            'enriched_data': enriched_data,
            'cache_stats': cache_stats
        })
        if isinstance(ai_result, dict) and 'ai_analysis' in ai_result:
            ai_analysis = ai_result['ai_analysis']
            if isinstance(ai_analysis, dict) and 'summary' in ai_analysis:
                if isinstance(ai_analysis['summary'], dict):
                    ai_summary = ai_analysis['summary'].get('summary', 'AI analysis completed')
                else:
                    ai_summary = ai_analysis['summary']
            else:
                ai_summary = 'AI analysis completed'
        else:
            ai_summary = 'AI analysis failed'
        if ai_summary:
            print("AI analysis completed. Summary generated.")
            print("\n🤖 AI THREAT ANALYSIS SUMMARY:")
            print("-" * 50)
            print(ai_summary[:500] + "..." if len(ai_summary) > 500 else ai_summary)
        
        # Save comprehensive results
        output_file = 'ioc_analysis_report.json'
        with open(output_file, 'w') as f:
            json.dump({
                'extracted_iocs': output,
                'enriched_data': enriched_data,
                'risk_analysis': scored_data,
                'dynamic_threat_scoring': dynamic_results,
                'metadata': {
                    'source_file': log_file,
                    'total_iocs': total_iocs,
                    'generated_at': str(datetime.datetime.now()),
                    'report_files': report_files,
                    'threat_map': threat_map_file,
                    'yara_results': yara_results,
                    'ai_summary': ai_result.get('ai_analysis', {}).get('summary', None) if isinstance(ai_result, dict) else None
                }
            }, f, indent=2)
        
        print(f"Complete analysis saved to {output_file}")
        print("All phases complete!")
        
        # Display risk summary
        _display_risk_summary(scored_data)
        
        # Display generated reports
        print("\n" + "="*60)
        print("📄 GENERATED REPORTS")
        print("="*60)
        for report_type, file_path in report_files.items():
            print(f"📄 {report_type.upper()}: {file_path}")
        
        # Display advanced features
        print("\n" + "="*60)
        print("🚀 ADVANCED FEATURES")
        print("="*60)
        if threat_map_file:
            print(f"🕸️ THREAT VISUALIZATION: {threat_map_file}")
            print("   └─ Open in browser to explore threat relationships")
        if yara_results:
            print(f"🔍 YARA SCANNING: {yara_results}")
            print("   └─ Active malware detection results")
        print("📊 BUSINESS INTELLIGENCE DASHBOARD: Access via Streamlit")
        print("   └─ Run 'streamlit run dashboard.py' to launch")
        if ai_summary:
            print("🤖 AI THREAT ANALYSIS: Generated")
            print("   └─ Human-readable threat intelligence summary")
        
        print("\n💡 Open the HTML dashboard in your browser for the best viewing experience!")
        print("💡 Launch the BI dashboard with: streamlit run dashboard.py")
            
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()