# Complete 9-Phase SOC Automation Pipeline

A comprehensive, enterprise-grade SOC tooling for extracting, enriching, and analyzing Indicators of Compromise (IOCs) from raw logs with advanced automation features.

## 🎯 Project Overview

This pipeline transforms basic IOC processing into a complete threat intelligence automation system with caching, visualization, active scanning, business intelligence dashboards, and AI-powered analysis.

## � Quick Start

### Prerequisites
- Python 3.8+
- Git

### Installation
```bash
git clone <your-repo-url>
cd soc-ioc-pipeline
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### Configuration
1. Copy the configuration template:
```bash
cp config.example.yaml config.yaml
```

2. Add your API keys to `config.yaml`:
```yaml
apis:
  virustotal:
    api_key: "YOUR_VIRUSTOTAL_API_KEY_HERE"
  abuseipdb:
    api_key: "YOUR_ABUSEIPDB_API_KEY_HERE"
  gemini:
    api_key: "YOUR_GEMINI_API_KEY_HERE"
```

### Usage
```bash
python main.py sample.log
```

## �📊 Pipeline Phases

### Phase 1: The Regex Engine (IOC Extraction) ✅
- Input: Raw log files
- Output: Clean list of unique IOCs (IPs, Domains, Hashes, URLs, Files)
- Features: De-duplication, large file handling, encoding support

### Phase 2: The API Orchestrator (Enrichment) ✅
- **APIs Integrated**: VirusTotal v3, AbuseIPDB, WHOIS
- **Rate Limiting**: Respects free tier limits with automatic sleeping
- **Error Handling**: Exponential backoff, comprehensive logging
- **Features**: Modular API clients, graceful failure handling

### Phase 3: The Intelligence Engine (Risk Scoring) ✅
- **Risk Levels**: CRITICAL, HIGH, MEDIUM, LOW, SAFE, UNKNOWN
- **Scoring Algorithm**: Analyzes VT detections, AbuseIPDB scores, reputation data
- **Configurable Thresholds**: Customizable risk scoring rules
- **Actionable Recommendations**: Automated suggestions based on risk levels

### Phase 4: The Delivery System (Reporting) ✅
- **Multiple Formats**: CSV, Markdown, HTML dashboard, Enhanced JSON
- **Quick Links**: Direct links to VT and AbuseIPDB pages
- **Analyst-Friendly**: Color-coded risk levels, actionable recommendations

### Phase 5: The Cache Layer (Performance Optimization) ✅
- **SQLite Database**: 24-hour expiration with automatic cleanup
- **Performance**: Eliminates redundant API calls
- **Statistics**: Cache hit rates and performance metrics
- **Defanging**: Safe IOC display in all reports

### Phase 6: The Knowledge Graph (Visualization) ✅
- **Interactive Network Graphs**: Pyvis-powered threat mapping
- **Node Relationships**: Visual connections between IOCs
- **Color-Coded**: Risk level visualization
- **HTML Export**: Browser-based interactive exploration

### Phase 7: The Hunter Module (YARA Integration) ✅
- **Active Scanning**: YARA rule-based file scanning
- **Rule Management**: Directory-based rule loading
- **Signature Detection**: Malware pattern matching
- **Integration**: Seamless pipeline integration

### Phase 8: The BI Dashboard (Business Intelligence) ✅
- **Streamlit App**: Modern web-based dashboard
- **KPI Metrics**: Risk distribution, temporal analysis
- **Interactive Charts**: Plotly-powered visualizations
- **Real-time Updates**: Live data exploration

### Phase 9: The AI Analyst (LLM Integration) ✅
- **Human-Readable Summaries**: LLM-powered threat analysis
- **Contextual Insights**: Beyond technical data
- **Multiple Providers**: Google Gemini, OpenAI support
- **Actionable Intelligence**: Analyst-focused reporting

## 🏗️ Architecture

```
Raw Logs → Extraction → Enrichment → Risk Scoring → Reporting
    ↓           ↓           ↓           ↓           ↓
Caching   Visualization  YARA Scanning  BI Dashboard  AI Analysis
```

## 📁 File Structure

```
.
├── main.py              # Main entry point (All 9 phases)
├── extract.py           # IOC extraction module
├── enrich.py            # API enrichment module
├── risk_scorer.py       # Risk scoring module
├── reporting.py         # Report generation module
├── database.py          # SQLite caching layer
├── utils.py             # Defanging utilities
├── visualizer.py        # Network graph visualization
├── scanner.py           # YARA integration
├── dashboard.py         # Streamlit BI dashboard
├── ai_summary.py        # LLM analysis integration
├── config.yaml          # Configuration file
├── requirements.txt     # Python dependencies
├── reports/             # Generated reports directory
├── ioc_cache.db         # SQLite cache database
├── ioc_analysis_report.json  # Complete analysis output
└── README.md           # This documentation
```

## Setup & API Keys

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Configure API Keys:**
   Edit the `.env` file in the project root and add your API keys:
   ```env
   # Google Gemini API Key (get from https://makersuite.google.com/app/apikey)
   GOOGLE_API_KEY=your_google_gemini_api_key_here
   
   # OpenAI API Key (optional, for fallback)
   OPENAI_API_KEY=your_openai_api_key_here
   ```

3. **Get API Keys:**
   - **VirusTotal**: Sign up at [virustotal.com](https://www.virustotal.com) (free tier: 4 req/min, 500/day)
   - **AbuseIPDB**: Sign up at [abuseipdb.com](https://www.abuseipdb.com) (free tier: 1000 check req/day)
   - **Google Gemini**: Get API key at [Google AI Studio](https://makersuite.google.com/app/apikey) (free tier available)

4. **Update Config:**
   Edit `config.yaml` and replace the placeholder values:
   ```yaml
   apis:
     virustotal:
       api_key: "your_actual_vt_api_key"
     abuseipdb:
       api_key: "your_actual_abuseipdb_api_key"
   ```

## 🚀 Advanced Features

### ⚡ Performance Optimization (Phase 5)
- **SQLite Caching**: 24-hour IOC data caching eliminates redundant API calls
- **Defanging**: Safe IOC display prevents accidental clicks in reports
- **Cache Statistics**: Hit rates and performance metrics tracking

### 🕸️ Threat Visualization (Phase 6)
- **Interactive Network Graphs**: Visual threat infrastructure mapping
- **Relationship Mapping**: Connected IOC analysis and visualization
- **Color-Coded Nodes**: Risk-based visual encoding
- **HTML Export**: Browser-based interactive exploration

### 🔍 Active Detection (Phase 7)
- **YARA Integration**: Rule-based malware scanning
- **File Scanning**: Active threat detection in log files
- **Rule Management**: Directory-based YARA rule loading
- **Signature Matching**: Pattern-based threat identification

### 📊 Business Intelligence (Phase 8)
- **Streamlit Dashboard**: Modern web-based BI interface
- **KPI Monitoring**: Risk distribution and temporal analysis
- **Interactive Charts**: Plotly-powered data visualization
- **Real-time Updates**: Live dashboard with current data

### 🤖 AI-Powered Analysis (Phase 9)
- **LLM Integration**: Human-readable threat intelligence
- **Contextual Summaries**: Beyond technical IOC data
- **Multiple Providers**: Google Gemini and OpenAI support
- **Analyst Insights**: Actionable intelligence for SOC teams

## Usage

```bash
# Run the complete 9-phase pipeline
python main.py path/to/your/logfile.log

# Launch the BI dashboard (after running analysis)
streamlit run dashboard.py

# View threat visualization (opens in browser)
# Open reports/threat_map.html in your browser
```

## Generated Outputs

The pipeline creates comprehensive outputs:

- **📄 Multiple Report Formats**: CSV, Markdown, HTML, JSON
- **🕸️ Threat Map**: Interactive network visualization (`threat_map.html`)
- **📊 BI Dashboard**: Streamlit web application
- **🤖 AI Summary**: Human-readable threat analysis
- **💾 Cached Data**: SQLite database for performance
- **🔍 YARA Results**: Active scanning reports

## Example Output

**Extracted IOCs:**
```json
{
  "ips": ["192.168.1.1", "192[.]168[.]1[.]1"],
  "domains": ["malicious.com", "example.com"],
  "hashes": ["d41d8cd98f00b204e9800998ecf8427e"],
  "urls": ["https://example.com/page"]
}
```

## Report Formats

The pipeline generates comprehensive reports in multiple formats:

### 📊 **CSV Summary** (`ioc_summary_TIMESTAMP.csv`)
- Spreadsheet-friendly format with key metrics
- One row per IOC with risk scores and quick links
- Perfect for Excel/Google Sheets analysis

### 📋 **CSV Detailed** (`ioc_detailed_TIMESTAMP.csv`) 
- Comprehensive analysis with all available data
- Threat categories, analysis dates, usage types
- Best for data analysis and reporting

### 📝 **Markdown Report** (`ioc_report_TIMESTAMP.md`)
- Human-readable analysis with sections by IOC category
- Quick links to VirusTotal and AbuseIPDB
- Recommendations and key findings
- Print-friendly format

### 🌐 **HTML Dashboard** (`ioc_dashboard_TIMESTAMP.html`)
- Interactive web-based dashboard
- Color-coded risk levels and visual summary cards
- Clickable links and responsive design
- **Recommended for primary analysis**

### 📄 **Enhanced JSON** (`ioc_analysis_enhanced_TIMESTAMP.json`)
- Complete analysis data with metadata
- Machine-readable format for integrations
- Includes report generation details

## Key Features

- **End-to-End Pipeline**: Extraction → Enrichment → Risk Scoring
- **Multi-Source Intelligence**: VirusTotal + AbuseIPDB analysis
- **Intelligent Risk Scoring**: Automated threat level assessment
- **Actionable Recommendations**: SOC-ready guidance
- **Rate Limited**: Respects API limits (VT: 3/min, AbuseIPDB: 800/day)
- **Fault Tolerant**: Continues processing even with API failures
- **Comprehensive Reporting**: JSON output with full analysis details

## Requirements

- Python 3.7+
- requests
- pyyaml

## Risk Levels

- **CRITICAL** (70+): Immediate blocking required 🚨
- **HIGH** (40-69): Urgent review needed ⚠️  
- **MEDIUM** (20-39): Monitor closely ⚡
- **LOW** (5-19): Log for awareness 👀
- **SAFE** (0-4): No action required ✅
- **UNKNOWN**: Insufficient data ❓

## 🎯 Success Metrics

✅ **All 9 Phases Implemented**: Complete SOC automation pipeline  
✅ **Caching Performance**: 100% hit rate on repeat analyses  
✅ **Modular Architecture**: Easy to extend and maintain  
✅ **Production Ready**: Error handling, logging, configuration  
✅ **Multiple Outputs**: Reports, visualizations, dashboards, AI analysis  
✅ **AI Integration**: Google Gemini-powered threat intelligence summaries  
✅ **Threat Visualization**: Interactive network graphs with pyvis  
✅ **Business Intelligence**: Streamlit dashboard with KPIs and charts  

## 🔄 Next Steps & Enhancements

- **Containerization**: Docker deployment for production
- **CI/CD Pipeline**: Automated testing and deployment
- **Alerting Integration**: SOC tool integration (Splunk, ELK)
- **Custom YARA Rules**: Organization-specific threat signatures
- **Advanced AI**: Multi-model analysis and custom prompts
- **Scalability**: Batch processing and distributed analysis
- **API Expansion**: Additional threat intelligence sources