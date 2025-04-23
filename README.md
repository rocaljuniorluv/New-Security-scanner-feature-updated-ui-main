# Enhanced Attack Surface Assessment Tool

A comprehensive security assessment tool that performs passive reconnaissance and security checks on websites and email addresses. The tool is designed to be non-intrusive while providing detailed security insights.

## Features

### Website Security Assessment
- **Network Security**
  - Passive DNS analysis
  - WHOIS information gathering
  - IP reputation checking
  - ASN information collection
  - Passive port and service enumeration via Shodan

- **DNS Health Assessment**
  - DNSSEC validation
  - DNS record analysis
  - Security record validation (SPF, DMARC, DKIM)
  - DNS misconfiguration detection

- **Endpoint Security**
  - OS fingerprinting (passive)
  - Security headers analysis
  - Server information gathering
  - Security misconfiguration detection

- **Vulnerability Assessment**
  - Common vulnerability checks (passive)
  - Security misconfiguration detection
  - Sensitive file exposure checks
  - Web application security analysis
  - Risk scoring and prioritization
  - Exploitability assessment
  - Impact analysis
  - Remediation tracking
  - Performance metrics (MTTD/MTTR)

- **Risk Analysis**
  - Severity-based scoring
  - Exploitability assessment
  - Impact analysis
  - Risk trend tracking
  - Historical data analysis
  - Remediation prioritization
  - Team responsibility assignment

- **Additional Security Checks**
  - SSL/TLS security
  - Cloud security
  - API security
  - Container security
  - Database security
  - Patching status

### Email Security Assessment
- **Email Validation**
  - Format validation
  - Domain validation
  - MX record checking

- **Domain Security**
  - SPF record validation
  - DMARC record checking
  - DKIM record verification
  - MX record analysis

- **Server Configuration**
  - STARTTLS support checking
  - SMTP authentication testing
  - Server security headers analysis

- **Security Headers**
  - Received headers analysis
  - SPF validation headers
  - Authentication results checking

- **Server Reputation**
  - IP reputation via VirusTotal
  - Domain reputation analysis
  - Historical data tracking

- **Security Best Practices**
  - SPF implementation check
  - DMARC implementation check
  - DKIM implementation check
  - STARTTLS support verification
  - SMTP authentication requirements

- **Phishing Risk Assessment**
  - Risk score calculation
  - Risk factor identification
  - Security gap analysis

### Slack Integration
- **Commands**
  - `/scan [domain]` - Scan a website
  - `/scan --email [email]` - Scan an email address
  - `/scan [domain] --email [email]` - Scan both website and email
  - `/scan --profile [quick|standard|comprehensive]` - Specify scan profile

- **Features**
  - Real-time scan status updates
  - Detailed security reports
  - Team collaboration
  - Historical data tracking
  - Custom scan profiles

## Architecture

The tool is built with a modern microservices architecture:

1. **Security Scanner API**
   - FastAPI-based REST API
   - Handles all security scanning logic
   - Exposes endpoints for scan requests
   - Manages historical data storage
   - Vulnerability tracking and analysis
   - Risk assessment engine
   - Performance metrics tracking

2. **Slack Bot**
   - User-friendly interface
   - Makes API calls to scanner service
   - Formats and delivers results
   - Handles user interactions
   - Real-time vulnerability alerts
   - Remediation status updates

## Prerequisites

- Python 3.8+
- Slack workspace with admin access
- Required API keys:
  - VirusTotal API key
  - Slack Bot Token
  - Slack App Token
  - Shodan API key (for passive reconnaissance)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/FavessssN/Security-scanner.git
cd Security-scanner
```

2. Create and activate a virtual environment:
```bash
python -m venv venv
source venv/bin/activate.ps1  # On Windows: venv\Scripts\activate.ps1
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Set up environment variables:
```bash
cp .env.example .env
# Edit .env with your API keys and configuration
```

## Usage

### Starting the Services

1. Start the Security Scanner API:
```bash
python security_scanner.py
```

2. Start the Slack Bot:
```bash
python slack_bot.py
```

### Using the Slack Bot

1. Invite the bot to your Slack channel
2. Use the following commands:
   ```
   /scan example.com
   /scan --email user@example.com
   /scan example.com --email user@example.com
   /scan example.com --profile comprehensive
   /scan example.com --vuln-report  # Get detailed vulnerability report
   /scan example.com --risk-score   # Get current risk score
   /scan example.com --remediation  # Get remediation status
   ```

### API Usage

The scanner can be used via API calls:

```bash
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{
    "target": "example.com",
    "email": "user@example.com",
    "profile": "standard",
    "vuln_assessment": true,
    "risk_analysis": true
  }'
```

## Output

The tool provides comprehensive reports in multiple formats:

1. **Console Output**
   - Rich text formatting
   - Color-coded results
   - Detailed findings
   - Risk scores and trends
   - Remediation recommendations

2. **Slack Messages**
   - Formatted security reports
   - Real-time updates
   - Interactive elements
   - Vulnerability alerts
   - Remediation status

3. **Historical Data**
   - SQLite database storage
   - Trend analysis
   - Asset tracking
   - Vulnerability history
   - Risk score progression

4. **Asset Inventory**
   - Discovered assets
   - Risk levels
   - Security status
   - Vulnerability mapping
   - Remediation status

5. **Compliance Reports**
   - PCI DSS
   - HIPAA
   - GDPR
   - Vulnerability metrics
   - Risk assessment

6. **Vulnerability Reports**
   - Detailed vulnerability findings
   - Risk scores and impact analysis
   - Remediation recommendations
   - Team assignments
   - Timeline estimates

7. **Performance Metrics**
   - Mean Time to Detect (MTTD)
   - Mean Time to Remediate (MTTR)
   - Vulnerability distribution
   - Risk score trends
   - Remediation effectiveness

## Security Notes

- The tool performs passive reconnaissance only
- No active exploitation or intrusive scanning
- Respects rate limits and security policies
- Uses only publicly available information
- Safe for production environments
- No port scanning or active service enumeration
- Relies on public data sources and APIs
- Non-intrusive vulnerability assessment
- Safe testing methods

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- VirusTotal for IP reputation data
- Slack for bot integration
- Shodan for passive reconnaissance data
- Various security tools and libraries
- OWASP for vulnerability guidance
- MITRE ATT&CK for threat modeling 
