#!/usr/bin/env python3
import os
import json
from typing import Dict, Any, Optional
from scoutsuite.core.console import set_logger_configuration
from scoutsuite.providers.aws.provider import AWS
from scoutsuite.providers.azure.provider import Azure
from scoutsuite.providers.gcp.provider import GCP
from scoutsuite.core.console import print_exception
import logging

logger = logging.getLogger(__name__)

class CloudSecurityScanner:
    def __init__(self, provider: str = 'aws'):
        self.provider = provider.lower()
        set_logger_configuration()
        
    def scan_aws(self, aws_access_key_id: str, aws_secret_access_key: str, aws_session_token: Optional[str] = None) -> Dict[str, Any]:
        """Run ScoutSuite scan for AWS"""
        try:
            aws = AWS(aws_access_key_id, aws_secret_access_key, aws_session_token)
            aws.run()
            return self._process_scoutsuite_results(aws)
        except Exception as e:
            logger.error(f"AWS scan failed: {str(e)}")
            return {'error': str(e)}

    def scan_azure(self, client_id: str, client_secret: str, tenant_id: str) -> Dict[str, Any]:
        """Run ScoutSuite scan for Azure"""
        try:
            azure = Azure(client_id, client_secret, tenant_id)
            azure.run()
            return self._process_scoutsuite_results(azure)
        except Exception as e:
            logger.error(f"Azure scan failed: {str(e)}")
            return {'error': str(e)}

    def scan_gcp(self, project_id: str, credentials_file: str) -> Dict[str, Any]:
        """Run ScoutSuite scan for GCP"""
        try:
            gcp = GCP(project_id, credentials_file)
            gcp.run()
            return self._process_scoutsuite_results(gcp)
        except Exception as e:
            logger.error(f"GCP scan failed: {str(e)}")
            return {'error': str(e)}

    def _process_scoutsuite_results(self, provider) -> Dict[str, Any]:
        """Process ScoutSuite results into a standardized format"""
        results = {
            'findings': [],
            'services': {},
            'risk_score': 0,
            'summary': {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0
            }
        }

        try:
            # Get the latest report file
            report_dir = os.path.join(os.getcwd(), 'scoutsuite-report')
            report_file = os.path.join(report_dir, f'{provider.provider_name}-{provider.account_id}.js')
            
            if not os.path.exists(report_file):
                return {'error': 'No ScoutSuite report found'}

            # Read and parse the report
            with open(report_file, 'r') as f:
                report_data = json.load(f)

            # Process findings
            for service, findings in report_data.get('findings', {}).items():
                results['services'][service] = {
                    'findings': [],
                    'risk_score': 0
                }

                for finding in findings:
                    severity = finding.get('level', 'low').lower()
                    results['summary'][severity] += 1
                    
                    finding_data = {
                        'title': finding.get('description', ''),
                        'description': finding.get('rationale', ''),
                        'severity': severity,
                        'remediation': finding.get('remediation', ''),
                        'references': finding.get('references', [])
                    }
                    
                    results['services'][service]['findings'].append(finding_data)
                    results['findings'].append(finding_data)

            # Calculate risk score
            total_findings = sum(results['summary'].values())
            if total_findings > 0:
                weights = {'critical': 40, 'high': 30, 'medium': 20, 'low': 10}
                weighted_sum = sum(results['summary'][level] * weights[level] for level in weights)
                results['risk_score'] = min(100, weighted_sum)

            return results

        except Exception as e:
            logger.error(f"Error processing ScoutSuite results: {str(e)}")
            return {'error': str(e)} 