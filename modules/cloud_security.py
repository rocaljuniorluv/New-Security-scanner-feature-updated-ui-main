#!/usr/bin/env python3
import os
import json
import asyncio
from typing import Dict, Any, List, Optional
from pathlib import Path
from ScoutSuite.core.console import set_logger_configuration
from ScoutSuite.providers.aws.provider import AWS
from ScoutSuite.providers.azure.provider import Azure
from ScoutSuite.providers.gcp.provider import GCP
from ScoutSuite.output.html import ScoutSuiteReport
from ScoutSuite.output.js import ScoutSuiteJS
from ScoutSuite.output.excel import ScoutSuiteExcel
from ScoutSuite.output.json import ScoutSuiteJSON

class CloudSecurityScanner:
    def __init__(self):
        self.logger = set_logger_configuration()
        self.results_dir = Path('results/cloud_security')
        self.results_dir.mkdir(parents=True, exist_ok=True)
        
    async def scan_aws(self, aws_access_key: str, aws_secret_key: str, aws_session_token: Optional[str] = None) -> Dict[str, Any]:
        """Scan AWS infrastructure"""
        try:
            # Initialize AWS provider
            aws = AWS(
                aws_access_key_id=aws_access_key,
                aws_secret_access_key=aws_secret_key,
                aws_session_token=aws_session_token
            )
            
            # Run ScoutSuite scan
            aws.run()
            
            # Generate reports
            report_path = self.results_dir / 'aws'
            report_path.mkdir(exist_ok=True)
            
            # Generate HTML report
            ScoutSuiteReport(aws, report_path / 'report.html')
            
            # Generate JSON report
            ScoutSuiteJSON(aws, report_path / 'report.json')
            
            # Generate Excel report
            ScoutSuiteExcel(aws, report_path / 'report.xlsx')
            
            # Load results
            with open(report_path / 'report.json', 'r') as f:
                results = json.load(f)
                
            return {
                'provider': 'aws',
                'status': 'success',
                'results': results
            }
            
        except Exception as e:
            self.logger.error(f"AWS scan error: {str(e)}")
            return {
                'provider': 'aws',
                'status': 'error',
                'error': str(e)
            }
            
    async def scan_azure(self, tenant_id: str, client_id: str, client_secret: str) -> Dict[str, Any]:
        """Scan Azure infrastructure"""
        try:
            # Initialize Azure provider
            azure = Azure(
                tenant_id=tenant_id,
                client_id=client_id,
                client_secret=client_secret
            )
            
            # Run ScoutSuite scan
            azure.run()
            
            # Generate reports
            report_path = self.results_dir / 'azure'
            report_path.mkdir(exist_ok=True)
            
            # Generate HTML report
            ScoutSuiteReport(azure, report_path / 'report.html')
            
            # Generate JSON report
            ScoutSuiteJSON(azure, report_path / 'report.json')
            
            # Generate Excel report
            ScoutSuiteExcel(azure, report_path / 'report.xlsx')
            
            # Load results
            with open(report_path / 'report.json', 'r') as f:
                results = json.load(f)
                
            return {
                'provider': 'azure',
                'status': 'success',
                'results': results
            }
            
        except Exception as e:
            self.logger.error(f"Azure scan error: {str(e)}")
            return {
                'provider': 'azure',
                'status': 'error',
                'error': str(e)
            }
            
    async def scan_gcp(self, project_id: str, credentials_file: str) -> Dict[str, Any]:
        """Scan GCP infrastructure"""
        try:
            # Initialize GCP provider
            gcp = GCP(
                project_id=project_id,
                credentials_file=credentials_file
            )
            
            # Run ScoutSuite scan
            gcp.run()
            
            # Generate reports
            report_path = self.results_dir / 'gcp'
            report_path.mkdir(exist_ok=True)
            
            # Generate HTML report
            ScoutSuiteReport(gcp, report_path / 'report.html')
            
            # Generate JSON report
            ScoutSuiteJSON(gcp, report_path / 'report.json')
            
            # Generate Excel report
            ScoutSuiteExcel(gcp, report_path / 'report.xlsx')
            
            # Load results
            with open(report_path / 'report.json', 'r') as f:
                results = json.load(f)
                
            return {
                'provider': 'gcp',
                'status': 'success',
                'results': results
            }
            
        except Exception as e:
            self.logger.error(f"GCP scan error: {str(e)}")
            return {
                'provider': 'gcp',
                'status': 'error',
                'error': str(e)
            }
            
    async def scan_all(self, 
                      aws_creds: Optional[Dict[str, str]] = None,
                      azure_creds: Optional[Dict[str, str]] = None,
                      gcp_creds: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """Scan all configured cloud providers"""
        results = {}
        
        if aws_creds:
            results['aws'] = await self.scan_aws(
                aws_creds['access_key'],
                aws_creds['secret_key'],
                aws_creds.get('session_token')
            )
            
        if azure_creds:
            results['azure'] = await self.scan_azure(
                azure_creds['tenant_id'],
                azure_creds['client_id'],
                azure_creds['client_secret']
            )
            
        if gcp_creds:
            results['gcp'] = await self.scan_gcp(
                gcp_creds['project_id'],
                gcp_creds['credentials_file']
            )
            
        return results 