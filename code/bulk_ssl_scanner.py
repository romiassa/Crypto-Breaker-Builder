#!/usr/bin/env python3
"""
Bulk SSL/TLS Scanner Module - FIXED VERSION
Scans multiple domains for SSL/TLS configuration and vulnerabilities
Author: CryptoTool
"""

import ssl
import socket
import json
import concurrent.futures
import argparse
import sys
import os
from datetime import datetime, timedelta
import logging
from typing import Dict, List, Any, Optional
import time

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class BulkSSLScanner:
    """Bulk SSL/TLS scanner for multiple domains - FIXED VERSION"""
    
    def __init__(self, max_workers: int = 10, timeout: int = 10):
        """
        Initialize the SSL scanner
        
        Args:
            max_workers: Maximum number of concurrent scans
            timeout: Connection timeout in seconds
        """
        self.max_workers = max_workers
        self.timeout = timeout
        self.results = {}
        
        # Weak ciphers to flag
        self.WEAK_CIPHERS = {
            'RC4', 'DES', '3DES', 'MD5', 'SHA1', 'EXPORT', 'NULL', 'ANON',
            'ADH', 'AECDH', 'CBC', 'CAMELLIA', 'SEED', 'IDEA', 'PSK'
        }
        
        # Vulnerable protocols
        self.VULNERABLE_PROTOCOLS = {
            'SSLv3': 'POODLE vulnerability',
            'TLSv1': 'Deprecated, BEAST vulnerability',
            'TLSv1.1': 'Should be disabled in favor of TLS 1.2+'
        }
        
        logger.info(f"SSL Scanner initialized with {max_workers} workers, timeout: {timeout}s")
    
    def scan_domain(self, domain: str) -> Dict[str, Any]:
        """
        Scan a single domain for SSL/TLS configuration - FIXED VERSION
        
        Args:
            domain: Domain name to scan
        
        Returns:
            Dictionary with scan results
        """
        result = {
            "domain": domain,
            "success": False,
            "scan_time": datetime.now().isoformat(),
            "error": None
        }
        
        try:
            # Clean domain (remove http:// or https://)
            domain = domain.replace('http://', '').replace('https://', '').split('/')[0]
            
            logger.info(f"Scanning SSL/TLS for: {domain}")
            
            # Get certificate using simple method
            cert_info = self._get_certificate_simple(domain)
            if cert_info:
                result.update(cert_info)
            
            # Get supported protocols (simplified)
            protocols = self._test_protocols_simple(domain)
            result["protocols"] = protocols
            
            # Get cipher info
            cipher_info = self._get_cipher_info(domain)
            if cipher_info:
                result["cipher"] = cipher_info
            
            # Perform security assessment
            assessment = self._assess_security_simple(protocols, cert_info)
            result["security_assessment"] = assessment
            
            # Calculate overall score
            result["security_score"] = self._calculate_security_score_simple(assessment, cert_info)
            
            result["success"] = True
            
            logger.info(f"Completed scan for {domain}: Score {result['security_score']}/100")
            
        except Exception as e:
            error_msg = str(e)
            result["error"] = error_msg
            logger.warning(f"Failed to scan {domain}: {error_msg}")
        
        return result
    
    def _get_certificate_simple(self, domain: str) -> Optional[Dict[str, Any]]:
        """Retrieve SSL certificate information - SIMPLIFIED WORKING VERSION"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((domain, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    # Get certificate info
                    cert = ssock.getpeercert()
                    
                    if cert:
                        # Parse certificate info
                        subject = {}
                        if 'subject' in cert:
                            for item in cert['subject']:
                                for key, value in item:
                                    subject[key] = value
                        
                        issuer = {}
                        if 'issuer' in cert:
                            for item in cert['issuer']:
                                for key, value in item:
                                    issuer[key] = value
                        
                        # Get validity dates
                        not_before = cert.get('notBefore', '')
                        not_after = cert.get('notAfter', '')
                        
                        # Calculate days remaining
                        days_remaining = 0
                        if not_after:
                            try:
                                # Parse date: "Dec  4 12:00:00 2024 GMT"
                                expiry_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                                days_remaining = (expiry_date - datetime.now()).days
                            except:
                                days_remaining = 0
                        
                        return {
                            "certificate_info": {
                                "subject": subject,
                                "issuer": issuer,
                                "valid_from": not_before,
                                "valid_to": not_after,
                                "days_remaining": days_remaining,
                                "version": cert.get('version', ''),
                            }
                        }
                    
        except Exception as e:
            logger.warning(f"Could not retrieve certificate for {domain}: {e}")
            return None
        
        return None
    
    def _test_protocols_simple(self, domain: str) -> Dict[str, bool]:
        """Test which SSL/TLS protocols are supported - SIMPLIFIED"""
        protocols = {
            'TLSv1': False,
            'TLSv1.1': False,
            'TLSv1.2': False,
            'TLSv1.3': False
        }
        
        # Test each protocol
        for proto_name in protocols.keys():
            try:
                # Create context for specific protocol
                context = ssl.create_default_context()
                
                # Set minimum/maximum version
                if proto_name == 'TLSv1':
                    context.minimum_version = ssl.TLSVersion.TLSv1
                    context.maximum_version = ssl.TLSVersion.TLSv1
                elif proto_name == 'TLSv1.1':
                    context.minimum_version = ssl.TLSVersion.TLSv1_1
                    context.maximum_version = ssl.TLSVersion.TLSv1_1
                elif proto_name == 'TLSv1.2':
                    context.minimum_version = ssl.TLSVersion.TLSv1_2
                    context.maximum_version = ssl.TLSVersion.TLSv1_2
                elif proto_name == 'TLSv1.3':
                    context.minimum_version = ssl.TLSVersion.TLSv1_3
                    context.maximum_version = ssl.TLSVersion.TLSv1_3
                
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((domain, 443), timeout=self.timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=domain) as ssock:
                        # If connection succeeds, protocol is supported
                        actual_version = ssock.version()
                        protocols[proto_name] = True
                        
            except:
                protocols[proto_name] = False
        
        return protocols
    
    def _get_cipher_info(self, domain: str) -> Optional[Dict[str, str]]:
        """Get cipher suite information"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((domain, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cipher = ssock.cipher()
                    if cipher:
                        return {
                            "name": cipher[0],
                            "version": cipher[1],
                            "bits": cipher[2],
                            "description": f"{cipher[0]} ({cipher[1]}, {cipher[2]} bits)"
                        }
        except Exception as e:
            logger.warning(f"Could not get cipher for {domain}: {e}")
        
        return None
    
    def _assess_security_simple(self, protocols: Dict[str, bool], 
                               cert_info: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Perform simplified security assessment"""
        assessment = {
            "issues": [],
            "warnings": [],
            "recommendations": [],
            "vulnerabilities": []
        }
        
        # Check protocols
        for protocol, enabled in protocols.items():
            if enabled and protocol in self.VULNERABLE_PROTOCOLS:
                assessment["vulnerabilities"].append({
                    "protocol": protocol,
                    "risk": "MEDIUM",
                    "description": self.VULNERABLE_PROTOCOLS[protocol]
                })
        
        # Check for TLS 1.3 (good)
        if protocols.get('TLSv1.3'):
            assessment["recommendations"].append("TLS 1.3 is enabled (excellent)")
        else:
            assessment["issues"].append("TLS 1.3 not enabled")
        
        # Check certificate validity
        if cert_info and "certificate_info" in cert_info:
            cert = cert_info["certificate_info"]
            days_remaining = cert.get("days_remaining", 0)
            
            if days_remaining < 0:
                assessment["vulnerabilities"].append({
                    "issue": "EXPIRED_CERTIFICATE",
                    "risk": "CRITICAL",
                    "description": f"Certificate expired {abs(days_remaining)} days ago"
                })
            elif days_remaining < 30:
                assessment["warnings"].append(f"Certificate expires in {days_remaining} days")
            elif days_remaining > 365 * 2:
                assessment["issues"].append(f"Certificate validity too long: {days_remaining} days")
        
        return assessment
    
    def _calculate_security_score_simple(self, assessment: Dict[str, Any], 
                                       cert_info: Optional[Dict[str, Any]]) -> int:
        """Calculate overall security score (0-100)"""
        score = 100
        
        # Deduct for vulnerabilities
        for vuln in assessment.get("vulnerabilities", []):
            risk = vuln.get("risk", "MEDIUM")
            if risk == "CRITICAL":
                score -= 30
            elif risk == "HIGH":
                score -= 20
            elif risk == "MEDIUM":
                score -= 10
            else:
                score -= 5
        
        # Deduct for issues
        score -= len(assessment.get("issues", [])) * 5
        
        # Deduct for warnings
        score -= len(assessment.get("warnings", [])) * 2
        
        # Bonus for recommendations
        score += len(assessment.get("recommendations", [])) * 2
        
        # Bonus for TLS 1.3
        if "TLS 1.3 is enabled" in assessment.get("recommendations", []):
            score += 10
        
        return max(0, min(100, score))
    
    def scan_bulk(self, domains: List[str]) -> Dict[str, Any]:
        """
        Scan multiple domains in parallel
        
        Args:
            domains: List of domain names
        
        Returns:
            Dictionary with all scan results
        """
        all_results = {
            "scan_time": datetime.now().isoformat(),
            "total_domains": len(domains),
            "scanned_domains": 0,
            "successful_scans": 0,
            "failed_scans": 0,
            "results": [],
            "summary": {
                "security_scores": {},
                "critical_issues": [],
                "recommendations": []
            }
        }
        
        logger.info(f"Starting bulk scan of {len(domains)} domains...")
        
        # Scan domains in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_domain = {executor.submit(self.scan_domain, domain): domain 
                              for domain in domains}
            
            for future in concurrent.futures.as_completed(future_to_domain):
                domain = future_to_domain[future]
                try:
                    result = future.result(timeout=self.timeout + 5)
                    all_results["results"].append(result)
                    
                    if result["success"]:
                        all_results["successful_scans"] += 1
                        
                        # Update summary
                        score = result.get("security_score", 0)
                        all_results["summary"]["security_scores"][domain] = score
                        
                        # Collect critical issues
                        for vuln in result.get("security_assessment", {}).get("vulnerabilities", []):
                            if vuln.get("risk") in ["CRITICAL", "HIGH"]:
                                all_results["summary"]["critical_issues"].append({
                                    "domain": domain,
                                    "issue": vuln.get("issue", "Unknown"),
                                    "risk": vuln.get("risk"),
                                    "description": vuln.get("description", "")
                                })
                        
                        # Collect recommendations
                        for rec in result.get("security_assessment", {}).get("recommendations", []):
                            all_results["summary"]["recommendations"].append({
                                "domain": domain,
                                "recommendation": rec
                            })
                        
                    else:
                        all_results["failed_scans"] += 1
                        
                except Exception as e:
                    logger.error(f"Exception scanning {domain}: {e}")
                    all_results["failed_scans"] += 1
        
        all_results["scanned_domains"] = len(all_results["results"])
        
        # Generate overall statistics
        if all_results["successful_scans"] > 0:
            scores = [r.get("security_score", 0) for r in all_results["results"] if r["success"]]
            if scores:
                all_results["summary"]["average_score"] = sum(scores) / len(scores)
                all_results["summary"]["min_score"] = min(scores)
                all_results["summary"]["max_score"] = max(scores)
                
                # Categorize by score
                categories = {
                    "excellent": [s for s in scores if s >= 90],
                    "good": [s for s in scores if 70 <= s < 90],
                    "fair": [s for s in scores if 50 <= s < 70],
                    "poor": [s for s in scores if s < 50]
                }
                all_results["summary"]["score_distribution"] = {
                    cat: len(scores_list) for cat, scores_list in categories.items()
                }
        
        logger.info(f"Bulk scan completed: {all_results['successful_scans']} successful, "
                   f"{all_results['failed_scans']} failed")
        
        return all_results
    
    def generate_report(self, results: Dict[str, Any], 
                       output_format: str = "json") -> str:
        """
        Generate a report from scan results
        
        Args:
            results: Scan results dictionary
            output_format: Report format (json, csv, text)
        
        Returns:
            Report string
        """
        if output_format == "json":
            return json.dumps(results, indent=2)
        
        elif output_format == "csv":
            output = []
            # Header
            output.append("Domain,Success,Security Score,Issues,Vulnerabilities,Warnings,Recommendations")
            
            for result in results.get("results", []):
                domain = result.get("domain", "")
                success = "Yes" if result.get("success") else "No"
                score = result.get("security_score", 0)
                
                assessment = result.get("security_assessment", {})
                issues = len(assessment.get("issues", []))
                vulns = len(assessment.get("vulnerabilities", []))
                warnings = len(assessment.get("warnings", []))
                recs = len(assessment.get("recommendations", []))
                
                output.append(f'{domain},{success},{score},{issues},{vulns},{warnings},{recs}')
            
            return "\n".join(output)
        
        elif output_format == "text":
            output = []
            output.append("=" * 80)
            output.append("BULK SSL/TLS SCAN REPORT")
            output.append("=" * 80)
            output.append(f"Scan Time: {results.get('scan_time')}")
            output.append(f"Total Domains: {results.get('total_domains')}")
            output.append(f"Successful: {results.get('successful_scans')}")
            output.append(f"Failed: {results.get('failed_scans')}")
            output.append("")
            
            if "summary" in results:
                summary = results["summary"]
                if "average_score" in summary:
                    output.append(f"Average Security Score: {summary['average_score']:.1f}/100")
                    output.append(f"Best Score: {summary.get('max_score', 0)}")
                    output.append(f"Worst Score: {summary.get('min_score', 0)}")
                    output.append("")
                
                if "score_distribution" in summary:
                    output.append("Score Distribution:")
                    for category, count in summary["score_distribution"].items():
                        output.append(f"  {category.title()}: {count}")
                    output.append("")
                
                if summary.get("critical_issues"):
                    output.append("CRITICAL ISSUES FOUND:")
                    for issue in summary["critical_issues"][:5]:
                        output.append(f"  • {issue['domain']}: {issue['issue']} ({issue['risk']})")
                    output.append("")
            
            output.append("DETAILED RESULTS:")
            output.append("-" * 80)
            
            for result in results.get("results", []):
                if result.get("success"):
                    output.append(f"\nDomain: {result.get('domain')}")
                    output.append(f"Security Score: {result.get('security_score')}/100")
                    
                    if result.get("certificate_info"):
                        cert = result["certificate_info"].get("certificate_info", {})
                        if cert.get("days_remaining"):
                            output.append(f"Certificate expires in: {cert['days_remaining']} days")
                    
                    assessment = result.get("security_assessment", {})
                    if assessment.get("vulnerabilities"):
                        output.append("Vulnerabilities:")
                        for vuln in assessment["vulnerabilities"]:
                            output.append(f"  - {vuln.get('issue', 'Unknown')} ({vuln.get('risk', 'Unknown')})")
                    
                    output.append("-" * 40)
            
            return "\n".join(output)
        
        else:
            return f"Unsupported format: {output_format}"


