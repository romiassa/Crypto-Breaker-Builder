#!/usr/bin/env python3
"""
Quantum Checker - Final Working Version
With correct analyze_certificate() method
"""

import socket
import ssl
from datetime import datetime
import logging
import subprocess
import re
import tempfile
import os
from typing import Dict, List, Any

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class QuantumChecker:
    """Quantum Checker - Works with analyze_certificate() method"""
    
    def __init__(self):
        self.QUANTUM_THREATS = {
            'RSA-1024': {'risk': 'CRITICAL', 'break_year': 2025},
            'RSA-2048': {'risk': 'HIGH', 'break_year': 2030},
            'RSA-3072': {'risk': 'MEDIUM', 'break_year': 2035},
            'RSA-4096': {'risk': 'MEDIUM', 'break_year': 2040},
            'ECDSA-P256': {'risk': 'HIGH', 'break_year': 2027},
            'ECDSA-P384': {'risk': 'MEDIUM', 'break_year': 2032},
            'SHA1': {'risk': 'CRITICAL', 'break_year': 'Already broken'},
            'MD5': {'risk': 'CRITICAL', 'break_year': 'Already broken'},
        }
        logger.info("Quantum Checker initialized with analyze_certificate() method")
    
    def analyze_certificate(self, domain: str) -> dict:
        """
        Analyze certificate for quantum vulnerabilities
        This method exists to match the expected interface
        """
        result = {
            "domain": domain,
            "analysis_time": datetime.now().isoformat(),
            "certificate_info": {},
            "quantum_vulnerabilities": [],
            "risk_assessment": {},
            "recommendations": [],
            "success": False
        }
        
        try:
            logger.info(f"Starting quantum analysis for: {domain}")
            
            # Clean the domain
            clean_domain = self._clean_domain(domain)
            
            # Step 1: Check if domain exists via DNS
            dns_check = self._check_dns(clean_domain)
            if not dns_check["success"]:
                result["error"] = dns_check["error"]
                result["recommendations"] = ["Check domain spelling", "Verify internet connection"]
                return result
            
            # Step 2: Try to connect via SSL/TLS
            ssl_info = self._connect_ssl(clean_domain)
            
            if ssl_info["connected"]:
                result["certificate_info"] = ssl_info
                result["success"] = True
                
                # Analyze quantum vulnerabilities
                vulnerabilities = self._find_vulnerabilities(ssl_info)
                result["quantum_vulnerabilities"] = vulnerabilities
                
                # Risk assessment
                risk = self._assess_risk(vulnerabilities, ssl_info)
                result["risk_assessment"] = risk
                
                # Generate recommendations
                recommendations = self._generate_recommendations(vulnerabilities, risk, ssl_info)
                result["recommendations"] = recommendations
                
                logger.info(f"✅ Quantum analysis completed for {clean_domain}")
            else:
                result["error"] = ssl_info.get("error", "SSL connection failed")
                result["recommendations"] = self._get_connection_failed_recommendations(clean_domain)
                
        except Exception as e:
            result["error"] = f"Analysis error: {str(e)}"
            logger.error(f"Quantum analysis failed: {e}")
        
        return result
    
    def _clean_domain(self, domain: str) -> str:
        """Clean domain string"""
        domain = str(domain).strip()
        
        # Remove protocol
        if domain.startswith(('http://', 'https://')):
            domain = domain.split('://')[1]
        
        # Remove path and port
        domain = domain.split('/')[0]
        domain = domain.split(':')[0]
        
        return domain.lower()
    
    def _check_dns(self, domain: str) -> Dict[str, Any]:
        """Check if domain exists via DNS"""
        try:
            ip_address = socket.gethostbyname(domain)
            return {
                "success": True,
                "ip_address": ip_address,
                "message": f"DNS resolved to {ip_address}"
            }
        except socket.gaierror:
            return {
                "success": False,
                "error": f"Domain '{domain}' does not exist (DNS lookup failed)"
            }
    
    def _connect_ssl(self, domain: str) -> Dict[str, Any]:
        """Connect via SSL and get certificate info"""
        result = {
            "connected": False,
            "error": None,
            "tls_version": None,
            "cipher": None,
            "algorithm": "Unknown",
            "key_size": 0,
            "signature_algorithm": "Unknown"
        }
        
        try:
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Try to connect
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    result["connected"] = True
                    result["tls_version"] = ssock.version()
                    
                    # Get cipher info
                    cipher = ssock.cipher()
                    if cipher:
                        result["cipher"] = cipher[0]
                        
                        # Try to detect algorithm from cipher
                        if 'ECDSA' in cipher[0] or 'ECDHE' in cipher[0]:
                            result["algorithm"] = "ECDSA-P256"
                            result["key_size"] = 256
                        elif 'RSA' in cipher[0]:
                            result["algorithm"] = "RSA-2048"
                            result["key_size"] = 2048
                        elif 'AES' in cipher[0]:
                            if '256' in cipher[0]:
                                result["algorithm"] = "AES-256"
                                result["key_size"] = 256
                            else:
                                result["algorithm"] = "AES-128"
                                result["key_size"] = 128
                    
                    # Try to get certificate info
                    try:
                        cert_bin = ssock.getpeercert(binary_form=True)
                        if cert_bin:
                            cert_details = self._parse_certificate(cert_bin)
                            result.update(cert_details)
                    except:
                        pass
                    
                    logger.info(f"✅ Connected to {domain} via {result['tls_version']}")
        
        except ConnectionRefusedError:
            result["error"] = "Connection refused (port 443 not open)"
        except socket.timeout:
            result["error"] = "Connection timeout"
        except ssl.SSLError as e:
            result["error"] = f"SSL error: {str(e)}"
        except Exception as e:
            result["error"] = f"Connection error: {str(e)}"
        
        return result
    
    def _parse_certificate(self, cert_bin: bytes) -> Dict[str, Any]:
        """Parse certificate to get algorithm details"""
        result = {}
        
        try:
            # Create temporary file
            with tempfile.NamedTemporaryFile(mode='wb', suffix='.der', delete=False) as f:
                f.write(cert_bin)
                temp_file = f.name
            
            try:
                # Use openssl to parse certificate
                cmd = ['openssl', 'x509', '-inform', 'DER', '-in', temp_file, '-text', '-noout']
                output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)
                
                # Extract signature algorithm
                sig_match = re.search(r'Signature Algorithm:\s*(.+)', output)
                if sig_match:
                    result["signature_algorithm"] = sig_match.group(1).strip()
                
                # Extract public key algorithm and size
                pk_match = re.search(r'Public Key Algorithm:\s*(.+)', output)
                if pk_match:
                    result["public_key_algorithm"] = pk_match.group(1).strip()
                
                # Extract key size
                size_match = re.search(r'Public-Key:\s*\((\d+)\s*bit\)', output)
                if size_match:
                    key_size = int(size_match.group(1))
                    result["key_size"] = key_size
                    
                    # Set algorithm based on key size
                    if 'RSA' in output:
                        result["algorithm"] = f"RSA-{key_size}"
                    elif 'ECDSA' in output or 'id-ecPublicKey' in output:
                        if key_size == 256:
                            result["algorithm"] = "ECDSA-P256"
                        elif key_size == 384:
                            result["algorithm"] = "ECDSA-P384"
                        else:
                            result["algorithm"] = f"ECDSA-P{key_size}"
                
            except subprocess.CalledProcessError:
                pass
            
            finally:
                # Clean up temp file
                if os.path.exists(temp_file):
                    os.unlink(temp_file)
                    
        except Exception as e:
            logger.debug(f"Certificate parsing error: {e}")
        
        return result
    
    def _find_vulnerabilities(self, ssl_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Find quantum vulnerabilities"""
        vulnerabilities = []
        
        algorithm = ssl_info.get("algorithm", "Unknown")
        sig_algo = ssl_info.get("signature_algorithm", "")
        
        # Check algorithm against known threats
        for algo_name, threat_info in self.QUANTUM_THREATS.items():
            if algo_name in algorithm or (algo_name.split('-')[0] in algorithm):
                vuln = {
                    "algorithm": algo_name,
                    "risk_level": threat_info["risk"],
                    "description": self._get_vulnerability_description(algo_name),
                    "break_year": threat_info["break_year"],
                    "type": "Shor" if "RSA" in algo_name or "ECDSA" in algo_name else "Grover"
                }
                vulnerabilities.append(vuln)
                break  # Found a match
        
        # Check for weak signature algorithms
        if sig_algo:
            sig_lower = sig_algo.lower()
            if 'sha1' in sig_lower:
                vulnerabilities.append({
                    "algorithm": "SHA1",
                    "risk_level": "CRITICAL",
                    "description": "SHA1 is already broken and provides no security",
                    "break_year": "Already broken",
                    "type": "Grover"
                })
            elif 'md5' in sig_lower:
                vulnerabilities.append({
                    "algorithm": "MD5",
                    "risk_level": "CRITICAL",
                    "description": "MD5 is completely broken and insecure",
                    "break_year": "Already broken",
                    "type": "Grover"
                })
        
        # If no specific vulnerabilities found, add generic warning
        if not vulnerabilities and ssl_info.get("connected"):
            vulnerabilities.append({
                "algorithm": "Unknown (assumed RSA-2048)",
                "risk_level": "HIGH",
                "description": "Assuming common RSA-2048 configuration",
                "break_year": 2030,
                "type": "Shor"
            })
        
        return vulnerabilities
    
    def _get_vulnerability_description(self, algorithm: str) -> str:
        """Get description for vulnerability"""
        descriptions = {
            'RSA-1024': 'RSA-1024 can be broken with classical computers today',
            'RSA-2048': 'RSA-2048 is vulnerable to Shor\'s algorithm (breakable ~2030)',
            'RSA-3072': 'RSA-3072 provides medium-term protection but still vulnerable',
            'RSA-4096': 'RSA-4096 offers better protection but still quantum-vulnerable',
            'ECDSA-P256': 'ECDSA-P256 is completely broken by Shor\'s algorithm',
            'ECDSA-P384': 'ECDSA-P384 provides more time but still vulnerable',
        }
        return descriptions.get(algorithm, f"{algorithm} is vulnerable to quantum attacks")
    
    def _assess_risk(self, vulnerabilities: List[Dict[str, Any]], ssl_info: Dict[str, Any]) -> Dict[str, Any]:
        """Assess overall quantum risk"""
        if not vulnerabilities:
            return {
                "overall_risk": "LOW",
                "quantum_readiness": "GOOD",
                "time_to_quantum_threat": "15+ years",
                "summary": "No quantum vulnerabilities detected"
            }
        
        # Get highest risk
        risk_order = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
        highest_vuln = max(vulnerabilities, key=lambda x: risk_order.get(x.get("risk_level", "LOW"), 0))
        risk_level = highest_vuln.get("risk_level", "LOW")
        
        # Determine assessment
        if risk_level == "CRITICAL":
            return {
                "overall_risk": "CRITICAL",
                "quantum_readiness": "VERY POOR",
                "time_to_quantum_threat": "IMMEDIATE",
                "vulnerability_count": len(vulnerabilities),
                "main_threat": highest_vuln.get("algorithm", "Unknown"),
                "summary": f"CRITICAL: {highest_vuln.get('algorithm')} needs immediate replacement"
            }
        elif risk_level == "HIGH":
            return {
                "overall_risk": "HIGH",
                "quantum_readiness": "POOR",
                "time_to_quantum_threat": "5-10 years",
                "vulnerability_count": len(vulnerabilities),
                "main_threat": highest_vuln.get("algorithm", "Unknown"),
                "summary": f"HIGH risk: {highest_vuln.get('algorithm')} vulnerable to quantum attacks"
            }
        elif risk_level == "MEDIUM":
            return {
                "overall_risk": "MEDIUM",
                "quantum_readiness": "FAIR",
                "time_to_quantum_threat": "10-15 years",
                "vulnerability_count": len(vulnerabilities),
                "main_threat": highest_vuln.get("algorithm", "Unknown"),
                "summary": f"MEDIUM risk: {highest_vuln.get('algorithm')} will need replacement"
            }
        else:
            return {
                "overall_risk": "LOW",
                "quantum_readiness": "GOOD",
                "time_to_quantum_threat": "15+ years",
                "vulnerability_count": len(vulnerabilities),
                "summary": "Low quantum risk"
            }
    
    def _generate_recommendations(self, vulnerabilities: List[Dict[str, Any]], 
                                 risk_assessment: Dict[str, Any], 
                                 ssl_info: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on analysis"""
        recommendations = []
        
        if not vulnerabilities:
            recommendations.append("✅ Excellent! No quantum vulnerabilities detected.")
            recommendations.append("• Current cryptography appears quantum-resistant")
            recommendations.append("• Continue monitoring quantum computing developments")
            return recommendations
        
        # Sort vulnerabilities by risk
        vulnerabilities.sort(key=lambda x: 0 if x.get("risk_level") == "CRITICAL" else 
                                         1 if x.get("risk_level") == "HIGH" else 2)
        
        highest_risk = vulnerabilities[0].get("risk_level", "LOW")
        
        # Critical vulnerabilities
        if highest_risk == "CRITICAL":
            critical_algo = vulnerabilities[0].get("algorithm", "")
            
            if "SHA1" in critical_algo or "MD5" in critical_algo:
                recommendations.append("🚨 CRITICAL - Broken Hash Algorithm:")
                recommendations.append("• IMMEDIATELY replace SHA1/MD5 with SHA-256")
                recommendations.append("• These algorithms are already broken today")
                recommendations.append("• Update certificates and code immediately")
            
            elif "1024" in critical_algo:
                recommendations.append("🚨 CRITICAL - Weak Key Size:")
                recommendations.append("• IMMEDIATELY upgrade to 2048-bit or higher")
                recommendations.append("• 1024-bit keys can be broken today")
                recommendations.append("• Generate new certificates immediately")
        
        # High risk vulnerabilities (most common)
        elif highest_risk == "HIGH":
            high_algo = vulnerabilities[0].get("algorithm", "")
            
            if "RSA-2048" in high_algo:
                recommendations.append("⚠️ HIGH RISK - RSA-2048:")
                recommendations.append("• Plan migration to post-quantum cryptography")
                recommendations.append("• Begin testing with CRYSTALS-Kyber (NIST standard)")
                recommendations.append("• Consider hybrid certificates during transition")
                recommendations.append("• Timeline: 2-3 year migration plan")
            
            elif "ECDSA" in high_algo:
                recommendations.append("⚠️ HIGH RISK - ECDSA:")
                recommendations.append("• ECDSA is also vulnerable to quantum attacks")
                recommendations.append("• Plan migration to post-quantum signatures")
                recommendations.append("• Test Falcon or SPHINCS+")
        
        # Medium risk
        elif highest_risk == "MEDIUM":
            recommendations.append("📊 MEDIUM RISK:")
            recommendations.append("• Provides medium-term protection")
            recommendations.append("• Still plan for eventual migration")
            recommendations.append("• Monitor quantum computing progress")
            recommendations.append("• Test post-quantum algorithms in lab")
        
        # General recommendations for all
        recommendations.append("📋 GENERAL QUANTUM PREPAREDNESS:")
        recommendations.append("• Conduct cryptographic inventory")
        recommendations.append("• Monitor NIST PQC standards (nist.gov/pqcrypto)")
        recommendations.append("• Develop 5-year migration roadmap")
        recommendations.append("• Train staff on post-quantum cryptography")
        
        return recommendations
    
    def _get_connection_failed_recommendations(self, domain: str) -> List[str]:
        """Recommendations when connection fails"""
        return [
            "❌ CONNECTION FAILED",
            f"• Could not connect to {domain}",
            "• Check if the website supports HTTPS",
            "• Verify the domain name is correct",
            "• Try accessing https://" + domain + " in your browser",
            "• The site might be down or blocking connections"
        ]
    
    def generate_report(self, analysis_result: Dict[str, Any]) -> str:
        """Generate report from analysis"""
        report = []
        
        report.append("🔐 QUANTUM SECURITY ANALYSIS")
        report.append("=" * 60)
        report.append(f"Domain: {analysis_result.get('domain', 'Unknown')}")
        report.append(f"Time: {analysis_result.get('analysis_time', 'Unknown')}")
        
        if analysis_result.get("success"):
            # Certificate info
            cert_info = analysis_result.get("certificate_info", {})
            report.append(f"\n🌐 CONNECTION STATUS: ✅ SUCCESS")
            
            if cert_info.get("tls_version"):
                report.append(f"  TLS Version: {cert_info['tls_version']}")
            if cert_info.get("cipher"):
                report.append(f"  Cipher: {cert_info['cipher']}")
            if cert_info.get("algorithm") != "Unknown":
                report.append(f"  Algorithm: {cert_info['algorithm']}")
            if cert_info.get("key_size"):
                report.append(f"  Key Size: {cert_info['key_size']} bits")
            if cert_info.get("signature_algorithm"):
                report.append(f"  Signature: {cert_info['signature_algorithm']}")
            
            # Risk assessment
            risk = analysis_result.get("risk_assessment", {})
            report.append(f"\n📊 RISK ASSESSMENT:")
            report.append(f"  Overall Risk: {risk.get('overall_risk', 'Unknown')}")
            report.append(f"  Quantum Readiness: {risk.get('quantum_readiness', 'Unknown')}")
            report.append(f"  Time to Quantum Threat: {risk.get('time_to_quantum_threat', 'Unknown')}")
            
            # Vulnerabilities
            vulns = analysis_result.get("quantum_vulnerabilities", [])
            if vulns:
                report.append(f"\n⚠️  QUANTUM VULNERABILITIES ({len(vulns)} found):")
                for i, vuln in enumerate(vulns, 1):
                    icon = "🚨" if vuln.get("risk_level") == "CRITICAL" else \
                           "⚠️" if vuln.get("risk_level") == "HIGH" else "📊"
                    report.append(f"  {icon} {vuln.get('algorithm', 'Unknown')} - {vuln.get('risk_level', 'Unknown')}")
                    desc = vuln.get("description", "")
                    if desc:
                        report.append(f"     {desc}")
            
            # Recommendations
            recs = analysis_result.get("recommendations", [])
            if recs:
                report.append(f"\n💡 RECOMMENDATIONS:")
                for i, rec in enumerate(recs[:10], 1):
                    if rec.startswith(("🚨", "⚠️", "📊", "📋", "❌")):
                        report.append(f"  {rec}")
                    elif rec.startswith("•"):
                        report.append(f"    {rec}")
                    else:
                        report.append(f"  {rec}")
        
        elif "error" in analysis_result:
            report.append(f"\n❌ ANALYSIS FAILED")
            report.append(f"  Error: {analysis_result['error']}")
            
            recs = analysis_result.get("recommendations", [])
            if recs:
                report.append(f"\n💡 SUGGESTIONS:")
                for rec in recs:
                    report.append(f"  {rec}")
        
        report.append("\n" + "=" * 60)
        report.append("Note: This analysis attempts real SSL/TLS connections")
        report.append("      and provides quantum vulnerability assessment.")
        
        return "\n".join(report)


    