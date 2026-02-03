#!/usr/bin/env python3
"""
Nmap Scanner Module - FIXED VERSION
Complete network scanner using python-nmap
Author: CryptoTool
"""

import nmap # type: ignore
import json
import sys
import argparse
import socket
import ipaddress
from datetime import datetime
import logging
from typing import Dict, List, Any, Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class NmapScanner:
    """Complete network scanner using python-nmap - FIXED VERSION"""
    
    def __init__(self):
        """Initialize the Nmap scanner"""
        try:
            self.nm = nmap.PortScanner()
            logger.info("Nmap scanner initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize Nmap scanner: {e}")
            # Create dummy scanner if nmap not available
            self.nm = None
    
    def validate_target(self, target: str) -> bool:
        """Validate if target is a valid IP or domain"""
        try:
            # Try to parse as IP address
            ipaddress.ip_address(target)
            return True
        except ValueError:
            # Try domain resolution
            try:
                socket.gethostbyname(target)
                return True
            except socket.gaierror:
                return False
        except:
            return False
    
    def scan_target(self, target: str, ports: str = "1-1000", 
                    arguments: str = "-sV") -> Dict[str, Any]:
        """
        Scan a target for open ports and services - FIXED: No root required
        
        Args:
            target: IP address or domain to scan
            ports: Port range to scan (default: 1-1000)
            arguments: Nmap arguments (default: -sV for version scan only)
        
        Returns:
            Dictionary with scan results
        """
        try:
            # Validate target
            if not self.validate_target(target):
                return {
                    "success": False,
                    "error": f"Invalid target: {target}. Must be a valid IP address or domain."
                }
            
            # Check if nmap is available
            if self.nm is None:
                return {
                    "success": False,
                    "error": "Nmap not available. Install with: pip install python-nmap"
                }
            
            logger.info(f"Starting scan on {target}, ports: {ports}, arguments: {arguments}")
            
            # Perform the scan (without -O to avoid root requirement)
            scan_args = arguments
            if "-O" in scan_args:
                scan_args = scan_args.replace("-O", "").strip()
                logger.info("Removed -O flag to avoid root requirement")
            
            self.nm.scan(hosts=target, ports=ports, arguments=scan_args)
            
            if target not in self.nm.all_hosts():
                return {
                    "success": False,
                    "error": f"Target {target} not found or not responding"
                }
            
            # Extract results
            results = {
                "success": True,
                "target": target,
                "scan_time": datetime.now().isoformat(),
                "scan_arguments": scan_args,
                "host_info": self._extract_host_info(target),
                "open_ports": self._extract_open_ports(target),
                "scan_summary": self._generate_summary(target)
            }
            
            logger.info(f"Scan completed successfully for {target}")
            return results
            
        except Exception as e:
            logger.error(f"Scan failed: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def _extract_host_info(self, target: str) -> Dict[str, Any]:
        """Extract host information from scan results"""
        host_info = {}
        
        try:
            host = self.nm[target]
            
            # Basic host info
            host_info.update({
                "hostname": host.hostname() if hasattr(host, 'hostname') else 'Unknown',
                "state": host.state() if hasattr(host, 'state') else 'Unknown',
                "addresses": dict(host.get("addresses", {})) if "addresses" in host else {},
            })
            
            # Vendor info if available
            if "vendor" in host:
                host_info["vendor"] = dict(host["vendor"])
            
            # MAC address if available
            if "addresses" in host and "mac" in host["addresses"]:
                host_info["mac_address"] = host["addresses"]["mac"]
                
        except Exception as e:
            logger.warning(f"Could not extract host info: {e}")
            host_info = {"error": str(e)}
        
        return host_info
    
    def _extract_open_ports(self, target: str) -> List[Dict[str, Any]]:
        """Extract open ports and service information"""
        open_ports = []
        
        try:
            host = self.nm[target]
            
            # Get all TCP ports
            if "tcp" in host:
                for port, port_info in host["tcp"].items():
                    if port_info.get("state") == "open":
                        open_ports.append({
                            "port": port,
                            "protocol": "tcp",
                            "state": port_info.get("state", ""),
                            "service": port_info.get("name", ""),
                            "version": port_info.get("version", ""),
                            "product": port_info.get("product", ""),
                            "extra_info": port_info.get("extrainfo", ""),
                        })
            
            # Get all UDP ports
            if "udp" in host:
                for port, port_info in host["udp"].items():
                    if port_info.get("state") == "open":
                        open_ports.append({
                            "port": port,
                            "protocol": "udp",
                            "state": port_info.get("state", ""),
                            "service": port_info.get("name", ""),
                            "version": port_info.get("version", ""),
                            "product": port_info.get("product", ""),
                            "extra_info": port_info.get("extrainfo", ""),
                        })
            
        except Exception as e:
            logger.warning(f"Could not extract port info: {e}")
        
        return open_ports
    
    def _generate_summary(self, target: str) -> Dict[str, Any]:
        """Generate a summary of the scan results"""
        summary = {
            "total_open_ports": 0,
            "tcp_ports": 0,
            "udp_ports": 0,
            "services_found": [],
            "vulnerability_indicators": []
        }
        
        try:
            host = self.nm[target]
            
            # Count TCP ports
            if "tcp" in host:
                tcp_ports = {port: info for port, info in host["tcp"].items() 
                            if info.get("state") == "open"}
                summary["tcp_ports"] = len(tcp_ports)
            
            # Count UDP ports
            if "udp" in host:
                udp_ports = {port: info for port, info in host["udp"].items() 
                            if info.get("state") == "open"}
                summary["udp_ports"] = len(udp_ports)
            
            summary["total_open_ports"] = summary["tcp_ports"] + summary["udp_ports"]
            
            # Collect unique services
            services = set()
            for protocol in ["tcp", "udp"]:
                if protocol in host:
                    for port_info in host[protocol].values():
                        if port_info.get("state") == "open":
                            service = port_info.get("name", "unknown")
                            if service and service != "unknown":
                                services.add(service)
            
            summary["services_found"] = list(services)
            
            # Check for common vulnerable services (educational purposes only)
            vulnerable_services = {
                "ftp": ["FTP may allow anonymous login"],
                "telnet": ["Telnet transmits credentials in plaintext"],
                "http": ["HTTP is unencrypted"],
                "smtp": ["SMTP may allow open relay"],
                "mysql": ["MySQL may have weak authentication"],
            }
            
            for service in summary["services_found"]:
                service_lower = service.lower()
                for vuln_service, indicators in vulnerable_services.items():
                    if vuln_service in service_lower:
                        summary["vulnerability_indicators"].extend(indicators)
            
        except Exception as e:
            logger.warning(f"Could not generate summary: {e}")
        
        return summary
    
    def scan_multiple_targets(self, targets: List[str], **kwargs) -> Dict[str, Any]:
        """
        Scan multiple targets
        
        Args:
            targets: List of IP addresses or domains
            **kwargs: Additional arguments passed to scan_target
        
        Returns:
            Dictionary with scan results for all targets
        """
        results = {
            "success": True,
            "scan_time": datetime.now().isoformat(),
            "total_targets": len(targets),
            "scanned_targets": [],
            "summary": {
                "successful_scans": 0,
                "failed_scans": 0
            }
        }
        
        for target in targets:
            try:
                scan_result = self.scan_target(target, **kwargs)
                results["scanned_targets"].append(scan_result)
                
                if scan_result.get("success"):
                    results["summary"]["successful_scans"] += 1
                else:
                    results["summary"]["failed_scans"] += 1
                    
            except Exception as e:
                logger.error(f"Failed to scan {target}: {e}")
                results["scanned_targets"].append({
                    "target": target,
                    "success": False,
                    "error": str(e)
                })
                results["summary"]["failed_scans"] += 1
        
        return results

