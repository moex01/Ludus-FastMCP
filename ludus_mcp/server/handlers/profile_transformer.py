"""Handler for applying Adversary/Defender profiles to range configurations.

This handler transforms existing configurations by:
- Adversary Profile: Injecting realistic vulnerabilities for red team training
- Defender Profile: Adding monitoring, logging, and detection capabilities
"""

from typing import Any
import copy
import yaml

from ludus_mcp.core.client import LudusAPIClient
from ludus_mcp.utils.logging import get_logger

logger = get_logger(__name__)


class ProfileTransformerHandler:
    """Handler for applying security profiles to configurations."""

    def __init__(self, client: LudusAPIClient) -> None:
        """Initialize the profile transformer handler."""
        self.client = client

    async def apply_adversary_profile(
        self,
        config: dict[str, Any],
        threat_level: str = "medium",
        target_vms: list[str] | None = None,
        include_documentation: bool = True,
    ) -> dict[str, Any]:
        """Apply adversary profile to inject realistic vulnerabilities.

        Args:
            config: Original Ludus configuration
            threat_level: Vulnerability level (low, medium, high)
            target_vms: Specific VMs to target (None = all)
            include_documentation: Include educational docs about vulnerabilities

        Returns:
            Dictionary with modified config and vulnerability documentation
        """
        logger.info(f"Applying adversary profile (threat_level={threat_level})")

        modified_config = copy.deepcopy(config)
        injections = []
        vms = modified_config.get("ludus", [])

        # Determine vulnerability sets based on threat level
        vuln_sets = self._get_vulnerability_sets(threat_level)

        for vm in vms:
            vm_name = vm.get("vm_name", "")
            hostname = vm.get("hostname", "")

            # Skip if not in target list
            if target_vms and hostname not in target_vms:
                continue

            # Determine VM type
            vm_type = self._determine_vm_type(vm)

            # Apply vulnerabilities based on VM type
            if vm_type == "domain_controller":
                vm_injections = self._inject_dc_vulnerabilities(vm, vuln_sets, threat_level)
                injections.extend(vm_injections)

            elif vm_type == "workstation":
                vm_injections = self._inject_workstation_vulnerabilities(vm, vuln_sets, threat_level)
                injections.extend(vm_injections)

            elif vm_type == "server":
                vm_injections = self._inject_server_vulnerabilities(vm, vuln_sets, threat_level)
                injections.extend(vm_injections)

        # Generate documentation
        documentation = ""
        if include_documentation:
            documentation = self._generate_adversary_documentation(injections, threat_level)

        result = {
            "status": "success",
            "profile_type": "adversary",
            "threat_level": threat_level,
            "modified_config": modified_config,
            "vulnerability_injections": injections,
            "vulnerabilities_count": len(injections),
            "affected_vms": list(set(inj["vm_name"] for inj in injections)),
            "documentation": documentation,
            "warnings": [
                "⚠️  These vulnerabilities are for EDUCATIONAL PURPOSES ONLY",
                "⚠️  Deploy in isolated environments only",
                "⚠️  Do NOT expose these systems to the internet",
            ],
            "next_steps": [
                "1. Review the vulnerability injections and documentation",
                "2. Understand each vulnerability before deploying",
                "3. Deploy with: deploy_range(config=modified_config)",
                "4. Practice exploitation in controlled environment",
            ],
        }

        return result

    async def apply_defender_profile(
        self,
        config: dict[str, Any],
        monitoring_level: str = "comprehensive",
        siem_type: str = "wazuh",
        detection_focus: list[str] | None = None,
    ) -> dict[str, Any]:
        """Apply defender profile to add monitoring and detection capabilities.

        Args:
            config: Original Ludus configuration
            monitoring_level: Level of monitoring (basic, comprehensive, advanced)
            siem_type: SIEM to deploy (wazuh, splunk, elastic)
            detection_focus: Specific attack types to focus detection on

        Returns:
            Dictionary with modified config and monitoring documentation
        """
        logger.info(f"Applying defender profile (level={monitoring_level}, siem={siem_type})")

        modified_config = copy.deepcopy(config)
        enhancements = []
        vms = modified_config.get("ludus", [])

        # Get monitoring capabilities based on level
        monitoring_caps = self._get_monitoring_capabilities(monitoring_level)

        for vm in vms:
            vm_name = vm.get("vm_name", "")
            hostname = vm.get("hostname", "")
            template = vm.get("template", "")

            # Determine OS type
            is_windows = "win" in template.lower()
            is_linux = any(x in template.lower() for x in ["ubuntu", "debian", "centos", "rhel", "kali"])

            # Apply monitoring based on OS
            if is_windows:
                vm_enhancements = self._add_windows_monitoring(
                    vm, monitoring_caps, monitoring_level, siem_type
                )
                enhancements.extend(vm_enhancements)

            elif is_linux:
                vm_enhancements = self._add_linux_monitoring(
                    vm, monitoring_caps, monitoring_level, siem_type
                )
                enhancements.extend(vm_enhancements)

        # Add SIEM server if not present
        siem_added = self._ensure_siem_server(modified_config, siem_type, monitoring_level)

        # Add detection rules
        detection_rules = self._add_detection_rules(detection_focus or [], siem_type)

        # Generate documentation
        documentation = self._generate_defender_documentation(
            enhancements, siem_type, monitoring_level, detection_rules
        )

        result = {
            "status": "success",
            "profile_type": "defender",
            "monitoring_level": monitoring_level,
            "siem_type": siem_type,
            "modified_config": modified_config,
            "monitoring_enhancements": enhancements,
            "enhancements_count": len(enhancements),
            "siem_added": siem_added,
            "detection_rules": detection_rules,
            "affected_vms": list(set(enh["vm_name"] for enh in enhancements)),
            "documentation": documentation,
            "next_steps": [
                "1. Review the monitoring enhancements",
                f"2. Ensure {siem_type.title()} SIEM is properly configured",
                "3. Deploy with: deploy_range(config=modified_config)",
                "4. Configure detection rules and alerting",
                "5. Practice threat hunting and incident response",
            ],
        }

        return result

    def _determine_vm_type(self, vm: dict[str, Any]) -> str:
        """Determine the type of VM."""
        if vm.get("domain", {}).get("role") == "primary-dc":
            return "domain_controller"
        elif "workstation" in vm.get("template", "").lower() or "win10" in vm.get("template", "").lower():
            return "workstation"
        elif "server" in vm.get("template", "").lower():
            return "server"
        return "other"

    def _get_vulnerability_sets(self, threat_level: str) -> dict[str, list[str]]:
        """Get vulnerability sets based on threat level."""
        vuln_sets = {
            "low": {
                "ad": ["weak_passwords", "open_shares"],
                "windows": ["outdated_software", "weak_local_admin"],
                "network": ["open_smb", "rdp_exposed"],
            },
            "medium": {
                "ad": ["weak_passwords", "open_shares", "kerberoasting", "asrep_roasting", "weak_gpo"],
                "windows": ["outdated_software", "weak_local_admin", "unquoted_service_paths", "weak_acls"],
                "network": ["open_smb", "rdp_exposed", "llmnr_poisoning", "weak_network_segmentation"],
            },
            "high": {
                "ad": [
                    "weak_passwords", "open_shares", "kerberoasting", "asrep_roasting",
                    "weak_gpo", "unconstrained_delegation", "dcsync_rights", "forest_trusts",
                    "certificate_services_vulns", "zerologon_vulnerable"
                ],
                "windows": [
                    "outdated_software", "weak_local_admin", "unquoted_service_paths",
                    "weak_acls", "alwaysinstallelevated", "cached_credentials", "autologon_creds"
                ],
                "network": [
                    "open_smb", "rdp_exposed", "llmnr_poisoning", "weak_network_segmentation",
                    "dns_zone_transfers", "ipv6_enabled", "ntlm_relay_possible"
                ],
            },
            "critical": {
                "ad": [
                    "weak_passwords", "open_shares", "kerberoasting", "asrep_roasting",
                    "weak_gpo", "unconstrained_delegation", "dcsync_rights", "forest_trusts",
                    "certificate_services_vulns", "zerologon_vulnerable", "golden_ticket",
                    "silver_ticket", "skeleton_key", "dcshadow", "krbtgt_backdoor"
                ],
                "windows": [
                    "outdated_software", "weak_local_admin", "unquoted_service_paths",
                    "weak_acls", "alwaysinstallelevated", "cached_credentials", "autologon_creds",
                    "dll_hijacking", "com_hijacking", "print_spooler_vulns", "smbghost",
                    "petitpotam", "registry_autoruns", "scheduled_task_persistence"
                ],
                "network": [
                    "open_smb", "rdp_exposed", "llmnr_poisoning", "weak_network_segmentation",
                    "dns_zone_transfers", "ipv6_enabled", "ntlm_relay_possible",
                    "smb_signing_disabled", "ldap_signing_disabled", "responder_poisoning"
                ],
                "persistence": [
                    "wmi_subscriptions", "registry_run_keys", "startup_folder",
                    "service_creation", "dll_sideloading", "bits_jobs"
                ],
                "exfiltration": [
                    "dns_tunneling", "cloud_storage_abuse", "email_exfil", "ftp_exfil"
                ],
            },
        }
        return vuln_sets.get(threat_level, vuln_sets["medium"])

    def _inject_dc_vulnerabilities(
        self, vm: dict[str, Any], vuln_sets: dict[str, list[str]], threat_level: str
    ) -> list[dict[str, Any]]:
        """Inject vulnerabilities into a domain controller."""
        injections = []
        vm_name = vm.get("vm_name", "")
        ad_vulns = vuln_sets.get("ad", [])

        # Initialize roles if not present
        if "roles" not in vm:
            vm["roles"] = []

        if "weak_passwords" in ad_vulns:
            vm["roles"].append("ludus_ad_weak_passwords")
            injections.append({
                "vm_name": vm_name,
                "vulnerability_type": "weak_passwords",
                "category": "Active Directory",
                "severity": "high",
                "ansible_role": "ludus_ad_weak_passwords",
                "description": "Domain users have weak, easily guessable passwords",
                "exploitation": "Password spraying, brute force attacks",
                "cve": None,
            })

        if "kerberoasting" in ad_vulns:
            vm["roles"].append("ludus_ad_kerberoast")
            injections.append({
                "vm_name": vm_name,
                "vulnerability_type": "kerberoasting",
                "category": "Active Directory",
                "severity": "high",
                "ansible_role": "ludus_ad_kerberoast",
                "description": "Service accounts with SPNs have weak passwords",
                "exploitation": "Kerberoasting attack to crack service account passwords",
                "cve": None,
            })

        if "asrep_roasting" in ad_vulns:
            vm["roles"].append("ludus_ad_asreproast")
            injections.append({
                "vm_name": vm_name,
                "vulnerability_type": "asrep_roasting",
                "category": "Active Directory",
                "severity": "medium",
                "ansible_role": "ludus_ad_asreproast",
                "description": "User accounts with 'Do not require Kerberos preauthentication' enabled",
                "exploitation": "AS-REP roasting to obtain crackable hashes",
                "cve": None,
            })

        if "unconstrained_delegation" in ad_vulns:
            vm["roles"].append("ludus_ad_unconstrained_delegation")
            injections.append({
                "vm_name": vm_name,
                "vulnerability_type": "unconstrained_delegation",
                "category": "Active Directory",
                "severity": "critical",
                "ansible_role": "ludus_ad_unconstrained_delegation",
                "description": "Computer accounts configured with unconstrained delegation",
                "exploitation": "Abuse unconstrained delegation to compromise domain",
                "cve": None,
            })

        return injections

    def _inject_workstation_vulnerabilities(
        self, vm: dict[str, Any], vuln_sets: dict[str, list[str]], threat_level: str
    ) -> list[dict[str, Any]]:
        """Inject vulnerabilities into a workstation."""
        injections = []
        vm_name = vm.get("vm_name", "")
        windows_vulns = vuln_sets.get("windows", [])

        if "roles" not in vm:
            vm["roles"] = []

        if "weak_local_admin" in windows_vulns:
            vm["roles"].append("ludus_weak_local_admin")
            injections.append({
                "vm_name": vm_name,
                "vulnerability_type": "weak_local_admin",
                "category": "Windows Security",
                "severity": "high",
                "ansible_role": "ludus_weak_local_admin",
                "description": "Local administrator account with weak password",
                "exploitation": "Local privilege escalation, lateral movement",
                "cve": None,
            })

        if "unquoted_service_paths" in windows_vulns:
            vm["roles"].append("ludus_unquoted_service_paths")
            injections.append({
                "vm_name": vm_name,
                "vulnerability_type": "unquoted_service_paths",
                "category": "Windows Security",
                "severity": "medium",
                "ansible_role": "ludus_unquoted_service_paths",
                "description": "Windows services with unquoted executable paths",
                "exploitation": "Privilege escalation via DLL hijacking",
                "cve": None,
            })

        return injections

    def _inject_server_vulnerabilities(
        self, vm: dict[str, Any], vuln_sets: dict[str, list[str]], threat_level: str
    ) -> list[dict[str, Any]]:
        """Inject vulnerabilities into a server."""
        injections = []
        vm_name = vm.get("vm_name", "")

        if "roles" not in vm:
            vm["roles"] = []

        # Add common server vulnerabilities
        vm["roles"].append("ludus_open_shares")
        injections.append({
            "vm_name": vm_name,
            "vulnerability_type": "open_shares",
            "category": "Network Security",
            "severity": "medium",
            "ansible_role": "ludus_open_shares",
            "description": "SMB shares with weak or no authentication",
            "exploitation": "Unauthorized file access, credential harvesting",
            "cve": None,
        })

        return injections

    def _get_monitoring_capabilities(self, monitoring_level: str) -> dict[str, list[str]]:
        """Get monitoring capabilities based on level."""
        capabilities = {
            "basic": {
                "windows": ["siem_agent", "event_forwarding"],
                "linux": ["siem_agent", "syslog_forwarding"],
                "network": [],
            },
            "comprehensive": {
                "windows": ["siem_agent", "event_forwarding", "sysmon", "powershell_logging"],
                "linux": ["siem_agent", "syslog_forwarding", "auditd", "osquery"],
                "network": ["netflow", "packet_capture"],
            },
            "advanced": {
                "windows": [
                    "siem_agent", "event_forwarding", "sysmon", "powershell_logging",
                    "edr", "process_monitoring", "file_integrity_monitoring"
                ],
                "linux": [
                    "siem_agent", "syslog_forwarding", "auditd", "osquery",
                    "edr", "process_monitoring", "file_integrity_monitoring"
                ],
                "network": ["netflow", "packet_capture", "zeek", "suricata"],
            },
            "elite": {
                "windows": [
                    "siem_agent", "event_forwarding", "sysmon", "powershell_logging",
                    "edr", "process_monitoring", "file_integrity_monitoring",
                    "threat_hunting_tools", "memory_forensics", "behavioral_analytics",
                    "automated_response", "deception_technology"
                ],
                "linux": [
                    "siem_agent", "syslog_forwarding", "auditd", "osquery",
                    "edr", "process_monitoring", "file_integrity_monitoring",
                    "threat_hunting_tools", "memory_forensics", "behavioral_analytics",
                    "automated_response", "honeypot_integration"
                ],
                "network": [
                    "netflow", "packet_capture", "zeek", "suricata",
                    "network_taps", "ssl_inspection", "dns_analytics",
                    "threat_intel_feeds", "automated_blocking"
                ],
                "threat_intelligence": [
                    "misp_integration", "threat_feed_aggregation", "ioc_matching",
                    "threat_actor_tracking", "ttp_correlation"
                ],
                "hunting": [
                    "sigma_rules", "yara_rules", "custom_hunting_queries",
                    "baseline_deviation", "peer_group_analysis"
                ],
            },
        }
        return capabilities.get(monitoring_level, capabilities["comprehensive"])

    def _add_windows_monitoring(
        self, vm: dict[str, Any], monitoring_caps: dict, level: str, siem_type: str
    ) -> list[dict[str, Any]]:
        """Add Windows monitoring capabilities."""
        enhancements = []
        vm_name = vm.get("vm_name", "")
        windows_caps = monitoring_caps.get("windows", [])

        if "roles" not in vm:
            vm["roles"] = []

        if "siem_agent" in windows_caps:
            agent_role = f"ludus_{siem_type}_agent"
            vm["roles"].append(agent_role)
            enhancements.append({
                "vm_name": vm_name,
                "enhancement_type": "siem_agent",
                "category": "Logging",
                "ansible_role": agent_role,
                "description": f"{siem_type.title()} agent for centralized logging",
                "capabilities": ["Event log forwarding", "Real-time alerting"],
            })

        if "sysmon" in windows_caps:
            vm["roles"].append("ludus_sysmon")
            enhancements.append({
                "vm_name": vm_name,
                "enhancement_type": "sysmon",
                "category": "Advanced Logging",
                "ansible_role": "ludus_sysmon",
                "description": "Sysmon for detailed process and network logging",
                "capabilities": ["Process creation", "Network connections", "File creation"],
            })

        if "powershell_logging" in windows_caps:
            vm["roles"].append("ludus_powershell_logging")
            enhancements.append({
                "vm_name": vm_name,
                "enhancement_type": "powershell_logging",
                "category": "Advanced Logging",
                "ansible_role": "ludus_powershell_logging",
                "description": "Enhanced PowerShell script block and transcription logging",
                "capabilities": ["Script block logging", "Transcription", "Module logging"],
            })

        return enhancements

    def _add_linux_monitoring(
        self, vm: dict[str, Any], monitoring_caps: dict, level: str, siem_type: str
    ) -> list[dict[str, Any]]:
        """Add Linux monitoring capabilities."""
        enhancements = []
        vm_name = vm.get("vm_name", "")
        linux_caps = monitoring_caps.get("linux", [])

        if "roles" not in vm:
            vm["roles"] = []

        if "siem_agent" in linux_caps:
            agent_role = f"ludus_{siem_type}_agent"
            vm["roles"].append(agent_role)
            enhancements.append({
                "vm_name": vm_name,
                "enhancement_type": "siem_agent",
                "category": "Logging",
                "ansible_role": agent_role,
                "description": f"{siem_type.title()} agent for centralized logging",
                "capabilities": ["Syslog forwarding", "Real-time alerting"],
            })

        if "auditd" in linux_caps:
            vm["roles"].append("ludus_auditd")
            enhancements.append({
                "vm_name": vm_name,
                "enhancement_type": "auditd",
                "category": "Advanced Logging",
                "ansible_role": "ludus_auditd",
                "description": "Linux audit framework for system call monitoring",
                "capabilities": ["File access", "System calls", "User activity"],
            })

        return enhancements

    def _ensure_siem_server(
        self, config: dict[str, Any], siem_type: str, monitoring_level: str
    ) -> bool:
        """Ensure SIEM server is present in configuration."""
        vms = config.get("ludus", [])

        # Check if SIEM already exists
        siem_exists = any(siem_type.lower() in vm.get("vm_name", "").lower() for vm in vms)

        if not siem_exists:
            # Add SIEM server
            siem_vm = {
                "vm_name": f"{{{{ range_id }}}}-{siem_type}",
                "hostname": siem_type.upper(),
                "template": "ubuntu-22-x64-server-template",
                "vlan": 10,
                "ip_last_octet": 100,
                "ram_gb": 8 if monitoring_level == "advanced" else 4,
                "cpus": 4 if monitoring_level == "advanced" else 2,
                "roles": [f"ludus_{siem_type}_server"],
            }
            vms.append(siem_vm)
            return True

        return False

    def _add_detection_rules(
        self, detection_focus: list[str], siem_type: str
    ) -> list[dict[str, Any]]:
        """Add detection rules based on focus areas."""
        rules = []

        common_rules = [
            {
                "rule_name": "Kerberoasting Detection",
                "category": "Active Directory",
                "description": "Detects TGS requests for service accounts",
                "severity": "high",
                "indicators": ["Event ID 4769", "RC4 encryption", "Service accounts"],
            },
            {
                "rule_name": "Lateral Movement Detection",
                "category": "Network",
                "description": "Detects PsExec and WMI-based lateral movement",
                "severity": "high",
                "indicators": ["Event ID 7045", "Service installation", "Remote execution"],
            },
            {
                "rule_name": "Credential Dumping",
                "category": "Credential Access",
                "description": "Detects LSASS memory access and credential dumping",
                "severity": "critical",
                "indicators": ["LSASS process access", "Mimikatz indicators", "SAM access"],
            },
            {
                "rule_name": "DCSync Attack Detection",
                "category": "Active Directory",
                "description": "Detects DCSync replication requests from non-DC machines",
                "severity": "critical",
                "indicators": ["Event ID 4662", "Replicating Directory Changes", "Non-DC source"],
            },
            {
                "rule_name": "Golden Ticket Detection",
                "category": "Persistence",
                "description": "Detects anomalous Kerberos TGT characteristics",
                "severity": "critical",
                "indicators": ["Unusual ticket lifetime", "Forged PAC", "KRBTGT usage"],
            },
            {
                "rule_name": "Pass-the-Hash Detection",
                "category": "Lateral Movement",
                "description": "Detects NTLM authentication from unusual sources",
                "severity": "high",
                "indicators": ["Event ID 4624 Type 3", "NTLM authentication", "Unusual source"],
            },
            {
                "rule_name": "Ransomware Behavior",
                "category": "Impact",
                "description": "Detects rapid file encryption and shadow copy deletion",
                "severity": "critical",
                "indicators": ["Mass file modification", "vssadmin delete", "bcdedit /set"],
            },
            {
                "rule_name": "Suspicious PowerShell",
                "category": "Execution",
                "description": "Detects encoded commands and download cradles",
                "severity": "high",
                "indicators": ["EncodedCommand", "DownloadString", "IEX", "Bypass"],
            },
            {
                "rule_name": "Persistence via Registry",
                "category": "Persistence",
                "description": "Detects registry run key modifications",
                "severity": "medium",
                "indicators": ["HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"],
            },
            {
                "rule_name": "DNS Tunneling",
                "category": "Exfiltration",
                "description": "Detects anomalous DNS query patterns",
                "severity": "high",
                "indicators": ["High DNS volume", "Long subdomains", "Unusual TXT queries"],
            },
        ]

        rules.extend(common_rules)
        return rules

    def get_apt_profile_configuration(self, apt_profile: str) -> dict[str, Any]:
        """Get configuration for specific APT profile."""
        apt_configs = {
            "apt28": {
                "name": "APT28 (Fancy Bear)",
                "description": "Russian state-sponsored group focusing on credential theft and lateral movement",
                "threat_level": "critical",
                "focus_areas": ["credential_access", "lateral_movement", "persistence"],
                "techniques": [
                    "password_spraying", "kerberoasting", "golden_ticket",
                    "dcsync", "rdp_hijacking", "wmi_lateral_movement"
                ],
                "tools": ["Mimikatz", "BloodHound", "Rubeus", "Impacket"],
                "persistence": ["wmi_subscriptions", "registry_run_keys", "service_creation"],
            },
            "apt29": {
                "name": "APT29 (Cozy Bear)",
                "description": "Advanced persistent threat with focus on stealth and cloud exploitation",
                "threat_level": "critical",
                "focus_areas": ["persistence", "stealth", "cloud_exploitation"],
                "techniques": [
                    "dll_sideloading", "com_hijacking", "wmi_subscriptions",
                    "cloud_token_theft", "oauth_abuse"
                ],
                "tools": ["Custom malware", "PowerShell Empire", "Cloud APIs"],
                "persistence": ["dll_hijacking", "scheduled_tasks", "bits_jobs"],
            },
            "apt41": {
                "name": "APT41 (Double Dragon)",
                "description": "Dual espionage and financially motivated attacks",
                "threat_level": "high",
                "focus_areas": ["initial_access", "privilege_escalation", "exfiltration"],
                "techniques": [
                    "supply_chain_compromise", "web_shell", "credential_dumping",
                    "data_staging", "cloud_storage_exfil"
                ],
                "tools": ["Custom RATs", "Web shells", "Credential dumpers"],
                "persistence": ["web_shells", "registry_autoruns", "service_creation"],
            },
            "fin7": {
                "name": "FIN7 (Carbanak)",
                "description": "Financially motivated cybercrime group",
                "threat_level": "high",
                "focus_areas": ["credential_access", "lateral_movement", "exfiltration"],
                "techniques": [
                    "phishing", "password_theft", "pos_malware",
                    "database_exfil", "payment_card_theft"
                ],
                "tools": ["Carbanak", "Cobalt Strike", "PowerShell", "Mimikatz"],
                "persistence": ["scheduled_tasks", "registry_run_keys"],
            },
            "lazarus": {
                "name": "Lazarus Group",
                "description": "North Korean APT with destructive and financial motivations",
                "threat_level": "critical",
                "focus_areas": ["impact", "exfiltration", "credential_access"],
                "techniques": [
                    "disk_wiper", "ransomware", "cryptocurrency_theft",
                    "swift_network_compromise", "destructive_malware"
                ],
                "tools": ["WannaCry", "Custom wipers", "Crypto miners"],
                "persistence": ["bootkit", "mbr_modification", "service_creation"],
            },
        }
        return apt_configs.get(apt_profile, {})

    def apply_threat_hunting_profile(
        self, config: dict[str, Any], hunting_profile: str, siem_type: str = "wazuh"
    ) -> dict[str, Any]:
        """Apply threat hunting profile for proactive detection."""
        hunting_configs = {
            "hunter_lite": {
                "capabilities": ["scheduled_searches", "basic_queries", "known_ioc_matching"],
                "tools": ["sigma_rules", "yara_basic"],
                "automation_level": "low",
                "hunting_frequency": "weekly",
            },
            "hunter_advanced": {
                "capabilities": [
                    "behavioral_analytics", "anomaly_detection", "baseline_deviation",
                    "peer_group_analysis", "threat_intel_enrichment"
                ],
                "tools": ["sigma_rules", "yara_advanced", "osquery", "velociraptor"],
                "automation_level": "medium",
                "hunting_frequency": "daily",
            },
            "hunter_elite": {
                "capabilities": [
                    "automated_hunting", "ml_anomaly_detection", "ttp_correlation",
                    "threat_actor_tracking", "custom_detection_logic", "hypothesis_driven_hunting"
                ],
                "tools": [
                    "sigma_rules", "yara_advanced", "osquery", "velociraptor",
                    "misp", "opencti", "jupyter_notebooks", "elastic_ml"
                ],
                "automation_level": "high",
                "hunting_frequency": "continuous",
            },
        }

        hunting_config = hunting_configs.get(hunting_profile, hunting_configs["hunter_lite"])

        # Add hunting capabilities to the configuration
        modified_config = copy.deepcopy(config)
        vms = modified_config.get("ludus", [])

        # Add threat hunting VM if elite level
        if hunting_profile == "hunter_elite":
            hunting_vm = {
                "vm_name": "{{{{ range_id }}}}-threat-hunting",
                "hostname": "HUNTER",
                "template": "ubuntu-22-x64-server-template",
                "vlan": 10,
                "ip_last_octet": 110,
                "ram_gb": 16,
                "cpus": 8,
                "roles": [
                    "ludus_velociraptor",
                    "ludus_jupyter_hunting",
                    "ludus_misp",
                    "ludus_opencti",
                ],
            }
            vms.append(hunting_vm)

        return {
            "status": "success",
            "profile_type": "threat_hunting",
            "hunting_level": hunting_profile,
            "modified_config": modified_config,
            "capabilities": hunting_config["capabilities"],
            "tools": hunting_config["tools"],
            "automation_level": hunting_config["automation_level"],
            "hunting_frequency": hunting_config["hunting_frequency"],
        }

    def apply_incident_response_profile(
        self, config: dict[str, Any], ir_profile: str
    ) -> dict[str, Any]:
        """Apply incident response profile for IR readiness."""
        ir_configs = {
            "ir_preparation": {
                "capabilities": [
                    "centralized_logging", "baseline_configuration", "ir_tools_preinstalled",
                    "network_diagrams", "asset_inventory"
                ],
                "tools": ["velociraptor", "ftk_imager", "volatility", "wireshark"],
                "playbooks": ["malware_infection", "data_breach", "ransomware"],
            },
            "ir_detection": {
                "capabilities": [
                    "real_time_alerting", "correlation_rules", "automated_playbooks",
                    "threat_intel_integration", "incident_ticketing"
                ],
                "tools": [
                    "velociraptor", "ftk_imager", "volatility", "wireshark",
                    "suricata", "zeek", "theHive", "cortex"
                ],
                "playbooks": [
                    "malware_infection", "data_breach", "ransomware",
                    "apt_intrusion", "insider_threat", "ddos_attack"
                ],
            },
            "ir_containment": {
                "capabilities": [
                    "network_segmentation", "automated_isolation", "forensic_imaging",
                    "memory_acquisition", "timeline_generation", "ioc_extraction"
                ],
                "tools": [
                    "velociraptor", "ftk_imager", "volatility", "wireshark",
                    "suricata", "zeek", "theHive", "cortex", "graylog",
                    "plaso", "timeline_explorer"
                ],
                "playbooks": [
                    "malware_infection", "data_breach", "ransomware",
                    "apt_intrusion", "insider_threat", "ddos_attack",
                    "business_email_compromise", "supply_chain_attack"
                ],
            },
            "ir_active_breach": {
                "capabilities": [
                    "full_packet_capture", "memory_forensics", "malware_analysis",
                    "threat_hunting", "ioc_pivoting", "attribution_analysis",
                    "evidence_preservation", "chain_of_custody"
                ],
                "tools": [
                    "velociraptor", "ftk_imager", "volatility", "wireshark",
                    "suricata", "zeek", "theHive", "cortex", "graylog",
                    "plaso", "timeline_explorer", "remnux", "flare_vm",
                    "cuckoo_sandbox", "yara", "ghidra", "ida_pro"
                ],
                "playbooks": [
                    "malware_infection", "data_breach", "ransomware",
                    "apt_intrusion", "insider_threat", "ddos_attack",
                    "business_email_compromise", "supply_chain_attack",
                    "cryptojacking", "web_defacement"
                ],
            },
        }

        ir_config = ir_configs.get(ir_profile, ir_configs["ir_preparation"])
        modified_config = copy.deepcopy(config)
        vms = modified_config.get("ludus", [])

        # Add IR server for advanced profiles
        if ir_profile in ["ir_containment", "ir_active_breach"]:
            ir_vm = {
                "vm_name": "{{{{ range_id }}}}-ir-workstation",
                "hostname": "IR-ANALYST",
                "template": "ubuntu-22-x64-desktop-template",
                "vlan": 10,
                "ip_last_octet": 120,
                "ram_gb": 32,
                "cpus": 8,
                "roles": [
                    "ludus_forensic_tools",
                    "ludus_thehive",
                    "ludus_cortex",
                    "ludus_volatility",
                    "ludus_remnux" if ir_profile == "ir_active_breach" else None,
                ],
            }
            ir_vm["roles"] = [r for r in ir_vm["roles"] if r]  # Remove None
            vms.append(ir_vm)

        return {
            "status": "success",
            "profile_type": "incident_response",
            "ir_level": ir_profile,
            "modified_config": modified_config,
            "capabilities": ir_config["capabilities"],
            "tools": ir_config["tools"],
            "playbooks": ir_config["playbooks"],
        }

    def apply_malware_analysis_profile(
        self, config: dict[str, Any], malware_profile: str
    ) -> dict[str, Any]:
        """Apply malware analysis profile for reverse engineering training.

        Args:
            config: Original Ludus configuration
            malware_profile: Level of malware analysis capabilities

        Returns:
            Dictionary with modified config and malware analysis setup
        """
        malware_configs = {
            "malware_basic": {
                "capabilities": [
                    "static_analysis", "strings_extraction", "file_identification",
                    "hash_analysis", "peid_detection", "basic_disassembly"
                ],
                "tools": [
                    "pestudio", "detect_it_easy", "exeinfo_pe", "strings",
                    "file_command", "md5deep", "ssdeep", "7zip"
                ],
                "vm_resources": {"ram_gb": 8, "cpus": 4},
                "automation_level": "manual",
                "sample_types": ["executables", "scripts", "documents"],
            },
            "malware_intermediate": {
                "capabilities": [
                    "static_analysis", "strings_extraction", "file_identification",
                    "hash_analysis", "peid_detection", "advanced_disassembly",
                    "dynamic_analysis", "behavioral_monitoring", "api_monitoring",
                    "network_monitoring", "sandbox_analysis"
                ],
                "tools": [
                    # Static analysis
                    "pestudio", "detect_it_easy", "exeinfo_pe", "strings",
                    "file_command", "md5deep", "ssdeep", "7zip", "pe_bear",
                    # Dynamic analysis
                    "procmon", "process_hacker", "wireshark", "fakenet_ng",
                    "regshot", "autoruns", "process_explorer"
                ],
                "vm_resources": {"ram_gb": 16, "cpus": 4},
                "automation_level": "semi-automated",
                "sample_types": ["executables", "scripts", "documents", "mobile_apps"],
            },
            "malware_advanced": {
                "capabilities": [
                    "static_analysis", "strings_extraction", "file_identification",
                    "hash_analysis", "peid_detection", "advanced_disassembly",
                    "dynamic_analysis", "behavioral_monitoring", "api_monitoring",
                    "network_monitoring", "sandbox_analysis", "debugger_analysis",
                    "unpacking", "deobfuscation", "code_emulation", "yara_rules",
                    "kernel_debugging", "memory_forensics"
                ],
                "tools": [
                    # Static analysis
                    "pestudio", "detect_it_easy", "exeinfo_pe", "strings",
                    "ida_free", "ghidra", "binary_ninja", "radare2", "pe_bear",
                    "capa", "floss", "retdec", "yara",
                    # Dynamic analysis
                    "procmon", "process_hacker", "wireshark", "fakenet_ng",
                    "x64dbg", "windbg", "ollydbg", "immunity_debugger",
                    "scylla", "de4dot", "upx", "volatility",
                    # Network
                    "inetsim", "burp_suite", "mitmproxy"
                ],
                "vm_resources": {"ram_gb": 32, "cpus": 8},
                "automation_level": "automated",
                "sample_types": ["executables", "scripts", "documents", "mobile_apps", "firmware"],
            },
            "malware_expert": {
                "capabilities": [
                    # All advanced capabilities plus:
                    "automated_detonation", "multi_os_analysis", "exploit_analysis",
                    "shellcode_analysis", "rootkit_analysis", "bootkit_analysis",
                    "cloud_malware_analysis", "apt_malware_analysis", "threat_intel_integration",
                    "ioc_extraction", "yara_rule_generation", "signature_generation"
                ],
                "tools": [
                    # All advanced tools plus:
                    "cuckoo_sandbox", "cape_sandbox", "joe_sandbox", "vmray",
                    "ida_pro", "binary_ninja_pro", "hopper", "x64dbg_advanced",
                    "volatility3", "rekall", "mandiant_redline", "axiom",
                    "misp", "opencti", "malware_bazaar", "virustotal_api",
                    "remnux_full", "flare_vm_full", "android_analysis_tools"
                ],
                "infrastructure": [
                    "remnux_vm", "flare_vm", "android_analysis_vm",
                    "linux_analysis_vm", "network_simulation", "isolated_network"
                ],
                "vm_resources": {"ram_gb": 64, "cpus": 12},
                "automation_level": "fully_automated",
                "sample_types": [
                    "executables", "scripts", "documents", "mobile_apps",
                    "firmware", "exploits", "rootkits", "bootkits"
                ],
            },
        }

        malware_config = malware_configs.get(malware_profile, malware_configs["malware_basic"])
        modified_config = copy.deepcopy(config)
        vms = modified_config.get("ludus", [])

        # Determine VMs to add based on profile level
        if malware_profile == "malware_basic":
            # Single Windows analysis VM
            analysis_vm = {
                "vm_name": "{{{{ range_id }}}}-malware-analysis",
                "hostname": "MALWARE-LAB",
                "template": "win10-22h2-x64-enterprise-template",
                "vlan": 99,  # Isolated VLAN
                "ip_last_octet": 10,
                "ram_gb": malware_config["vm_resources"]["ram_gb"],
                "cpus": malware_config["vm_resources"]["cpus"],
                "roles": [
                    "ludus_malware_basic_tools",
                    "ludus_isolated_network",
                ],
            }
            vms.append(analysis_vm)

        elif malware_profile == "malware_intermediate":
            # Windows analysis VM + REMnux
            windows_vm = {
                "vm_name": "{{{{ range_id }}}}-malware-win",
                "hostname": "MALWARE-WIN",
                "template": "win10-22h2-x64-enterprise-template",
                "vlan": 99,
                "ip_last_octet": 10,
                "ram_gb": 8,
                "cpus": 4,
                "roles": [
                    "ludus_malware_intermediate_tools",
                    "ludus_dynamic_analysis",
                    "ludus_isolated_network",
                ],
            }
            remnux_vm = {
                "vm_name": "{{{{ range_id }}}}-remnux",
                "hostname": "REMNUX",
                "template": "ubuntu-22-x64-server-template",
                "vlan": 99,
                "ip_last_octet": 20,
                "ram_gb": 8,
                "cpus": 4,
                "roles": [
                    "ludus_remnux_basic",
                    "ludus_isolated_network",
                ],
            }
            vms.extend([windows_vm, remnux_vm])

        elif malware_profile == "malware_advanced":
            # Full analysis lab: Windows, Linux, REMnux, Network sim
            windows_vm = {
                "vm_name": "{{{{ range_id }}}}-malware-win",
                "hostname": "MALWARE-WIN",
                "template": "win10-22h2-x64-enterprise-template",
                "vlan": 99,
                "ip_last_octet": 10,
                "ram_gb": 16,
                "cpus": 8,
                "roles": [
                    "ludus_flare_vm",
                    "ludus_advanced_debugging",
                    "ludus_isolated_network",
                ],
            }
            remnux_vm = {
                "vm_name": "{{{{ range_id }}}}-remnux",
                "hostname": "REMNUX",
                "template": "ubuntu-22-x64-server-template",
                "vlan": 99,
                "ip_last_octet": 20,
                "ram_gb": 16,
                "cpus": 4,
                "roles": [
                    "ludus_remnux_full",
                    "ludus_isolated_network",
                ],
            }
            network_sim = {
                "vm_name": "{{{{ range_id }}}}-inetsim",
                "hostname": "INETSIM",
                "template": "ubuntu-22-x64-server-template",
                "vlan": 99,
                "ip_last_octet": 1,
                "ram_gb": 4,
                "cpus": 2,
                "roles": [
                    "ludus_inetsim",
                    "ludus_fakenet",
                ],
            }
            vms.extend([windows_vm, remnux_vm, network_sim])

        elif malware_profile == "malware_expert":
            # Complete malware lab: Multiple OS analysis VMs + Sandbox + TI
            flare_vm = {
                "vm_name": "{{{{ range_id }}}}-flare-vm",
                "hostname": "FLARE-VM",
                "template": "win10-22h2-x64-enterprise-template",
                "vlan": 99,
                "ip_last_octet": 10,
                "ram_gb": 24,
                "cpus": 8,
                "roles": [
                    "ludus_flare_vm_full",
                    "ludus_advanced_debugging",
                    "ludus_isolated_network",
                ],
            }
            remnux_vm = {
                "vm_name": "{{{{ range_id }}}}-remnux",
                "hostname": "REMNUX",
                "template": "ubuntu-22-x64-server-template",
                "vlan": 99,
                "ip_last_octet": 20,
                "ram_gb": 16,
                "cpus": 4,
                "roles": [
                    "ludus_remnux_full",
                    "ludus_isolated_network",
                ],
            }
            sandbox_vm = {
                "vm_name": "{{{{ range_id }}}}-cuckoo",
                "hostname": "CUCKOO",
                "template": "ubuntu-22-x64-server-template",
                "vlan": 99,
                "ip_last_octet": 30,
                "ram_gb": 16,
                "cpus": 8,
                "roles": [
                    "ludus_cuckoo_sandbox",
                    "ludus_cape_sandbox",
                ],
            }
            network_sim = {
                "vm_name": "{{{{ range_id }}}}-inetsim",
                "hostname": "INETSIM",
                "template": "ubuntu-22-x64-server-template",
                "vlan": 99,
                "ip_last_octet": 1,
                "ram_gb": 4,
                "cpus": 2,
                "roles": [
                    "ludus_inetsim",
                    "ludus_fakenet",
                ],
            }
            threat_intel_vm = {
                "vm_name": "{{{{ range_id }}}}-threat-intel",
                "hostname": "THREAT-INTEL",
                "template": "ubuntu-22-x64-server-template",
                "vlan": 10,  # Management network
                "ip_last_octet": 150,
                "ram_gb": 8,
                "cpus": 4,
                "roles": [
                    "ludus_misp",
                    "ludus_malware_bazaar",
                ],
            }
            vms.extend([flare_vm, remnux_vm, sandbox_vm, network_sim, threat_intel_vm])

        return {
            "status": "success",
            "profile_type": "malware_analysis",
            "malware_level": malware_profile,
            "modified_config": modified_config,
            "capabilities": malware_config["capabilities"],
            "tools": malware_config["tools"],
            "vm_resources": malware_config["vm_resources"],
            "automation_level": malware_config["automation_level"],
            "sample_types": malware_config["sample_types"],
            "infrastructure": malware_config.get("infrastructure", []),
            "next_steps": [
                "1. Review the malware analysis setup",
                f"2. Verify isolated network (VLAN 99) configuration",
                "3. Deploy with: deploy_range(config=modified_config)",
                "4. Configure INetSim for internet simulation",
                "5. Test sample detonation in isolated environment",
                "6. Never connect analysis VMs to production network",
            ],
            "warnings": [
                "⚠️  Analysis VMs are in ISOLATED NETWORK (VLAN 99)",
                "⚠️  Never connect these systems to production networks",
                "⚠️  Use only for malware analysis training",
                "⚠️  Ensure proper snapshot/restore procedures",
                "⚠️  Handle malware samples with extreme caution",
            ],
        }

    def _generate_adversary_documentation(
        self, injections: list[dict[str, Any]], threat_level: str
    ) -> str:
        """Generate educational documentation for adversary profile."""
        if not injections:
            return "No vulnerabilities were injected."

        doc = f"""# Adversary Profile Documentation

## Threat Level: {threat_level.upper()}

This configuration has been enhanced with {len(injections)} realistic vulnerabilities for red team training.

## ⚠️  WARNING
- These vulnerabilities are for EDUCATIONAL PURPOSES ONLY
- Deploy ONLY in isolated lab environments
- NEVER expose these systems to production networks or the internet

## Injected Vulnerabilities

"""
        for idx, inj in enumerate(injections, 1):
            doc += f"""### {idx}. {inj['vulnerability_type'].replace('_', ' ').title()}

- **VM**: {inj['vm_name']}
- **Category**: {inj['category']}
- **Severity**: {inj['severity'].upper()}
- **Description**: {inj['description']}
- **Exploitation**: {inj['exploitation']}
- **Ansible Role**: `{inj['ansible_role']}`

"""

        doc += """## Exploitation Practice

Use these vulnerabilities to practice:
1. Reconnaissance and enumeration
2. Vulnerability identification
3. Exploitation techniques
4. Post-exploitation and pivoting
5. Privilege escalation
6. Lateral movement

## Remediation

After exploitation practice, remediate vulnerabilities to practice blue team skills:
- Apply security patches
- Strengthen password policies
- Configure proper ACLs and permissions
- Implement network segmentation
- Enable security logging and monitoring
"""

        return doc

    def _generate_defender_documentation(
        self,
        enhancements: list[dict[str, Any]],
        siem_type: str,
        monitoring_level: str,
        detection_rules: list[dict[str, Any]],
    ) -> str:
        """Generate documentation for defender profile."""
        if not enhancements:
            return "No monitoring enhancements were added."

        doc = f"""# Defender Profile Documentation

## Monitoring Level: {monitoring_level.upper()}
## SIEM: {siem_type.title()}

This configuration has been enhanced with {len(enhancements)} monitoring capabilities.

## Monitoring Enhancements

"""
        for idx, enh in enumerate(enhancements, 1):
            doc += f"""### {idx}. {enh['enhancement_type'].replace('_', ' ').title()}

- **VM**: {enh['vm_name']}
- **Category**: {enh['category']}
- **Description**: {enh['description']}
- **Capabilities**: {', '.join(enh['capabilities'])}
- **Ansible Role**: `{enh['ansible_role']}`

"""

        doc += f"""## Detection Rules

{len(detection_rules)} detection rules have been configured:

"""
        for idx, rule in enumerate(detection_rules, 1):
            doc += f"""### {idx}. {rule['rule_name']}

- **Category**: {rule['category']}
- **Severity**: {rule['severity'].upper()}
- **Description**: {rule['description']}
- **Indicators**: {', '.join(rule['indicators'])}

"""

        doc += f"""## {siem_type.title()} Configuration

After deployment:
1. Access {siem_type.title()} dashboard
2. Verify agent connectivity from all endpoints
3. Configure alerting thresholds
4. Create custom detection rules
5. Set up dashboards for SOC operations

## Blue Team Practice

Use this environment to practice:
1. Log analysis and correlation
2. Threat hunting
3. Incident detection and response
4. Security monitoring
5. Alert triage and investigation
6. Forensic analysis
"""

        return doc
