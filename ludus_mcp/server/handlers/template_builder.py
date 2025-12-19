"""Custom template builder for creating OS templates with containers and applications."""

import json
import os
import re
import yaml
from pathlib import Path
from typing import Any
from urllib.parse import urljoin
import httpx
from ludus_mcp.utils.logging import get_logger

logger = get_logger(__name__)


class TemplateBuilder:
    """Build custom Ludus templates with OS configurations and containerized applications."""

    def __init__(self):
        """Initialize the template builder."""
        self.templates_dir = Path("/tmp/ludus-custom-templates")
        self.templates_dir.mkdir(exist_ok=True)

    def create_template(
        self,
        name: str,
        os_type: str | None = None,
        os_version: str | None = None,
        iso_url: str | None = None,
        iso_checksum: str | None = None,
        iso_checksum_type: str = "sha256",
        packages: list[str] | None = None,
        containers: list[dict[str, Any]] | None = None,
        ansible_roles: list[str] | None = None,
        description: str | None = None,
        disk_size: str = "40G",
        memory: int = 4096,
        cores: int = 2,
        additional_config: dict[str, Any] | None = None,
        auto_detect_os: bool = True,
    ) -> dict[str, Any]:
        """
        Create a custom OS template with optional containers and packages.
        
        Supports ANY operating system via ISO URL. If os_type is not provided,
        it will be auto-detected from the ISO URL/filename.

        Args:
            name: Template name (e.g., "ubuntu-docker-splunk")
            os_type: OS type (linux, windows, bsd, macos) - auto-detected if None
            os_version: OS version (e.g., "22.04", "2022", "11") - used for default ISO lookup
            iso_url: URL to OS ISO (required if os_version not in defaults)
            iso_checksum: Optional ISO checksum for verification
            iso_checksum_type: Checksum type (default: "sha256")
            packages: List of packages to install
            containers: List of container configurations
            ansible_roles: List of Ansible roles to apply
            description: Template description
            disk_size: Disk size (default: "40G")
            memory: Memory in MB (default: 4096)
            cores: CPU cores (default: 2)
            additional_config: Additional Packer configuration options
            auto_detect_os: Auto-detect OS type from ISO URL (default: True)

        Returns:
            Template configuration and file paths
        """
        logger.info(f"Creating custom template: {name}")

        template_dir = self.templates_dir / name
        template_dir.mkdir(exist_ok=True)

        # Auto-detect OS type if not provided and ISO URL is available
        if os_type is None and iso_url:
            detected = self.detect_os_type_from_iso(iso_url)
            os_type = detected["os_family"]
            logger.info(f"Auto-detected OS type: {os_type} from ISO URL")
        elif os_type is None:
            # Default to linux if nothing specified
            os_type = "linux"
            logger.warning("No OS type specified and no ISO URL provided, defaulting to 'linux'")

        # Generate template configuration
        config = self._generate_template_config(
            name=name,
            os_type=os_type,
            os_version=os_version,
            iso_url=iso_url,
            iso_checksum=iso_checksum,
            iso_checksum_type=iso_checksum_type,
            description=description,
            disk_size=disk_size,
            memory=memory,
            cores=cores,
            additional_config=additional_config,
            auto_detect_os=auto_detect_os,
        )

        # Generate provisioning scripts
        provisioning_scripts = self._generate_provisioning_scripts(
            os_type=os_type,
            packages=packages or [],
            containers=containers or [],
        )

        # Generate Ansible playbook if roles specified
        ansible_playbook = None
        if ansible_roles:
            ansible_playbook = self._generate_ansible_playbook(ansible_roles)

        # Write files to template directory
        self._write_template_files(
            template_dir=template_dir,
            config=config,
            provisioning_scripts=provisioning_scripts,
            ansible_playbook=ansible_playbook,
        )

        return {
            "name": name,
            "directory": str(template_dir),
            "os_type": os_type,
            "os_version": os_version,
            "has_containers": bool(containers),
            "has_ansible": bool(ansible_roles),
            "files_created": [
                f.name for f in template_dir.iterdir() if f.is_file()
            ],
        }

    def create_container_template(
        self,
        name: str,
        base_os: str,
        containers: list[dict[str, Any]],
        description: str | None = None,
    ) -> dict[str, Any]:
        """
        Create a template specifically for running containerized applications.

        Args:
            name: Template name
            base_os: Base OS (ubuntu-22.04, debian-12, rocky-9, etc.)
            containers: List of container configurations with image, ports, volumes, env
            description: Template description

        Returns:
            Template configuration
        """
        logger.info(f"Creating container template: {name}")

        # Parse base OS
        os_parts = base_os.lower().split("-")
        os_type = "linux"
        os_name = os_parts[0]
        os_version = os_parts[1] if len(os_parts) > 1 else "latest"

        # Add Docker/Podman to packages
        packages = ["docker.io", "docker-compose", "curl", "wget"]

        return self.create_template(
            name=name,
            os_type=os_type,
            os_version=f"{os_name}-{os_version}",
            packages=packages,
            containers=containers,
            description=description or f"Container host running: {', '.join([c.get('name', c.get('image', 'unknown')) for c in containers])}",
        )

    def detect_os_type_from_iso(self, iso_url: str, os_type: str | None = None) -> dict[str, Any]:
        """Detect OS type and boot configuration from ISO URL or filename.
        
        Args:
            iso_url: ISO URL or filename
            os_type: Optional explicit OS type override
            
        Returns:
            Dictionary with detected OS information and boot configuration hints
        """
        iso_lower = iso_url.lower()
        detected_info = {
            "os_family": "unknown",
            "boot_type": "auto",
            "needs_preseed": False,
            "needs_autounattend": False,
            "suggested_boot_wait": "10s",
        }
        
        # If explicit OS type provided, use it
        if os_type:
            detected_info["os_family"] = os_type.lower()
        
        # Detect from URL/filename patterns
        if any(x in iso_lower for x in ["ubuntu", "debian", "kali", "parrot", "mint", "elementary"]):
            detected_info["os_family"] = "linux"
            detected_info["boot_type"] = "linux"
            detected_info["needs_preseed"] = True
        elif any(x in iso_lower for x in ["rocky", "centos", "rhel", "fedora", "alma", "oracle"]):
            detected_info["os_family"] = "linux"
            detected_info["boot_type"] = "linux"
            detected_info["needs_preseed"] = True
        elif any(x in iso_lower for x in ["arch", "manjaro", "endeavour"]):
            detected_info["os_family"] = "linux"
            detected_info["boot_type"] = "linux"
            detected_info["needs_preseed"] = False  # Arch uses different boot
        elif any(x in iso_lower for x in ["windows", "win", "server"]):
            detected_info["os_family"] = "windows"
            detected_info["boot_type"] = "windows"
            detected_info["needs_autounattend"] = True
            detected_info["suggested_boot_wait"] = "2m"
        elif any(x in iso_lower for x in ["freebsd", "openbsd", "netbsd"]):
            detected_info["os_family"] = "bsd"
            detected_info["boot_type"] = "bsd"
        elif any(x in iso_lower for x in ["macos", "darwin"]):
            detected_info["os_family"] = "macos"
            detected_info["boot_type"] = "macos"
        else:
            # Unknown - default to Linux assumptions
            detected_info["os_family"] = "linux"
            detected_info["boot_type"] = "linux"
            detected_info["needs_preseed"] = True
        
        return detected_info
    
    def _generate_template_config(
        self,
        name: str,
        os_type: str,
        os_version: str | None,
        iso_url: str | None,
        description: str | None,
        iso_checksum: str | None = None,
        iso_checksum_type: str = "sha256",
        disk_size: str = "40G",
        memory: int = 4096,
        cores: int = 2,
        additional_config: dict[str, Any] | None = None,
        auto_detect_os: bool = True,
    ) -> dict[str, Any]:
        """Generate Packer template configuration.
        
        Supports any ISO URL for building custom templates.
        Can auto-detect OS type from ISO URL if os_type is not provided.
        """
        # Extended default ISOs for common OS types
        default_isos = {
            # Ubuntu
            "ubuntu-22.04": "https://releases.ubuntu.com/22.04/ubuntu-22.04.3-live-server-amd64.iso",
            "ubuntu-20.04": "https://releases.ubuntu.com/20.04/ubuntu-20.04.6-live-server-amd64.iso",
            "ubuntu-18.04": "https://releases.ubuntu.com/18.04/ubuntu-18.04.6-live-server-amd64.iso",
            # Debian
            "debian-12": "https://cdimage.debian.org/debian-cd/current/amd64/iso-cd/debian-12.4.0-amd64-netinst.iso",
            "debian-11": "https://cdimage.debian.org/debian-cd/current/amd64/iso-cd/debian-11.9.0-amd64-netinst.iso",
            # Rocky Linux
            "rocky-9": "https://download.rockylinux.org/pub/rocky/9/isos/x86_64/Rocky-9.3-x86_64-minimal.iso",
            "rocky-8": "https://download.rockylinux.org/pub/rocky/8/isos/x86_64/Rocky-8.9-x86_64-minimal.iso",
            # CentOS Stream
            "centos-stream-9": "https://mirror.stream.centos.org/9-stream/BaseOS/x86_64/iso/CentOS-Stream-9-latest-x86_64-boot.iso",
            # Windows
            "windows-2022": "https://software-download.microsoft.com/download/sg/20348.169.210806-2348.fe_release_svc_refresh_SERVER_EVAL_x64FRE_en-us.iso",
            "windows-2019": "https://software-download.microsoft.com/download/pr/17763.737.190906-2324.rs5_release_svc_refresh_SERVER_EVAL_x64FRE_en-us_1.iso",
            "windows-11": "https://software-download.microsoft.com/download/sg/22000.194.210913-1125.co_release_svc_refresh_CLIENTENTERPRISEEVAL_OEMRET_x64FRE_en-us.iso",
            "windows-10": "https://software-download.microsoft.com/download/pr/19041.508.2008-1905.2008-1.19041.508-2008_release_svc_refresh_CLIENTENTERPRISEEVAL_OEMRET_x64FRE_en-us.iso",
            # Kali Linux
            "kali": "https://cdimage.kali.org/kali-2024.1/kali-linux-2024.1-live-amd64.iso",
            # Parrot OS
            "parrot": "https://deb.parrot.sh/parrot/iso/6.0/Parrot-security-6.0_amd64.iso",
        }

        # Use provided ISO URL or lookup default
        iso = iso_url or default_isos.get(os_version or "", "")
        
        if not iso:
            if iso_url:
                iso = iso_url
            else:
                raise ValueError(
                    f"No ISO URL found for os_version '{os_version}' and no iso_url provided. "
                    f"Please provide an iso_url parameter. "
                    f"Use get_common_iso_urls() to find ISO URLs for common operating systems."
                )
        
        # Auto-detect OS type from ISO if needed
        if auto_detect_os and iso:
            detected = self.detect_os_type_from_iso(iso, os_type)
            if detected["os_family"] != "unknown" and os_type == "unknown":
                logger.info(f"Auto-detected OS family: {detected['os_family']} from ISO URL")
                os_type = detected["os_family"]

        # Build Packer configuration
        builder_config = {
            "type": "proxmox-iso",
            "proxmox_url": "{{ env `PROXMOX_URL` }}",
            "username": "{{ env `PROXMOX_USERNAME` }}",
            "password": "{{ env `PROXMOX_PASSWORD` }}",
            "node": "{{ env `PROXMOX_NODE` }}",
            "vm_name": name,
            "template_description": description or f"Custom {os_type} template: {name}",
            "iso_url": iso,
            "iso_checksum": iso_checksum or "none",
            "iso_checksum_type": iso_checksum_type if iso_checksum else "none",
            "insecure_skip_tls_verify": True,
            "cores": cores,
            "memory": memory,
            "disk_size": disk_size,
            "network_adapters": [{
                "bridge": "vmbr0",
                "model": "virtio"
            }],
            "boot_wait": "10s",
        }
        
        # Auto-detect OS configuration if ISO provided
        detected_os = None
        if iso and auto_detect_os:
            detected_os = self.detect_os_type_from_iso(iso, os_type)
        
        # Add OS-specific boot configuration
        if os_type == "linux" or (detected_os and detected_os["boot_type"] == "linux"):
            # Generic Linux boot command (works for most Debian/Ubuntu-based)
            builder_config.update({
                "boot_command": [
                    "<esc><wait>",
                    "<esc><wait>",
                    "<enter><wait>",
                    "/install/vmlinuz<wait>",
                    " auto<wait>",
                    " console-setup/ask_detect=false<wait>",
                    " console-setup/layoutcode=us<wait>",
                    " console-setup/modelcode=pc105<wait>",
                    " debian-installer=en_US<wait>",
                    " fb=false<wait>",
                    " initrd=/install/initrd.gz<wait>",
                    " kbd-chooser/method=us<wait>",
                    " keyboard-configuration/layout=USA<wait>",
                    " keyboard-configuration/variant=USA<wait>",
                    " locale=en_US<wait>",
                    " netcfg/get_domain=vm<wait>",
                    " netcfg/get_hostname=packer<wait>",
                    " noapic<wait>",
                ] + (["preseed/url=http://{{ .HTTPIP }}:{{ .HTTPPort }}/preseed.cfg<wait>"] if (detected_os and detected_os.get("needs_preseed", True)) else []) + [
                    " -- <wait>",
                    "<enter><wait>"
                ],
                "http_directory": "http",
            })
        elif os_type == "windows" or (detected_os and detected_os["boot_type"] == "windows"):
            builder_config.update({
                "boot_command": [
                    "<enter><wait>",
                    "<f8><wait>",
                    "<down><down><down><down><down><enter><wait>",
                    "<down><down><down><down><down><enter><wait>",
                ],
                "http_directory": "http",
                "floppy_files": [
                    "scripts/autounattend.xml"
                ] if (detected_os and detected_os.get("needs_autounattend", True)) else [],
            })
            builder_config["boot_wait"] = detected_os.get("suggested_boot_wait", "2m") if detected_os else "2m"
        elif detected_os and detected_os["boot_type"] == "bsd":
            # BSD systems typically use different boot methods
            builder_config.update({
                "boot_command": [
                    "<enter><wait>",
                ],
                "boot_wait": "30s",
            })
        else:
            # Generic/unknown OS - minimal boot configuration
            logger.warning(f"Unknown OS type '{os_type}', using generic boot configuration")
            builder_config.update({
                "boot_command": [
                    "<enter><wait>",
                ],
                "boot_wait": "10s",
            })

        # Merge any additional configuration
        if additional_config:
            builder_config.update(additional_config)

        config = {
            "builders": [builder_config],
            "provisioners": [],
        }

        return config

    def _generate_provisioning_scripts(
        self,
        os_type: str,
        packages: list[str],
        containers: list[dict[str, Any]],
    ) -> dict[str, str]:
        """Generate provisioning scripts for the template."""
        scripts = {}

        if os_type == "linux":
            scripts["provision.sh"] = self._generate_linux_provision_script(packages, containers)
            if containers:
                scripts["start-containers.sh"] = self._generate_container_startup_script(containers)
                scripts["docker-compose.yml"] = self._generate_docker_compose(containers)

        elif os_type == "windows":
            scripts["provision.ps1"] = self._generate_windows_provision_script(packages, containers)

        return scripts

    def _generate_linux_provision_script(
        self,
        packages: list[str],
        containers: list[dict[str, Any]],
    ) -> str:
        """Generate Linux provisioning script."""
        script = """#!/bin/bash
set -e

echo "=== Starting Linux Provisioning ==="

# Update system
echo "Updating system packages..."
apt-get update || yum update -y || true
apt-get upgrade -y || yum upgrade -y || true

# Install requested packages
echo "Installing packages..."
"""

        # Add package installation
        if packages:
            apt_packages = " ".join(packages)
            script += f"""
if command -v apt-get &> /dev/null; then
    apt-get install -y {apt_packages}
elif command -v yum &> /dev/null; then
    yum install -y {apt_packages}
fi
"""

        # Add Docker setup if containers requested
        if containers:
            script += """
# Install Docker if not present
if ! command -v docker &> /dev/null; then
    echo "Installing Docker..."
    curl -fsSL https://get.docker.com | sh
    systemctl enable docker
    systemctl start docker
fi

# Install Docker Compose
if ! command -v docker-compose &> /dev/null; then
    echo "Installing Docker Compose..."
    curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    chmod +x /usr/local/bin/docker-compose
fi

echo "=== Docker installed successfully ==="
"""

        script += """
echo "=== Provisioning complete ==="
"""
        return script

    def _generate_windows_provision_script(
        self,
        packages: list[str],
        containers: list[dict[str, Any]],
    ) -> str:
        """Generate Windows provisioning script."""
        script = """# Windows Provisioning Script
Write-Host "=== Starting Windows Provisioning ===" -ForegroundColor Green

# Install Chocolatey if not present
if (!(Get-Command choco -ErrorAction SilentlyContinue)) {
    Write-Host "Installing Chocolatey..."
    Set-ExecutionPolicy Bypass -Scope Process -Force
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
    iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
}

# Install requested packages
"""

        if packages:
            for package in packages:
                script += f"""
Write-Host "Installing {package}..."
choco install -y {package}
"""

        if containers:
            script += """
# Install Docker Desktop for Windows
Write-Host "Installing Docker Desktop..."
choco install -y docker-desktop
"""

        script += """
Write-Host "=== Provisioning complete ===" -ForegroundColor Green
"""
        return script

    def _generate_container_startup_script(
        self,
        containers: list[dict[str, Any]],
    ) -> str:
        """Generate script to start containers on boot."""
        script = """#!/bin/bash
# Start containers on boot

cd /opt/containers

echo "Starting containers..."
docker-compose up -d

echo "Containers started successfully"
docker-compose ps
"""
        return script

    def _generate_docker_compose(
        self,
        containers: list[dict[str, Any]],
    ) -> str:
        """Generate docker-compose.yml file."""
        compose = {
            "version": "3.8",
            "services": {}
        }

        for container in containers:
            service_name = container.get("name", container["image"].split("/")[-1].split(":")[0])
            service_config = {
                "image": container["image"],
                "container_name": service_name,
                "restart": "unless-stopped",
            }

            # Add ports
            if "ports" in container:
                service_config["ports"] = container["ports"]

            # Add environment variables
            if "environment" in container:
                service_config["environment"] = container["environment"]

            # Add volumes
            if "volumes" in container:
                service_config["volumes"] = container["volumes"]

            # Add command
            if "command" in container:
                service_config["command"] = container["command"]

            # Add networks
            if "networks" in container:
                service_config["networks"] = container["networks"]

            compose["services"][service_name] = service_config

        import yaml
        return yaml.dump(compose, default_flow_style=False, sort_keys=False)

    def _generate_ansible_playbook(
        self,
        roles: list[str],
    ) -> str:
        """Generate Ansible playbook for applying roles."""
        playbook = [{
            "name": "Configure template with Ansible roles",
            "hosts": "all",
            "become": True,
            "roles": roles,
        }]

        import yaml
        return yaml.dump(playbook, default_flow_style=False, sort_keys=False)
    
    def _generate_packer_hcl(self, config: dict[str, Any]) -> str:
        """Generate Packer HCL configuration from dict.
        
        Converts the configuration dictionary to proper HCL format.
        """
        builder = config["builders"][0]
        
        hcl = """packer {
  required_plugins {
    proxmox = {
      source  = "github.com/hashicorp/proxmox"
      version = "~> 1"
    }
  }
}

source "proxmox-iso" "template" {
"""
        
        # Add builder configuration
        hcl += f'  proxmox_url = "{builder["proxmox_url"]}"\n'
        hcl += f'  username = "{builder["username"]}"\n'
        hcl += f'  password = "{builder["password"]}"\n'
        hcl += f'  node = "{builder["node"]}"\n'
        hcl += f'  vm_name = "{builder["vm_name"]}"\n'
        hcl += f'  template_description = "{builder["template_description"]}"\n'
        hcl += f'  iso_url = "{builder["iso_url"]}"\n'
        hcl += f'  iso_checksum = "{builder["iso_checksum"]}"\n'
        if builder.get("iso_checksum_type") and builder["iso_checksum"] != "none":
            hcl += f'  iso_checksum_type = "{builder["iso_checksum_type"]}"\n'
        hcl += f'  insecure_skip_tls_verify = {str(builder["insecure_skip_tls_verify"]).lower()}\n'
        hcl += f'  cores = {builder["cores"]}\n'
        hcl += f'  memory = {builder["memory"]}\n'
        hcl += f'  disk_size = "{builder["disk_size"]}"\n'
        hcl += f'  boot_wait = "{builder["boot_wait"]}"\n'
        
        # Add network adapters
        if "network_adapters" in builder:
            hcl += "\n  network_adapters {\n"
            for adapter in builder["network_adapters"]:
                hcl += f'    bridge = "{adapter["bridge"]}"\n'
                hcl += f'    model = "{adapter["model"]}"\n'
            hcl += "  }\n"
        
        # Add boot command if present
        if "boot_command" in builder:
            hcl += "\n  boot_command = [\n"
            for cmd in builder["boot_command"]:
                hcl += f'    "{cmd}",\n'
            hcl += "  ]\n"
        
        # Add http_directory if present
        if "http_directory" in builder:
            hcl += f'  http_directory = "{builder["http_directory"]}"\n'
        
        # Add floppy_files if present
        if "floppy_files" in builder:
            hcl += "\n  floppy_files = [\n"
            for file in builder["floppy_files"]:
                hcl += f'    "{file}",\n'
            hcl += "  ]\n"
        
        hcl += """}

build {
  sources = ["source.proxmox-iso.template"]
"""
        
        # Add provisioners if any
        if config.get("provisioners"):
            for provisioner in config["provisioners"]:
                hcl += "\n  provisioner {\n"
                for key, value in provisioner.items():
                    if isinstance(value, str):
                        hcl += f'    {key} = "{value}"\n'
                    elif isinstance(value, bool):
                        hcl += f'    {key} = {str(value).lower()}\n'
                    elif isinstance(value, (int, float)):
                        hcl += f'    {key} = {value}\n'
                hcl += "  }\n"
        
        hcl += "}\n"
        
        return hcl

    def _write_template_files(
        self,
        template_dir: Path,
        config: dict[str, Any],
        provisioning_scripts: dict[str, str],
        ansible_playbook: str | None,
    ) -> None:
        """Write template files to directory."""
        # Write Packer HCL config (proper HCL format, not JSON)
        config_file = template_dir / "template.pkr.hcl"
        with open(config_file, "w") as f:
            f.write(self._generate_packer_hcl(config))

        # Write provisioning scripts
        for filename, content in provisioning_scripts.items():
            script_file = template_dir / filename
            with open(script_file, "w") as f:
                f.write(content)

            # Make shell scripts executable
            if filename.endswith(".sh"):
                os.chmod(script_file, 0o755)

        # Write Ansible playbook if present
        if ansible_playbook:
            playbook_file = template_dir / "playbook.yml"
            with open(playbook_file, "w") as f:
                f.write(ansible_playbook)

        # Write README
        readme_file = template_dir / "README.md"
        with open(readme_file, "w") as f:
            f.write(self._generate_readme(template_dir.name, config, provisioning_scripts))

    def _generate_readme(
        self,
        name: str,
        config: dict[str, Any],
        scripts: dict[str, str],
    ) -> str:
        """Generate README for the template."""
        readme = f"""# Custom Ludus Template: {name}

This is a custom-generated Ludus template created by the Ludus MCP server.

## Contents

"""
        for filename in scripts.keys():
            readme += f"- `{filename}` - Provisioning script\n"

        readme += """
## Usage

1. Add the template to Ludus:
   ```bash
   ludus templates add --directory /path/to/this/template
   ```

2. Build the template:
   ```bash
   ludus templates build --template {name}
   ```

3. Use in your range configuration:
   ```yaml
   ludus:
     - vm_name: my-vm
       template: {name}
   ```

## Customization

You can modify the provisioning scripts and template configuration to suit your needs.

Generated by Ludus MCP Server
"""
        return readme

    def get_common_container_configs(self) -> dict[str, dict[str, Any]]:
        """Get pre-configured containers for common applications."""
        return {
            "splunk": {
                "image": "splunk/splunk:latest",
                "ports": ["8000:8000", "8088:8088", "9997:9997"],
                "environment": {
                    "SPLUNK_START_ARGS": "--accept-license",
                    "SPLUNK_PASSWORD": "changeme123!",
                },
                "volumes": [
                    "/opt/splunk/etc:/opt/splunk/etc",
                    "/opt/splunk/var:/opt/splunk/var",
                ],
            },
            "wazuh": {
                "image": "wazuh/wazuh:latest",
                "ports": ["443:443", "1514:1514", "1515:1515", "55000:55000"],
                "environment": {
                    "WAZUH_API_PASSWORD": "changeme",
                },
            },
            "elk": {
                "image": "sebp/elk:latest",
                "ports": ["5601:5601", "9200:9200", "5044:5044"],
                "environment": {
                    "ES_JAVA_OPTS": "-Xms2g -Xmx2g",
                },
            },
            "nginx": {
                "image": "nginx:latest",
                "ports": ["80:80", "443:443"],
                "volumes": [
                    "/etc/nginx/conf.d:/etc/nginx/conf.d",
                    "/var/www/html:/usr/share/nginx/html",
                ],
            },
            "postgres": {
                "image": "postgres:15",
                "ports": ["5432:5432"],
                "environment": {
                    "POSTGRES_PASSWORD": "changeme",
                    "POSTGRES_DB": "mydb",
                },
                "volumes": [
                    "/var/lib/postgresql/data:/var/lib/postgresql/data",
                ],
            },
            "redis": {
                "image": "redis:latest",
                "ports": ["6379:6379"],
                "command": "redis-server --appendonly yes",
                "volumes": [
                    "/data:/data",
                ],
            },
            "grafana": {
                "image": "grafana/grafana:latest",
                "ports": ["3000:3000"],
                "environment": {
                    "GF_SECURITY_ADMIN_PASSWORD": "changeme",
                },
                "volumes": [
                    "/var/lib/grafana:/var/lib/grafana",
                ],
            },
        }
    
    def get_latest_kali_weekly_iso(self) -> dict[str, str]:
        """Fetch the latest Kali Linux weekly ISO URL and checksum.
        
        Parses the Kali weekly directory to find the most recent ISO.
        Uses synchronous httpx for compatibility.
        
        Returns:
            Dictionary with 'iso_url', 'iso_checksum', 'iso_filename', 'year', and 'week'
            
        Raises:
            Exception: If unable to fetch or parse the directory
        """
        base_url = "https://cdimage.kali.org/kali-weekly/"
        checksums_url = urljoin(base_url, "SHA256SUMS")
        
        logger.info("Fetching latest Kali Linux weekly ISO information...")
        
        try:
            with httpx.Client(timeout=30.0, follow_redirects=True) as client:
                # Fetch the checksums file
                response = client.get(checksums_url)
                response.raise_for_status()
                checksums_content = response.text
            
            # Parse checksums to find latest installer ISO
            # Format: checksum  kali-linux-YYYY-W##-installer-amd64.iso
            iso_pattern = re.compile(r'^([a-f0-9]{64})\s+kali-linux-(\d{4})-W(\d{2})-installer-amd64\.iso$', re.MULTILINE)
            matches = iso_pattern.findall(checksums_content)
            
            if not matches:
                raise Exception("No Kali weekly installer ISOs found in checksums")
            
            # Sort by year and week (latest first)
            matches.sort(key=lambda x: (int(x[1]), int(x[2])), reverse=True)
            latest = matches[0]
            
            checksum, year, week = latest
            iso_filename = f"kali-linux-{year}-W{week}-installer-amd64.iso"
            iso_url = urljoin(base_url, iso_filename)
            
            logger.info(f"Found latest Kali weekly: {iso_filename} (Week {week}, {year})")
            
            return {
                "iso_url": iso_url,
                "iso_checksum": checksum,
                "iso_filename": iso_filename,
                "year": year,
                "week": week,
            }
        except httpx.HTTPError as e:
            raise Exception(f"Network error fetching Kali weekly ISO: {e}")
        except Exception as e:
            raise Exception(f"Error fetching latest Kali weekly ISO: {e}")
    
    def create_kali_weekly_template(
        self,
        name: str = "kali-weekly-latest",
        packages: list[str] | None = None,
        ansible_roles: list[str] | None = None,
        description: str | None = None,
        disk_size: str = "40G",
        memory: int = 4096,
        cores: int = 2,
        iso_info: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Create a Kali Linux weekly template with automatic latest ISO detection.
        
        Args:
            name: Template name (default: "kali-weekly-latest")
            packages: Additional packages to install
            ansible_roles: Ansible roles to apply
            description: Template description
            disk_size: Disk size (default: "40G")
            memory: Memory in MB (default: 4096)
            cores: CPU cores (default: 2)
            iso_info: Optional pre-fetched ISO info (if None, will fetch latest)
            
        Returns:
            Template creation result with file paths and ISO information
        """
        logger.info(f"Creating Kali Linux weekly template: {name}")
        
        # Use provided ISO info or fetch latest
        if iso_info is None:
            try:
                iso_info = self.get_latest_kali_weekly_iso()
            except Exception as e:
                logger.error(f"Failed to fetch latest Kali weekly ISO: {e}")
                raise
        
        # Create template with Kali ISO
        result = self.create_template(
            name=name,
            os_type="linux",
            os_version="kali",
            iso_url=iso_info["iso_url"],
            iso_checksum=iso_info["iso_checksum"],
            iso_checksum_type="sha256",
            packages=packages or [],
            ansible_roles=ansible_roles,
            description=description or f"Kali Linux Weekly {iso_info['year']} Week {iso_info['week']}",
            disk_size=disk_size,
            memory=memory,
            cores=cores,
        )
        
        # Add ISO information to result
        result["kali_iso_info"] = {
            "filename": iso_info["iso_filename"],
            "year": iso_info["year"],
            "week": iso_info["week"],
            "checksum": iso_info["iso_checksum"],
        }
        
        return result
