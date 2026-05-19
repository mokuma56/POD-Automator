# =============================================================================
# POD Automator — Packer build for Ubuntu 24.04 LTS appliance
#
# Produces an OVF/OVA (VMware) and/or VMDK that can be imported into:
#   - VMware ESXi / vSphere / Fusion / Workstation
#   - VirtualBox (convert OVA)
#   - Proxmox (import VMDK)
#
# Prerequisites (on the build machine):
#   brew install hashicorp/tap/packer        # macOS
#   packer plugins install github.com/hashicorp/vmware
#   packer plugins install github.com/hashicorp/virtualbox   # optional
#
# Build:
#   cd appliance/packer
#   packer init .
#   packer build pod-automator.pkr.hcl
#
# Output: appliance/packer/output-pod-automator/
# =============================================================================

packer {
  required_version = ">= 1.10.0"
  required_plugins {
    vmware = {
      source  = "github.com/hashicorp/vmware"
      version = "~> 1"
    }
  }
}

# ── Variables ────────────────────────────────────────────────────────────────
variable "vm_name" {
  default = "pod-automator-appliance"
}

variable "disk_size_mb" {
  default = 40960   # 40 GB
}

variable "memory_mb" {
  default = 4096    # 4 GB RAM
}

variable "cpus" {
  default = 2
}

variable "ssh_username" {
  default = "podmgr"
}

variable "ssh_password" {
  default = "C1sco12345"
}

variable "ubuntu_iso_url" {
  # Ubuntu 24.04.2 LTS server ISO
  default = "https://releases.ubuntu.com/24.04/ubuntu-24.04.2-live-server-amd64.iso"
}

variable "ubuntu_iso_checksum" {
  default = "sha256:d6fef1fc6a6f1a7c4b8d3ef6bc3051c0e5b7f3c4a7e5d3b1f8e2c4a6b8d0e2f4"
  # NOTE: Update this checksum before building.
  # Get the current value from: https://releases.ubuntu.com/24.04/SHA256SUMS
}

variable "repo_url" {
  default = "https://github.com/maokuma_cisco/pod-automator.git"
}

variable "headless" {
  default = true
}

# ── Source: VMware ISO ───────────────────────────────────────────────────────
source "vmware-iso" "pod_automator" {
  vm_name          = var.vm_name
  guest_os_type    = "ubuntu-64"
  headless         = var.headless

  iso_url          = var.ubuntu_iso_url
  iso_checksum     = var.ubuntu_iso_checksum

  disk_size        = var.disk_size_mb
  memory           = var.memory_mb
  cpus             = var.cpus

  network          = "nat"
  network_adapter_type = "vmxnet3"

  ssh_username     = var.ssh_username
  ssh_password     = var.ssh_password
  ssh_port         = 22
  ssh_timeout      = "60m"

  shutdown_command = "echo '${var.ssh_password}' | sudo -S shutdown -P now"

  output_directory = "output-${var.vm_name}"

  # Ubuntu 24.04 autoinstall boot command
  boot_wait = "5s"
  boot_command = [
    "e<wait>",
    "<down><down><down><end>",
    " autoinstall ds=nocloud;s=http://{{ .HTTPIP }}:{{ .HTTPPort }}/",
    "<F10>"
  ]

  http_directory = "http"

  vmx_data = {
    "virtualHW.version"    = "19"
    "tools.syncTime"       = "TRUE"
    "svga.autodetect"      = "TRUE"
  }

  # Export as OVA
  format = "ova"
}

# ── Build ────────────────────────────────────────────────────────────────────
build {
  name    = "pod-automator"
  sources = ["source.vmware-iso.pod_automator"]

  # Wait for cloud-init to finish
  provisioner "shell" {
    inline = [
      "echo 'Waiting for cloud-init to complete...'",
      "sudo cloud-init status --wait || true"
    ]
  }

  # Run the install script
  provisioner "shell" {
    environment_vars = [
      "REPO_URL=${var.repo_url}",
      "DEBIAN_FRONTEND=noninteractive"
    ]
    execute_command  = "echo '${var.ssh_password}' | sudo -S bash -c '{{ .Vars }} bash {{ .Path }}'"
    script           = "../install.sh"
  }

  # Drop a build-info file
  provisioner "shell" {
    inline = [
      "echo \"Built by Packer on $(date)\" | sudo tee /etc/pod-automator-build-info",
      "echo \"Repo: ${var.repo_url}\" | sudo tee -a /etc/pod-automator-build-info"
    ]
  }

  # Clean up build artefacts from the image
  provisioner "shell" {
    inline = [
      "sudo apt-get clean",
      "sudo rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*",
      "sudo truncate -s 0 /etc/machine-id",
      "sudo rm -f /etc/ssh/ssh_host_*",
      "sudo cloud-init clean --logs",
      "sudo sync"
    ]
  }

  post-processor "manifest" {
    output     = "output-${var.vm_name}/manifest.json"
    strip_path = true
  }
}
