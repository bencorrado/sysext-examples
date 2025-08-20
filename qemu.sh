#!/usr/bin/env bash
#
# QEMU system extension script
#
# This script creates a QEMU system extension for Ubuntu 24.04
# with support for Intel Gen 12 processors and KVM acceleration.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

source ./shared.sh

# Define service mappings for GitHub Actions workflow
defineServiceMappings "qemu-kvm run-qemu.mount libvirtd virtlogd virtlockd"

if [ -n "$QEMU_VERSION" ]; then
  latest_version="$QEMU_VERSION"
else
  # Update package cache first
  printf "${GREEN}Updating package cache...\n"
  if command -v sudo >/dev/null 2>&1; then
    sudo apt-get update -qq
  else
    apt-get update -qq
  fi

  # Get the latest QEMU version from Ubuntu 24.04 repositories
  # Try multiple methods to get a working version
  printf "${GREEN}Checking available QEMU versions...\n"
  apt-cache policy qemu-system-x86 || true

  latest_version=$(apt-cache policy qemu-system-x86 | grep Candidate | awk '{print $2}' | cut -d':' -f2 | cut -d'+' -f1)

  # If that fails, try to get any available version
  if [ -z "$latest_version" ] || [ "$latest_version" = "(none)" ]; then
    printf "${YELLOW}Candidate version not found, trying madison...\n"
    latest_version=$(apt-cache madison qemu-system-x86 | head -1 | awk '{print $3}' | cut -d':' -f2 | cut -d'+' -f1)
  fi

  # If still no version, use a fallback approach - just use "latest" as identifier
  if [ -z "$latest_version" ] || [ "$latest_version" = "(none)" ]; then
    printf "${YELLOW}Could not determine specific QEMU version, using 'latest' identifier\n"
    latest_version="latest"
  fi
fi

printf "${GREEN}Using version %s\n" "$latest_version"

FORCE=${FORCE:-false}

if [ -z "$latest_version" ]; then
  printf "${RED}Could not determine QEMU version\n"
  exit 1
fi

if [ -d qemu-"$latest_version" ]; then
  if [ "$FORCE" == "false" ]; then
    printf "${RED}Version already exists\n"
    exit 0
  fi
  printf "${YELLOW}Version exists but FORCE was set, removing existing version\n"
  rm -Rf qemu-"$latest_version"
fi

# Store the original directory path
SCRIPT_DIR=$(pwd)

mkdir -p qemu-"$latest_version"
pushd qemu-"$latest_version" > /dev/null || exit 1

# Store the qemu directory path
QEMU_DIR=$(pwd)

createDirs

# Create additional directories for QEMU
mkdir -p usr/local/share/qemu/init
mkdir -p usr/local/lib/systemd/system/multi-user.target.d
mkdir -p usr/local/lib/x86_64-linux-gnu/qemu
mkdir -p usr/local/lib/qemu
mkdir -p usr/local/share/qemu/scripts
mkdir -p etc/default
mkdir -p etc/qemu

printf "${GREEN}Downloading QEMU packages\n"

# Create a temporary directory for package extraction
tmpDir=$(mktemp -d)
# Ensure the temporary directory is accessible by apt
chmod 755 "$tmpDir"

# Download the main QEMU packages we need
packages=(
  "qemu-system-x86"
  "qemu-system-common"
  "qemu-system-data"
  "qemu-utils"
  "qemu-block-extra"
  "swtpm"
  "swtpm-tools"
  "libtpms0"
  "libvirt-daemon-system"
  "libvirt-clients"
  "libvirt-daemon-driver-qemu"
  "trousers"
  "libusb-1.0-0"
  "usbutils"
)

# Download packages
for package in "${packages[@]}"; do
  printf "${GREEN}Downloading package: %s\n" "$package"
  cd "$tmpDir"

  # Show what version will be downloaded
  available_version=$(apt-cache policy "$package" | grep Candidate | awk '{print $2}')
  printf "${GREEN}Available version for %s: %s\n" "$package" "$available_version"

  # Try to download the package, with retries and fallbacks
  # Note: apt-get download should not use sudo to avoid permission issues
  if ! apt-get download "$package"; then
    printf "${YELLOW}Failed to download %s, trying with --allow-unauthenticated\n" "$package"
    if ! apt-get download --allow-unauthenticated "$package"; then
      printf "${YELLOW}Failed to download %s, trying apt-cache search for alternatives\n" "$package"

      # For critical packages, try to find alternatives
      case "$package" in
        "qemu-system-x86")
          # Try qemu-system-x86-64 as alternative
          if apt-cache search qemu-system-x86-64 | grep -q qemu-system-x86-64; then
            printf "${YELLOW}Trying alternative: qemu-system-x86-64\n"
            apt-get download qemu-system-x86-64 || true
          fi
          ;;
        *)
          printf "${YELLOW}Skipping unavailable package: %s\n" "$package"
          ;;
      esac
    fi
  fi
done

# Check if we have any packages downloaded
cd "$tmpDir"
if ! ls *.deb >/dev/null 2>&1; then
  printf "${RED}No packages were successfully downloaded. Cannot proceed.\n"
  exit 1
fi

# Extract packages
printf "${GREEN}Extracting QEMU packages\n"
for deb in *.deb; do
  if [ -f "$deb" ]; then
    printf "${GREEN}Extracting %s\n" "$deb"
    dpkg-deb -x "$deb" extracted/
  fi
done

# Copy files to the proper locations
cd extracted
printf "${GREEN}Installing QEMU binaries and libraries\n"

# Copy binaries from all packages
if [ -d usr/bin ]; then
  cp -a usr/bin/* "$QEMU_DIR/usr/local/bin/" 2>/dev/null || true
fi

if [ -d usr/sbin ]; then
  cp -a usr/sbin/* "$QEMU_DIR/usr/local/sbin/" 2>/dev/null || true
fi

# Copy shared data (firmware, BIOS files, etc.) - this is crucial for QEMU to work
if [ -d usr/share/qemu ]; then
  cp -a usr/share/qemu/* "$QEMU_DIR/usr/local/share/qemu/" 2>/dev/null || true
fi

# Download additional BIOS files using apt-get
printf "${GREEN}Downloading BIOS files using package manager\n"

# Add SeaBIOS to packages list and download it
printf "${GREEN}Adding SeaBIOS package\n"
if apt-cache show seabios >/dev/null 2>&1; then
  printf "${GREEN}Downloading SeaBIOS package\n"
  apt-get download seabios

  # Extract SeaBIOS
  if ls seabios_*.deb >/dev/null 2>&1; then
    dpkg-deb -x seabios_*.deb seabios_extracted/
    if [ -f "seabios_extracted/usr/share/seabios/bios.bin" ]; then
      cp "seabios_extracted/usr/share/seabios/bios.bin" "$QEMU_DIR/usr/local/share/qemu/seabios.bin"
      printf "${GREEN}SeaBIOS installed from package\n"
    elif [ -f "seabios_extracted/usr/share/qemu/bios.bin" ]; then
      cp "seabios_extracted/usr/share/qemu/bios.bin" "$QEMU_DIR/usr/local/share/qemu/seabios.bin"
      printf "${GREEN}SeaBIOS installed from package (qemu path)\n"
    fi
    rm -rf seabios_*.deb seabios_extracted/
  fi
else
  printf "${YELLOW}SeaBIOS package not available\n"
fi

# Add OVMF if available
printf "${GREEN}Checking for OVMF UEFI firmware\n"
if apt-cache show ovmf >/dev/null 2>&1; then
  printf "${GREEN}Downloading OVMF package\n"
  apt-get download ovmf

  if ls ovmf_*.deb >/dev/null 2>&1; then
    dpkg-deb -x ovmf_*.deb ovmf_extracted/
    if [ -d "ovmf_extracted/usr/share/OVMF" ]; then
      cp -r ovmf_extracted/usr/share/OVMF/* "$QEMU_DIR/usr/local/share/qemu/" 2>/dev/null || true
      printf "${GREEN}OVMF UEFI firmware installed\n"
    fi
    rm -rf ovmf_*.deb ovmf_extracted/
  fi
else
  printf "${YELLOW}OVMF package not available\n"
fi

# Add iPXE ROMs if available
printf "${GREEN}Checking for iPXE network boot ROMs\n"
if apt-cache show ipxe-qemu >/dev/null 2>&1; then
  printf "${GREEN}Downloading iPXE package\n"
  apt-get download ipxe-qemu

  if ls ipxe-qemu_*.deb >/dev/null 2>&1; then
    dpkg-deb -x ipxe-qemu_*.deb ipxe_extracted/
    if [ -d "ipxe_extracted/usr/lib/ipxe/qemu" ]; then
      cp ipxe_extracted/usr/lib/ipxe/qemu/* "$QEMU_DIR/usr/local/share/qemu/" 2>/dev/null || true
      printf "${GREEN}iPXE ROMs installed\n"
    fi
    rm -rf ipxe-qemu_*.deb ipxe_extracted/
  fi
else
  printf "${YELLOW}iPXE package not available\n"
fi

# Create essential BIOS files if they don't exist
if [ ! -f "$QEMU_DIR/usr/local/share/qemu/seabios.bin" ]; then
  printf "${YELLOW}Creating placeholder SeaBIOS (QEMU will use built-in)\n"
  touch "$QEMU_DIR/usr/local/share/qemu/seabios.bin"
fi

# Copy QEMU library modules (plugins) from qemu-system-common and qemu-block-extra
if [ -d usr/lib/x86_64-linux-gnu/qemu ]; then
  cp -a usr/lib/x86_64-linux-gnu/qemu/* "$QEMU_DIR/usr/local/lib/x86_64-linux-gnu/qemu/" 2>/dev/null || true
fi

# Copy system libraries (like libtpms) to the proper location
if [ -d usr/lib/x86_64-linux-gnu ]; then
  # Create the target directory structure
  mkdir -p "$QEMU_DIR/usr/local/lib/x86_64-linux-gnu"
  # Copy all .so files from the system lib directory
  find usr/lib/x86_64-linux-gnu -name "*.so*" -exec cp {} "$QEMU_DIR/usr/local/lib/x86_64-linux-gnu/" \; 2>/dev/null || true
fi

# Copy QEMU helper binaries
if [ -d usr/lib/qemu ]; then
  cp -a usr/lib/qemu/* "$QEMU_DIR/usr/local/lib/qemu/" 2>/dev/null || true
fi

# Copy systemd units from qemu-block-extra
if [ -d usr/lib/systemd/system ]; then
  cp -a usr/lib/systemd/system/* "$QEMU_DIR/usr/local/lib/systemd/system/" 2>/dev/null || true
fi

# Copy network helper scripts
if [ -f etc/qemu-ifup ]; then
  cp etc/qemu-ifup "$QEMU_DIR/etc/" 2>/dev/null || true
fi

if [ -f etc/qemu-ifdown ]; then
  cp etc/qemu-ifdown "$QEMU_DIR/etc/" 2>/dev/null || true
fi

# Copy default configuration
if [ -f etc/default/qemu-kvm ]; then
  cp etc/default/qemu-kvm "$QEMU_DIR/etc/default/" 2>/dev/null || true
fi

# Return to the qemu directory
cd "$QEMU_DIR"

# Copy systemd service files
printf "${GREEN}Copying systemd service files\n"
mkdir -p usr/local/lib/systemd/system/
mkdir -p usr/local/lib/systemd/system/multi-user.target.d/
cp "$SCRIPT_DIR/services/qemu-kvm.service" usr/local/lib/systemd/system/
cp "$SCRIPT_DIR/services/qemu-kvm.defaults" usr/local/lib/systemd/system/
cp "$SCRIPT_DIR/services/run-qemu.mount" usr/local/lib/systemd/system/
cp "$SCRIPT_DIR/services/libvirtd.service" usr/local/lib/systemd/system/
cp "$SCRIPT_DIR/services/virtlogd.service" usr/local/lib/systemd/system/
cp "$SCRIPT_DIR/services/virtlockd.service" usr/local/lib/systemd/system/

# Create systemd target dependencies
cat > usr/local/lib/systemd/system/multi-user.target.d/10-qemu-services.conf << EOF
[Unit]
Wants=qemu-kvm.service run-qemu.mount libvirtd.service
After=qemu-kvm.service run-qemu.mount libvirtd.service
EOF

# Set the proper permissions for network helpers
chmod +x etc/qemu-ifup 2>/dev/null || true
chmod +x etc/qemu-ifdown 2>/dev/null || true
chmod u+s usr/local/lib/qemu/qemu-bridge-helper 2>/dev/null || true

# Create QEMU configuration file
printf "${GREEN}Creating QEMU configuration\n"
cat > etc/qemu/qemu.conf << 'EOF'
# QEMU Configuration
# This file configures QEMU system-wide settings

# BIOS and firmware search paths
firmware_path = ["/usr/local/share/qemu"]

# Default machine settings
default_machine = "q35"

# Security settings
security_default_confined = 0
security_require_confined = 0

# User and group for QEMU processes
user = "root"
group = "root"

# Memory settings
max_files = 32768
max_processes = 131072

# Network settings
bridge_helper = "/usr/local/libexec/qemu-bridge-helper"
EOF

# Create helper scripts
printf "${GREEN}Creating helper scripts\n"

# vTPM2 setup script
cat > usr/local/share/qemu/scripts/setup-vtpm2.sh << 'EOF'
#!/bin/bash
# QEMU vTPM2 Setup Helper Script
# Usage: setup-vtpm2.sh <vm-name> [tpm-version]

VM_NAME="${1:-default-vm}"
TPM_VERSION="${2:-2.0}"
TPM_DIR="/tmp/vtpm-${VM_NAME}"
SOCKET_PATH="${TPM_DIR}/swtpm-sock"

if [ "$#" -eq 0 ]; then
    echo "Usage: $0 <vm-name> [tpm-version]"
    echo "Example: $0 my-vm 2.0"
    exit 1
fi

echo "Setting up vTPM2 for VM: ${VM_NAME}"

# Create TPM directory
mkdir -p "${TPM_DIR}"

# Initialize TPM state
echo "Initializing TPM state..."
swtpm_setup --tpmstate "${TPM_DIR}" --tpm2 --create-ek-cert --create-platform-cert

# Start swtpm daemon
echo "Starting swtpm daemon..."
swtpm socket --tpmstate dir="${TPM_DIR}" --ctrl type=unixio,path="${TPM_DIR}/swtpm-ctrl" --server type=unixio,path="${SOCKET_PATH}" --tpm2 --daemon

echo "vTPM2 setup complete!"
echo "Socket path: ${SOCKET_PATH}"
echo ""
echo "Add these QEMU arguments to use vTPM2:"
echo "  -chardev socket,id=chrtpm,path=${SOCKET_PATH}"
echo "  -tpmdev emulator,id=tpm0,chardev=chrtpm"
echo "  -device tpm-tis,tpmdev=tpm0"
echo ""
echo "To stop the TPM daemon:"
echo "  pkill -f \"swtpm.*${VM_NAME}\""
EOF

# TXT capability check script
cat > usr/local/share/qemu/scripts/txt-capability-check.sh << 'EOF'
#!/bin/bash
# Intel TXT Capability Check Script

echo "=== Intel TXT Capability Check ==="
echo "Date: $(date)"
echo ""

# CPU TXT Support
if grep -q smx /proc/cpuinfo; then
    echo "✅ CPU TXT Support: YES (smx flag present)"
else
    echo "❌ CPU TXT Support: NO (smx flag missing)"
fi

# VMX Support
if grep -q vmx /proc/cpuinfo; then
    echo "✅ CPU VMX Support: YES"
else
    echo "❌ CPU VMX Support: NO"
fi

# CET Support
if grep -q user_shstk /proc/cpuinfo && grep -q ibt /proc/cpuinfo; then
    echo "✅ CPU CET Support: YES (user_shstk + ibt)"
else
    echo "❌ CPU CET Support: NO"
fi

# IOMMU Support
if dmesg | grep -q "Intel-IOMMU"; then
    echo "✅ IOMMU Support: YES (Intel-IOMMU detected)"
elif dmesg | grep -q "DMAR"; then
    echo "✅ IOMMU Support: YES (DMAR detected)"
else
    echo "❌ IOMMU Support: NO (check BIOS settings)"
fi

# TPM Present
if ls /dev/tpm* >/dev/null 2>&1; then
    echo "✅ TPM Device: YES ($(ls /dev/tpm*))"
else
    echo "❌ TPM Device: NO"
fi

# TXT Status (requires tboot)
if command -v txt-stat >/dev/null 2>&1; then
    echo ""
    echo "=== TXT Status ==="
    txt-stat 2>/dev/null || echo "⚠️  TXT Status: tboot not active"
else
    echo "⚠️  TXT Status: txt-stat not available (install tboot)"
fi

echo ""
echo "=== Microcode Version ==="
grep microcode /proc/cpuinfo | head -1

echo ""
echo "=== Recommendations ==="
if ! grep -q smx /proc/cpuinfo; then
    echo "- Enable Intel TXT in BIOS/UEFI settings"
fi
if ! dmesg | grep -q -E "(Intel-IOMMU|DMAR)"; then
    echo "- Enable VT-d/IOMMU in BIOS/UEFI settings"
    echo "- Add intel_iommu=on to kernel command line"
fi
if ! ls /dev/tpm* >/dev/null 2>&1; then
    echo "- Enable TPM in BIOS/UEFI settings"
fi
EOF

# USB device enumeration for Nomad
cat > usr/local/share/qemu/scripts/usb-nomad-enumerate.sh << 'EOF'
#!/bin/bash
# USB Device Enumeration for Nomad
# Outputs USB devices in format suitable for Nomad device plugin

echo "=== USB Devices for Nomad ==="
echo "# Format: device_type vendor_id product_id device_name"
echo ""

lsusb | while IFS= read -r line; do
    # Parse lsusb output: Bus 001 Device 002: ID 1234:5678 Device Name
    if [[ $line =~ Bus\ ([0-9]+)\ Device\ ([0-9]+):\ ID\ ([0-9a-fA-F]+):([0-9a-fA-F]+)\ (.+) ]]; then
        bus="${BASH_REMATCH[1]}"
        device="${BASH_REMATCH[2]}"
        vendor_id="${BASH_REMATCH[3]}"
        product_id="${BASH_REMATCH[4]}"
        device_name="${BASH_REMATCH[5]}"

        # Clean up device name for use in Nomad
        clean_name=$(echo "$device_name" | sed 's/[^a-zA-Z0-9_-]/_/g' | sed 's/__*/_/g' | sed 's/^_\|_$//g')

        # Output in Nomad format
        echo "usb/${clean_name,,} vendor=${vendor_id} product=${product_id} name=\"${device_name}\""
    fi
done

echo ""
echo "=== Usage in Nomad Job ==="
echo 'device "usb/device_name" {'
echo '  vendor_id    = "1234"'
echo '  product_id   = "5678"'
echo '  device_name  = "Device Name"'
echo '}'
EOF

# Security status check script
cat > usr/local/share/qemu/scripts/security-status-check.sh << 'EOF'
#!/bin/bash
# System Security Status Check

echo "=== System Security Status ==="
echo "Date: $(date)"
echo ""

echo "=== CPU Security Features ==="
echo "Microcode Version: $(grep microcode /proc/cpuinfo | head -1 | awk '{print $3}')"

# CET Status
if dmesg | grep -i cet >/dev/null 2>&1; then
    echo "✅ CET Status: $(dmesg | grep -i cet | tail -1)"
else
    echo "⚠️  CET Status: No CET messages in dmesg"
fi

# IOMMU Groups
iommu_groups=$(find /sys/kernel/iommu_groups/ -type l 2>/dev/null | wc -l)
if [ "$iommu_groups" -gt 0 ]; then
    echo "✅ IOMMU Groups: $iommu_groups groups found"
else
    echo "❌ IOMMU Groups: No IOMMU groups found"
fi

echo ""
echo "=== KVM Security ==="
if [ -d /sys/module/kvm_intel ]; then
    echo "KVM Intel Module: Loaded"
    for param in /sys/module/kvm_intel/parameters/*; do
        if [ -r "$param" ]; then
            param_name=$(basename "$param")
            param_value=$(cat "$param" 2>/dev/null || echo "unreadable")
            echo "  $param_name: $param_value"
        fi
    done
else
    echo "❌ KVM Intel Module: Not loaded"
fi

echo ""
echo "=== Virtualization Status ==="
if [ -c /dev/kvm ]; then
    echo "✅ KVM Device: Available (/dev/kvm)"
    echo "   Permissions: $(ls -l /dev/kvm)"
else
    echo "❌ KVM Device: Not available"
fi

echo ""
echo "=== TPM Status ==="
if ls /dev/tpm* >/dev/null 2>&1; then
    for tpm_dev in /dev/tpm*; do
        echo "✅ TPM Device: $tpm_dev"
        echo "   Permissions: $(ls -l "$tpm_dev")"
    done
else
    echo "❌ TPM Device: Not found"
fi

echo ""
echo "=== USB Controllers ==="
lspci | grep -i usb | while read -r line; do
    echo "USB Controller: $line"
done

echo ""
echo "=== Memory Protection ==="
if grep -q "SLUB.*FZP" /proc/cmdline; then
    echo "✅ SLUB Debug: Enabled"
else
    echo "⚠️  SLUB Debug: Not detected in cmdline"
fi

if grep -q "init_on_alloc=1" /proc/cmdline; then
    echo "✅ Init on Alloc: Enabled"
else
    echo "⚠️  Init on Alloc: Not enabled"
fi

echo ""
echo "=== Kernel Address Security ==="
if grep -q "kptr_restrict" /proc/sys/kernel/kptr_restrict 2>/dev/null; then
    kptr_value=$(cat /proc/sys/kernel/kptr_restrict 2>/dev/null)
    case "$kptr_value" in
        0) echo "❌ Kernel Pointers: Exposed (kptr_restrict=0)" ;;
        1) echo "⚠️  Kernel Pointers: Restricted for unprivileged (kptr_restrict=1)" ;;
        2) echo "✅ Kernel Pointers: Hidden (kptr_restrict=2)" ;;
        *) echo "⚠️  Kernel Pointers: Unknown setting ($kptr_value)" ;;
    esac
else
    echo "❌ Kernel Pointers: kptr_restrict not available"
fi

if dmesg | grep -q "unhashed kernel memory addresses" 2>/dev/null; then
    echo "❌ Address Exposure: Kernel addresses visible in logs"
    echo "   Recommendation: Add 'kptr_restrict=2' to kernel command line"
else
    echo "✅ Address Exposure: Kernel addresses properly hidden"
fi

echo ""
echo "=== Intel Memory Encryption ==="
if grep -q tme /proc/cpuinfo; then
    echo "✅ TME Support: Available in CPU"
    if dmesg | grep -q "x86/tme: enabled by BIOS" 2>/dev/null; then
        echo "✅ TME Status: Enabled by BIOS"
    elif dmesg | grep -q "Intel TME enabled" 2>/dev/null; then
        echo "✅ TME Status: Active"
    else
        echo "⚠️  TME Status: Available but status unknown (check dmesg)"
    fi
else
    echo "❌ TME Support: Not available in CPU flags"
fi

if dmesg | grep -q "x86/mktme: BIOS enabled" 2>/dev/null; then
    echo "✅ MKTME Status: Enabled by BIOS"
    mktme_info=$(dmesg | grep "x86/mktme: BIOS enabled" 2>/dev/null)
    echo "   $mktme_info"
else
    echo "⚠️  MKTME Support: Not detected in dmesg"
fi

echo ""
echo "=== Advanced CPU Security Features ==="
cpu_flags=$(grep flags /proc/cpuinfo | head -1)

# Check for various security features
if echo "$cpu_flags" | grep -q smep; then
    echo "✅ SMEP: Supported"
else
    echo "❌ SMEP: Not supported"
fi

if echo "$cpu_flags" | grep -q smap; then
    echo "✅ SMAP: Supported"
else
    echo "❌ SMAP: Not supported"
fi

if echo "$cpu_flags" | grep -q umip; then
    echo "✅ UMIP: Supported"
else
    echo "❌ UMIP: Not supported"
fi

if echo "$cpu_flags" | grep -q mpx; then
    echo "✅ MPX: Supported"
else
    echo "❌ MPX: Not supported"
fi

echo ""
echo "=== Memory Error Detection (EDAC) ==="
if [ -d /sys/devices/system/edac/mc ]; then
    edac_controllers=$(find /sys/devices/system/edac/mc -name "mc*" | wc -l)
    if [ "$edac_controllers" -gt 0 ]; then
        echo "✅ EDAC Controllers: $edac_controllers detected"
        for mc in /sys/devices/system/edac/mc/mc*; do
            if [ -f "$mc/mc_name" ]; then
                mc_name=$(cat "$mc/mc_name" 2>/dev/null)
                mc_num=$(basename "$mc")
                echo "   $mc_num: $mc_name"
            fi
        done
    else
        echo "❌ EDAC Controllers: None detected"
    fi

    # Check for EDAC errors
    if [ -f /sys/devices/system/edac/mc/mc0/ce_count ]; then
        ce_count=$(cat /sys/devices/system/edac/mc/mc0/ce_count 2>/dev/null || echo "0")
        ue_count=$(cat /sys/devices/system/edac/mc/mc0/ue_count 2>/dev/null || echo "0")
        echo "   Correctable Errors: $ce_count"
        echo "   Uncorrectable Errors: $ue_count"
    fi
else
    echo "❌ EDAC: Not available or not loaded"
fi

# Check for EDAC resource conflicts
if dmesg | grep -q "igen6_register_mci.*mapping multiple BARs" 2>/dev/null; then
    echo "⚠️  EDAC Warning: Resource mapping conflict detected"
    echo "   Recommendation: Add 'pci=realloc iommu.strict=1' to kernel command line"
else
    echo "✅ EDAC Resources: No conflicts detected"
fi

echo ""
echo "=== Additional Security Features ==="

# Check KASLR
if grep -q "kaslr" /proc/cmdline 2>/dev/null || dmesg | grep -q "KASLR enabled" 2>/dev/null; then
    echo "✅ KASLR: Enabled"
else
    echo "⚠️  KASLR: Status unknown (may be enabled by default)"
fi

# Check vsyscall
if grep -q "vsyscall=none" /proc/cmdline 2>/dev/null; then
    echo "✅ vsyscall: Disabled (secure)"
elif grep -q "vsyscall=emulate" /proc/cmdline 2>/dev/null; then
    echo "⚠️  vsyscall: Emulation mode (less secure)"
else
    echo "❌ vsyscall: Default mode (consider vsyscall=none)"
fi

# Check audit
if grep -q "audit=1" /proc/cmdline 2>/dev/null; then
    echo "✅ Kernel Audit: Enabled"
else
    echo "⚠️  Kernel Audit: Not explicitly enabled"
fi

# Check module signature enforcement
if grep -q "module.sig_enforce=1" /proc/cmdline 2>/dev/null; then
    echo "✅ Module Signatures: Enforced"
else
    echo "⚠️  Module Signatures: Not enforced"
fi

# Check slab_nomerge
if grep -q "slab_nomerge" /proc/cmdline 2>/dev/null; then
    echo "✅ SLAB No-merge: Enabled (prevents cache-based exploits)"
else
    echo "⚠️  SLAB No-merge: Not enabled"
fi

# Check page poisoning
if grep -q "page_poison=1" /proc/cmdline 2>/dev/null; then
    echo "✅ Page Poisoning: Enabled"
else
    echo "⚠️  Page Poisoning: Not enabled (init_on_free provides similar protection)"
fi

echo ""
echo "=== Container/Docker Support ==="

# Check cgroup v2
if [ -f /sys/fs/cgroup/cgroup.controllers ]; then
    echo "✅ Cgroup v2: Available"
    controllers=$(cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null)
    echo "   Controllers: $controllers"
else
    echo "⚠️  Cgroup v2: Not available (check systemd.unified_cgroup_hierarchy=1)"
fi

# Check AppArmor
if grep -q "apparmor=1" /proc/cmdline 2>/dev/null; then
    echo "✅ AppArmor: Enabled via kernel parameter"
elif [ -d /sys/kernel/security/apparmor ]; then
    echo "✅ AppArmor: Available"
    if [ -f /sys/kernel/security/apparmor/profiles ]; then
        profile_count=$(wc -l < /sys/kernel/security/apparmor/profiles 2>/dev/null || echo "0")
        echo "   Loaded profiles: $profile_count"
    fi
else
    echo "❌ AppArmor: Not available"
fi

# Check memory cgroup
if grep -q "cgroup_enable=memory" /proc/cmdline 2>/dev/null; then
    echo "✅ Memory Cgroup: Explicitly enabled"
elif [ -f /sys/fs/cgroup/memory.max ] || [ -f /sys/fs/cgroup/memory/memory.limit_in_bytes ]; then
    echo "✅ Memory Cgroup: Available"
else
    echo "⚠️  Memory Cgroup: Status unclear"
fi

# Check transparent hugepages
if [ -f /sys/kernel/mm/transparent_hugepage/enabled ]; then
    thp_status=$(cat /sys/kernel/mm/transparent_hugepage/enabled 2>/dev/null)
    if echo "$thp_status" | grep -q "\[madvise\]"; then
        echo "✅ Transparent Hugepages: madvise (optimal for containers)"
    elif echo "$thp_status" | grep -q "\[always\]"; then
        echo "⚠️  Transparent Hugepages: always (may cause container issues)"
    elif echo "$thp_status" | grep -q "\[never\]"; then
        echo "⚠️  Transparent Hugepages: never (may impact performance)"
    else
        echo "⚠️  Transparent Hugepages: $thp_status"
    fi
else
    echo "❌ Transparent Hugepages: Not available"
fi

# Check for Docker-specific kernel features
echo ""
echo "=== Docker Kernel Features ==="
docker_features=("bridge" "veth" "iptables" "netfilter" "overlay" "aufs" "devicemapper")
for feature in "${docker_features[@]}"; do
    if lsmod | grep -q "$feature" 2>/dev/null; then
        echo "✅ $feature: Loaded"
    else
        echo "⚠️  $feature: Not loaded (may load on demand)"
    fi
done
EOF

# USB authorization helper script
cat > usr/local/share/qemu/scripts/usb-authorize.sh << 'EOF'
#!/bin/bash
# USB Device Authorization Helper

if [ "$#" -eq 0 ]; then
    echo "USB Device Authorization Helper"
    echo ""
    echo "Usage:"
    echo "  $0 list                    # List all USB devices and their status"
    echo "  $0 authorize <device>      # Authorize specific device (e.g., 3-2)"
    echo "  $0 authorize-hub <hub>     # Authorize all devices on hub (e.g., usb3)"
    echo "  $0 revoke <device>         # Revoke device authorization"
    echo ""
    exit 1
fi

case "$1" in
    list)
        echo "=== USB Device Authorization Status ==="
        for device in /sys/bus/usb/devices/*/; do
            if [ -f "$device/authorized" ]; then
                device_name=$(basename "$device")
                authorized=$(cat "$device/authorized" 2>/dev/null)
                if [ -f "$device/product" ]; then
                    product=$(cat "$device/product" 2>/dev/null)
                    vendor=$(cat "$device/manufacturer" 2>/dev/null || echo "Unknown")
                    status="❌ BLOCKED"
                    [ "$authorized" = "1" ] && status="✅ AUTHORIZED"
                    echo "$device_name: $status - $vendor $product"
                fi
            fi
        done
        ;;
    authorize)
        if [ -z "$2" ]; then
            echo "Error: Please specify device (e.g., 3-2)"
            exit 1
        fi
        device_path="/sys/bus/usb/devices/$2/authorized"
        if [ -f "$device_path" ]; then
            echo 1 > "$device_path"
            echo "✅ Authorized device $2"
        else
            echo "❌ Device $2 not found"
            exit 1
        fi
        ;;
    authorize-hub)
        if [ -z "$2" ]; then
            echo "Error: Please specify hub (e.g., usb3)"
            exit 1
        fi
        hub_path="/sys/bus/usb/devices/$2/authorized_default"
        if [ -f "$hub_path" ]; then
            echo 1 > "$hub_path"
            echo "✅ Authorized all devices on hub $2"
        else
            echo "❌ Hub $2 not found"
            exit 1
        fi
        ;;
    revoke)
        if [ -z "$2" ]; then
            echo "Error: Please specify device (e.g., 3-2)"
            exit 1
        fi
        device_path="/sys/bus/usb/devices/$2/authorized"
        if [ -f "$device_path" ]; then
            echo 0 > "$device_path"
            echo "❌ Revoked authorization for device $2"
        else
            echo "❌ Device $2 not found"
            exit 1
        fi
        ;;
    *)
        echo "Unknown command: $1"
        exit 1
        ;;
esac
EOF

chmod +x usr/local/share/qemu/scripts/setup-vtpm2.sh
chmod +x usr/local/share/qemu/scripts/txt-capability-check.sh
chmod +x usr/local/share/qemu/scripts/usb-nomad-enumerate.sh
chmod +x usr/local/share/qemu/scripts/security-status-check.sh
chmod +x usr/local/share/qemu/scripts/usb-authorize.sh

# List installed binaries
printf "${GREEN}Installed QEMU binaries:\n"
ls -la usr/local/bin/qemu* 2>/dev/null || printf "${YELLOW}No QEMU binaries found in usr/local/bin\n"

# Clean up temporary files
rm -Rf "$tmpDir"

# Create extension release
createExtensionRelease qemu-"$latest_version" true

# Remove empty directories
find . -type d -empty -delete

popd > /dev/null || exit 1

if [ "${PUSH}" != false ]; then
  buildAndPush qemu-"$latest_version"
fi

if [ "${KEEP_FILES}" == "false" ]; then
  rm -Rf qemu-"$latest_version"
fi

printf "${GREEN}Done\n"
printf "${GREEN}QEMU system extension created with Intel Gen 12 processor and security support\n"
printf "${GREEN}Included packages: qemu-system-x86, qemu-system-common, qemu-system-data, qemu-utils, qemu-block-extra\n"
printf "${GREEN}                   swtpm, swtpm-tools, libtpms0, libvirt-daemon-system, libvirt-clients\n"
printf "${GREEN}                   libvirt-daemon-driver-qemu, trousers, libusb-1.0-0, usbutils, libfdt1\n"
printf "${GREEN}Available binaries: qemu-system-x86_64, qemu-img, qemu-io, qemu-nbd, qemu-storage-daemon\n"
printf "${GREEN}                    swtpm, virsh, virt-install, libvirtd\n"
printf "${GREEN}Security features:\n"
printf "${GREEN}  - vTPM2 support: swtpm, swtpm_setup, swtpm_bios, swtpm_cert, swtpm_ioctl\n"
printf "${GREEN}  - Intel TXT ready: trousers, hardware detection (requires tboot for full TXT)\n"
printf "${GREEN}  - Intel CET support: enabled by default in VMs\n"
printf "${GREEN}  - USB device passthrough: direct passthrough for Nomad integration\n"
printf "${GREEN}Helper scripts:\n"
printf "${GREEN}  - vTPM2 setup: /usr/local/share/qemu/scripts/setup-vtpm2.sh\n"
printf "${GREEN}  - TXT capability check: /usr/local/share/qemu/scripts/txt-capability-check.sh\n"
printf "${GREEN}  - USB enumeration: /usr/local/share/qemu/scripts/usb-nomad-enumerate.sh\n"
printf "${GREEN}  - USB authorization: /usr/local/share/qemu/scripts/usb-authorize.sh\n"
printf "${GREEN}  - Security status: /usr/local/share/qemu/scripts/security-status-check.sh\n"
printf "${GREEN}Services: qemu-kvm, libvirtd, virtlogd, virtlockd, run-qemu.mount\n"
printf "${GREEN}To use KVM acceleration, ensure /dev/kvm is available and accessible\n"
printf "${GREEN}Example usage: qemu-system-x86_64 -enable-kvm -cpu host,+cet-ss,+cet-ibt -m 2048 disk.img\n"
printf "${GREEN}Example with vTPM2: /usr/local/share/qemu/scripts/setup-vtpm2.sh my-vm\n"
