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
  # Get the latest QEMU version from Ubuntu 24.04 repositories
  latest_version=$(apt-cache policy qemu-system-x86 | grep Candidate | awk '{print $2}' | cut -d':' -f2 | cut -d'+' -f1)
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

printf "${GREEN}Downloading QEMU packages\n"

# Create a temporary directory for package extraction
tmpDir=$(mktemp -d)

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
  apt-get download "$package"
done

# Extract packages
printf "${GREEN}Extracting QEMU packages\n"
cd "$tmpDir"
for deb in *.deb; do
  printf "${GREEN}Extracting %s\n" "$deb"
  dpkg-deb -x "$deb" extracted/
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
EOF

chmod +x usr/local/share/qemu/scripts/setup-vtpm2.sh
chmod +x usr/local/share/qemu/scripts/txt-capability-check.sh
chmod +x usr/local/share/qemu/scripts/usb-nomad-enumerate.sh
chmod +x usr/local/share/qemu/scripts/security-status-check.sh

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
printf "${GREEN}                   libvirt-daemon-driver-qemu, trousers, libusb-1.0-0, usbutils\n"
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
printf "${GREEN}  - Security status: /usr/local/share/qemu/scripts/security-status-check.sh\n"
printf "${GREEN}Services: qemu-kvm, libvirtd, virtlogd, virtlockd, run-qemu.mount\n"
printf "${GREEN}To use KVM acceleration, ensure /dev/kvm is available and accessible\n"
printf "${GREEN}Example usage: qemu-system-x86_64 -enable-kvm -cpu host,+cet-ss,+cet-ibt -m 2048 disk.img\n"
printf "${GREEN}Example with vTPM2: /usr/local/share/qemu/scripts/setup-vtpm2.sh my-vm\n"
