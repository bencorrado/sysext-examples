#!/usr/bin/env bash
#
# Intel Microcode system extension script
#
# This script creates an Intel microcode system extension with automatic
# updates via systemd timer and Nomad node drain coordination.
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
defineServiceMappings "intel-microcode-update.timer intel-microcode-update.service"

if [ -n "$INTEL_MICROCODE_VERSION" ]; then
  latest_version="$INTEL_MICROCODE_VERSION"
else
  # Get the latest intel-microcode version from Ubuntu 24.04 repositories
  latest_version=$(apt-cache policy intel-microcode | grep Candidate | awk '{print $2}' | cut -d':' -f2 | cut -d'+' -f1)
fi

printf "${GREEN}Using version %s\n" "$latest_version"

FORCE=${FORCE:-false}

if [ -z "$latest_version" ]; then
  printf "${RED}Could not determine Intel microcode version\n"
  exit 1
fi

if [ -d intel-microcode-"$latest_version" ]; then
  if [ "$FORCE" == "false" ]; then
    printf "${RED}Version already exists\n"
    exit 0
  fi
  printf "${YELLOW}Version exists but FORCE was set, removing existing version\n"
  rm -Rf intel-microcode-"$latest_version"
fi

# Store the original directory path
SCRIPT_DIR=$(pwd)

mkdir -p intel-microcode-"$latest_version"
pushd intel-microcode-"$latest_version" > /dev/null || exit 1

# Store the microcode directory path
MICROCODE_DIR=$(pwd)

createDirs

# Create additional directories
mkdir -p usr/local/lib/systemd/system/multi-user.target.d
mkdir -p usr/local/share/intel-microcode/scripts
mkdir -p etc/default

printf "${GREEN}Downloading Intel microcode packages\n"

# Create a temporary directory for package extraction
tmpDir=$(mktemp -d)

# Download the intel-microcode package
packages=(
  "intel-microcode"
  "iucode-tool"
)

# Download packages
for package in "${packages[@]}"; do
  printf "${GREEN}Downloading package: %s\n" "$package"
  cd "$tmpDir"
  apt-get download "$package"
done

# Extract packages
printf "${GREEN}Extracting Intel microcode packages\n"
cd "$tmpDir"
for deb in *.deb; do
  printf "${GREEN}Extracting %s\n" "$deb"
  dpkg-deb -x "$deb" extracted/
done

# Copy files to the proper locations
cd extracted
printf "${GREEN}Installing Intel microcode binaries and data\n"

# Copy binaries
if [ -d usr/bin ]; then
  cp -a usr/bin/* "$MICROCODE_DIR/usr/local/bin/" 2>/dev/null || true
fi

if [ -d usr/sbin ]; then
  cp -a usr/sbin/* "$MICROCODE_DIR/usr/local/sbin/" 2>/dev/null || true
fi

# Copy microcode data
if [ -d lib/firmware ]; then
  mkdir -p "$MICROCODE_DIR/lib/firmware"
  cp -a lib/firmware/* "$MICROCODE_DIR/lib/firmware/" 2>/dev/null || true
fi

# Copy any additional files
if [ -d usr/share ]; then
  mkdir -p "$MICROCODE_DIR/usr/local/share"
  cp -a usr/share/* "$MICROCODE_DIR/usr/local/share/" 2>/dev/null || true
fi

# Return to the microcode directory
cd "$MICROCODE_DIR"

# Create systemd service and timer files
printf "${GREEN}Creating systemd service and timer\n"

# Microcode update service
cat > usr/local/lib/systemd/system/intel-microcode-update.service << 'EOF'
[Unit]
Description=Intel Microcode Update with Nomad Coordination
Documentation=man:iucode_tool(8)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/share/intel-microcode/scripts/update-microcode.sh
User=root
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# Microcode update timer with fleet-wide randomization
cat > usr/local/lib/systemd/system/intel-microcode-update.timer << 'EOF'
[Unit]
Description=Weekly Intel Microcode Update (Fleet Randomized)
Documentation=man:iucode_tool(8)

[Timer]
# Run weekly with randomization across the entire week
# This spreads updates across 7 days instead of all on Sunday
OnCalendar=weekly
# Random delay up to 6 days (518400 seconds) to spread across the week
RandomizedDelaySec=518400
# Run 10 minutes after boot if we missed the scheduled time
OnBootSec=10min
# Additional randomization to avoid simultaneous reboots
AccuracySec=1h
Persistent=true

[Install]
WantedBy=timers.target
EOF

# Create the microcode update script
cat > usr/local/share/intel-microcode/scripts/update-microcode.sh << 'EOF'
#!/bin/bash
# Intel Microcode Update Script with Nomad Coordination

set -euo pipefail

LOG_TAG="intel-microcode-update"
NOMAD_DRAIN_TIMEOUT="10m"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [$LOG_TAG] $*" | systemd-cat -t "$LOG_TAG"
}

# Add additional randomization for fleet coordination
RANDOM_DELAY=$((RANDOM % 3600))  # Random delay up to 1 hour
log "Starting Intel microcode update process (random delay: ${RANDOM_DELAY}s)"
sleep "$RANDOM_DELAY"

# Check if we're in a maintenance window (avoid business hours)
current_hour=$(date +%H)
current_day=$(date +%u)  # 1=Monday, 7=Sunday

# Avoid updates during business hours (8 AM - 6 PM, Monday-Friday)
if [ "$current_day" -le 5 ] && [ "$current_hour" -ge 8 ] && [ "$current_hour" -lt 18 ]; then
    log "Skipping update during business hours (${current_hour}:00 on weekday)"
    exit 0
fi

# Check if we're running on Intel CPU
if ! grep -q "vendor_id.*GenuineIntel" /proc/cpuinfo; then
    log "Not running on Intel CPU, skipping microcode update"
    exit 0
fi

# Get current microcode version
current_microcode=$(grep microcode /proc/cpuinfo | head -1 | awk '{print $3}')
log "Current microcode version: $current_microcode"

# Check if Nomad is running and drain the node
if systemctl is-active --quiet nomad 2>/dev/null; then
    log "Nomad detected, draining node before microcode update"
    
    # Drain the node (allow failures in case node is already drained)
    if nomad node drain -self -deadline "$NOMAD_DRAIN_TIMEOUT" -yes || true; then
        log "Successfully drained Nomad node"
    else
        log "Warning: Failed to drain Nomad node, continuing anyway"
    fi
    
    # Wait a bit for jobs to migrate
    sleep 30
else
    log "Nomad not detected or not running, proceeding without draining"
fi

# Update microcode
log "Updating Intel microcode"
if iucode_tool -S --write-earlyfw=/boot/early_ucode.cpio /lib/firmware/intel-ucode/*; then
    log "Successfully updated microcode early firmware"
else
    log "Error: Failed to update microcode"
    exit 1
fi

# Check if update requires reboot
if [ -f /var/run/reboot-required ]; then
    log "Reboot required for microcode update, scheduling reboot"
    
    # Schedule reboot in 2 minutes to allow logging to complete
    shutdown -r +2 "Rebooting for Intel microcode update"
    
    log "Reboot scheduled in 2 minutes"
else
    log "Microcode update completed, no reboot required"
    
    # Re-enable Nomad node if it was drained
    if systemctl is-active --quiet nomad 2>/dev/null; then
        log "Re-enabling Nomad node"
        nomad node drain -self -disable || log "Warning: Failed to re-enable Nomad node"
    fi
fi

log "Intel microcode update process completed"
EOF

chmod +x usr/local/share/intel-microcode/scripts/update-microcode.sh

# Create systemd target dependency
cat > usr/local/lib/systemd/system/multi-user.target.d/10-intel-microcode.conf << EOF
[Unit]
Wants=intel-microcode-update.timer
After=intel-microcode-update.timer
EOF

# List installed binaries
printf "${GREEN}Installed Intel microcode binaries:\n"
ls -la usr/local/bin/* 2>/dev/null || printf "${YELLOW}No binaries found in usr/local/bin\n"
ls -la usr/local/sbin/* 2>/dev/null || printf "${YELLOW}No binaries found in usr/local/sbin\n"

# Clean up temporary files
rm -Rf "$tmpDir"

# Create extension release
createExtensionRelease intel-microcode-"$latest_version" true

# Remove empty directories
find . -type d -empty -delete

popd > /dev/null || exit 1

if [ "${PUSH}" != false ]; then
  buildAndPush intel-microcode-"$latest_version"
fi

if [ "${KEEP_FILES}" == "false" ]; then
  rm -Rf intel-microcode-"$latest_version"
fi

printf "${GREEN}Done\n"
printf "${GREEN}Intel microcode system extension created\n"
printf "${GREEN}Included packages: intel-microcode, iucode-tool\n"
printf "${GREEN}Update schedule: Weekly with fleet-wide randomization (spread across 7 days)\n"
printf "${GREEN}Business hours protection: Skips updates 8 AM - 6 PM on weekdays\n"
printf "${GREEN}Nomad integration: Automatic node drain before updates\n"
printf "${GREEN}Fleet coordination: Random delays to prevent simultaneous reboots\n"
printf "${GREEN}Update script: /usr/local/share/intel-microcode/scripts/update-microcode.sh\n"
printf "${GREEN}Manual update: systemctl start intel-microcode-update.service\n"
