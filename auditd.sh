#!/usr/bin/env bash
#
# auditd system extension script
#
# This script creates an auditd system extension from Ubuntu packages
# with the Linux Audit daemon and related tools.
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
defineServiceMappings "auditd.service"

if [ -n "$AUDITD_VERSION" ]; then
  latest_version="$AUDITD_VERSION"
else
  # Get the latest auditd version from Ubuntu repositories
  # The package has an epoch (1:) which we strip for the directory name
  full_version=$(apt-cache policy auditd | grep Candidate | awk '{print $2}')
  # Strip the epoch if present
  latest_version=$(echo "$full_version" | sed 's/^[0-9]*://')
fi

printf "${GREEN}Using version %s\n" "$latest_version"

FORCE=${FORCE:-false}

if [ -z "$latest_version" ]; then
  printf "${RED}Could not determine auditd version\n"
  exit 1
fi

if [ -d auditd-"$latest_version" ]; then
  if [ "$FORCE" == "false" ]; then
    printf "${RED}Version already exists\n"
    exit 0
  fi
  printf "${YELLOW}Version exists but FORCE was set, removing existing version\n"
  rm -Rf auditd-"$latest_version"
fi

# Store the original directory path
SCRIPT_DIR=$(pwd)

mkdir -p auditd-"$latest_version"
pushd auditd-"$latest_version" > /dev/null || exit 1

# Store the auditd directory path
AUDITD_DIR=$(pwd)

createDirs

# Create additional directories
mkdir -p etc/audit
mkdir -p etc/audit/rules.d
mkdir -p etc/audit/plugins.d
mkdir -p usr/local/share/audit
mkdir -p usr/local/share/doc/auditd

printf "${GREEN}Downloading auditd packages\n"

# Create a temporary directory for package extraction
tmpDir=$(mktemp -d)

# Packages to download:
# - auditd: main daemon and utilities
# - libaudit1: audit library
# - libauparse0t64: audit parsing library
# - libaudit-common: common audit configuration files
# - libcap-ng0: capability library (dependency)
packages=(
  "auditd"
  "libaudit1"
  "libauparse0t64"
  "libaudit-common"
  "libcap-ng0"
)

# Download packages
for package in "${packages[@]}"; do
  printf "${GREEN}Downloading package: %s\n" "$package"
  cd "$tmpDir"
  apt-get download "$package"
done

# Extract packages
printf "${GREEN}Extracting auditd packages\n"
cd "$tmpDir"
for deb in *.deb; do
  printf "${GREEN}Extracting %s\n" "$deb"
  dpkg-deb -x "$deb" extracted/
done

# Copy files to the proper locations
cd extracted
printf "${GREEN}Installing auditd binaries and libraries\n"

# Copy binaries to usr/local/bin and usr/local/sbin
if [ -d usr/bin ]; then
  cp -a usr/bin/* "$AUDITD_DIR/usr/local/bin/" 2>/dev/null || true
fi

if [ -d usr/sbin ]; then
  cp -a usr/sbin/* "$AUDITD_DIR/usr/local/sbin/" 2>/dev/null || true
fi

if [ -d sbin ]; then
  cp -a sbin/* "$AUDITD_DIR/usr/local/sbin/" 2>/dev/null || true
fi

# Copy libraries to usr/local/lib
if [ -d usr/lib ]; then
  mkdir -p "$AUDITD_DIR/usr/local/lib"
  find usr/lib -type f -name "*.so*" -exec cp -a {} "$AUDITD_DIR/usr/local/lib/" \; 2>/dev/null || true
  # Also copy any subdirectories with libraries
  if [ -d usr/lib/x86_64-linux-gnu ]; then
    cp -a usr/lib/x86_64-linux-gnu/*.so* "$AUDITD_DIR/usr/local/lib/" 2>/dev/null || true
  fi
fi

if [ -d lib/x86_64-linux-gnu ]; then
  mkdir -p "$AUDITD_DIR/usr/local/lib"
  cp -a lib/x86_64-linux-gnu/*.so* "$AUDITD_DIR/usr/local/lib/" 2>/dev/null || true
fi

# Copy configuration files
if [ -d etc/audit ]; then
  cp -a etc/audit/* "$AUDITD_DIR/etc/audit/" 2>/dev/null || true
fi

# Copy audisp (audit dispatcher) files if present
if [ -d etc/audisp ]; then
  mkdir -p "$AUDITD_DIR/etc/audisp"
  cp -a etc/audisp/* "$AUDITD_DIR/etc/audisp/" 2>/dev/null || true
fi

# Copy share files (man pages, etc)
if [ -d usr/share ]; then
  mkdir -p "$AUDITD_DIR/usr/local/share"
  cp -a usr/share/* "$AUDITD_DIR/usr/local/share/" 2>/dev/null || true
fi

# Copy systemd service files
if [ -d lib/systemd/system ]; then
  cp -a lib/systemd/system/* "$AUDITD_DIR/usr/local/lib/systemd/system/" 2>/dev/null || true
fi

if [ -d usr/lib/systemd/system ]; then
  cp -a usr/lib/systemd/system/* "$AUDITD_DIR/usr/local/lib/systemd/system/" 2>/dev/null || true
fi

# Return to the auditd directory
cd "$AUDITD_DIR"

# Update systemd service file to use correct paths
if [ -f usr/local/lib/systemd/system/auditd.service ]; then
  printf "${GREEN}Updating auditd.service for sysext paths\n"
  # Update ExecStart path
  sed -i 's|/sbin/auditd|/usr/local/sbin/auditd|g' usr/local/lib/systemd/system/auditd.service
  # Update ExecStartPost if present
  sed -i 's|/sbin/augenrules|/usr/local/sbin/augenrules|g' usr/local/lib/systemd/system/auditd.service
  # Update ExecReload if present
  sed -i 's|/sbin/auditctl|/usr/local/sbin/auditctl|g' usr/local/lib/systemd/system/auditd.service
  sed -i 's|/usr/sbin/auditd|/usr/local/sbin/auditd|g' usr/local/lib/systemd/system/auditd.service
  sed -i 's|/usr/sbin/augenrules|/usr/local/sbin/augenrules|g' usr/local/lib/systemd/system/auditd.service
  sed -i 's|/usr/sbin/auditctl|/usr/local/sbin/auditctl|g' usr/local/lib/systemd/system/auditd.service
fi

# Create ld.so.conf.d entry for the libraries
mkdir -p "$AUDITD_DIR/etc/ld.so.conf.d"
cat > "$AUDITD_DIR/etc/ld.so.conf.d/auditd-sysext.conf" << EOF
# auditd sysext libraries
/usr/local/lib
EOF

# List installed binaries
printf "${GREEN}Installed auditd binaries:\n"
ls -la usr/local/bin/* 2>/dev/null || printf "${YELLOW}No binaries found in usr/local/bin\n"
ls -la usr/local/sbin/* 2>/dev/null || printf "${YELLOW}No binaries found in usr/local/sbin\n"

printf "${GREEN}Installed libraries:\n"
ls -la usr/local/lib/*.so* 2>/dev/null || printf "${YELLOW}No libraries found\n"

# Clean up temporary files
rm -Rf "$tmpDir"

# Create extension release
createExtensionRelease auditd-"$latest_version" true

# Remove empty directories
find . -type d -empty -delete

popd > /dev/null || exit 1

if [ "${PUSH}" != false ]; then
  buildAndPush auditd-"$latest_version"
fi

if [ "${KEEP_FILES}" == "false" ]; then
  rm -Rf auditd-"$latest_version"
fi

printf "${GREEN}Done\n"
printf "${GREEN}auditd system extension created\n"
printf "${GREEN}Included packages: auditd, libaudit1, libauparse0t64, libaudit-common, libcap-ng0\n"
printf "${GREEN}Binaries: auditd, auditctl, ausearch, aureport, autrace, augenrules\n"
printf "${GREEN}Service: auditd.service\n"
printf "${GREEN}Configuration: /etc/audit/auditd.conf, /etc/audit/rules.d/\n"

