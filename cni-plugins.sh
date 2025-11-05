#!/usr/bin/env bash
#
# CNI Plugins system extension script
#
# Downloads and installs Container Network Interface (CNI) plugins
# from https://github.com/containernetworking/plugins
#

source ./shared.sh

# Define service mappings for GitHub Actions workflow
# CNI plugins don't have systemd services - they're called by container runtimes
defineServiceMappings ""

if [ -n "$CNI_PLUGINS_VERSION" ]; then
  latest_version="$CNI_PLUGINS_VERSION"
else
  latest_version=$(curl -s https://api.github.com/repos/containernetworking/plugins/releases/latest | jq -r '.tag_name')
fi

printf "${GREEN}Using version %s\n" "$latest_version"

URL=https://github.com/containernetworking/plugins/releases/download/${latest_version}/cni-plugins-linux-amd64-${latest_version}.tgz
SHASUM_URL=https://github.com/containernetworking/plugins/releases/download/${latest_version}/cni-plugins-linux-amd64-${latest_version}.tgz.sha256

FORCE=${FORCE:-false}

if [ -z "$latest_version" ]; then
  exit 1
fi

if [ -d cni-plugins-"$latest_version" ]; then
  if [ "$FORCE" == "false" ]; then
    printf "${RED}Version already exists\n"
    exit 0
  fi
  printf "${YELLOW}Version exists but FORCE was set, removing existing version\n"
  rm -Rf cni-plugins-"$latest_version"
fi

mkdir -p cni-plugins-"$latest_version"
pushd cni-plugins-"$latest_version" > /dev/null || exit 1
createDirs

# Create directory for CNI plugins
mkdir -p usr/local/libexec/cni

# Download CNI plugins and checksum
printf "${GREEN}Downloading CNI plugins and checksum\n"
tmpDir=$(mktemp -d)
curl -fsSL "${URL}" -o "$tmpDir/cni-plugins.tgz"
curl -fsSL "${SHASUM_URL}" -o "$tmpDir/cni-plugins.tgz.sha256"

# Verify checksum if sha256sum is available
if command -v sha256sum &> /dev/null; then
  printf "${GREEN}Verifying checksum\n"

  # The .sha256 file contains just the checksum, not the filename
  expected_checksum=$(cat "$tmpDir/cni-plugins.tgz.sha256" | awk '{print $1}')

  if [ -n "$expected_checksum" ]; then
    # Calculate the actual checksum
    actual_checksum=$(sha256sum "$tmpDir/cni-plugins.tgz" | awk '{print $1}')

    if [ "$actual_checksum" = "$expected_checksum" ]; then
      printf "${GREEN}Checksum verification successful\n"
    else
      printf "${RED}Checksum verification failed\n"
      printf "${RED}Expected: %s\n" "$expected_checksum"
      printf "${RED}Actual: %s\n" "$actual_checksum"
      # If verification fails but SKIP_VERIFY is set, continue anyway
      if [ "${SKIP_VERIFY:-false}" == "true" ]; then
        printf "${YELLOW}SKIP_VERIFY is set, continuing despite verification failure\n"
      else
        exit 1
      fi
    fi
  else
    printf "${YELLOW}Could not find checksum in .sha256 file\n"
    if [ "${SKIP_VERIFY:-false}" == "true" ]; then
      printf "${YELLOW}SKIP_VERIFY is set, continuing without verification\n"
    else
      exit 1
    fi
  fi
else
  printf "${YELLOW}sha256sum not available, skipping checksum verification\n"
fi

# Extract the tar file
printf "${GREEN}Extracting CNI plugins\n"
tar xzf "$tmpDir/cni-plugins.tgz" -C usr/local/libexec/cni

# Make all binaries executable
chmod +x usr/local/libexec/cni/*

# List installed plugins
printf "${GREEN}Installed CNI plugins:\n"
ls -la usr/local/libexec/cni/

# Clean up
rm -Rf "$tmpDir"
createExtensionRelease cni-plugins-"$latest_version" false
find . -type d -empty -delete
popd > /dev/null || exit 1
if [ "${PUSH}" != false ]; then
  buildAndPush cni-plugins-"$latest_version"
fi
if [ "${KEEP_FILES}" == "false" ]; then
  rm -Rf cni-plugins-"$latest_version"
fi
printf "${GREEN}Done\n"

