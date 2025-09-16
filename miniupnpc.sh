#!/usr/bin/env bash

source ./shared.sh

if [ -n "$MINIUPNPC_VERSION" ];then
  latest_version="$MINIUPNPC_VERSION"
else
  # Try to get the latest version from the REST API
  printf "${GREEN}Checking for latest version from REST API\n"
  api_response=$(curl -s "http://miniupnp.free.fr/files/rest.php/tags/miniupnpc?count=1")

  # Check if the response is valid JSON
  if echo "$api_response" | jq . >/dev/null 2>&1; then
    # Try to extract the version using the correct JSON path
    latest_version=$(echo "$api_response" | jq -r '.tags.miniupnpc[0].version' 2>/dev/null)

    # Debug output
    printf "${GREEN}REST API response: %s\n" "$api_response"
    printf "${GREEN}Extracted version: %s\n" "$latest_version"
  else
    latest_version=""
  fi

  # If REST API fails, try to parse the HTML page
  if [ -z "$latest_version" ] || [ "$latest_version" == "null" ]; then
    printf "${YELLOW}Failed to get latest version from REST API, trying to parse HTML page\n"

    # Try to extract the latest version from the HTML page
    html_page=$(curl -s "http://miniupnp.free.fr/files/")
    if [ -n "$html_page" ]; then
      # Look for miniupnpc-X.X.X.tar.gz pattern and extract the version
      latest_version=$(echo "$html_page" | grep -o 'miniupnpc-[0-9]\+\.[0-9]\+\.[0-9]\+\.tar\.gz' | head -1 | sed 's/miniupnpc-\([0-9]\+\.[0-9]\+\.[0-9]\+\)\.tar\.gz/\1/')
    fi

    # If HTML parsing fails, fall back to a default version
    if [ -z "$latest_version" ]; then
      printf "${YELLOW}Failed to parse HTML page, falling back to default version\n"
      latest_version="2.3.3"
    fi
  fi
fi

printf "${GREEN}Using version %s\n" "$latest_version"

URL=http://miniupnp.free.fr/files/miniupnpc-${latest_version}.tar.gz
SIG_URL=http://miniupnp.free.fr/files/miniupnpc-${latest_version}.tar.gz.sig

FORCE=${FORCE:-false}

if [ -d miniupnpc-"$latest_version" ]; then
  if [ "$FORCE" == "false" ];then
    printf "${RED}Version already exists\n"
    exit 0
  fi
  printf "${YELLOW}Version exists but FORCE was set, removing existing version\n"
  rm -Rf miniupnpc-"$latest_version"
fi

mkdir -p miniupnpc-"$latest_version"
pushd miniupnpc-"$latest_version" > /dev/null || exit 1
createDirs

# Create additional directories
printf "${GREEN}Creating directories\n"
mkdir -p usr/local/bin
mkdir -p usr/local/include/miniupnpc
mkdir -p usr/local/lib
mkdir -p usr/local/share/doc/miniupnpc

# Download MiniUPnPc and signature
printf "${GREEN}Downloading MiniUPnPc and signature\n"
tmpDir=$(mktemp -d)
curl -fsSL "${URL}" -o "$tmpDir/miniupnpc.tar.gz"
curl -fsSL "${SIG_URL}" -o "$tmpDir/miniupnpc.tar.gz.sig" || true

# Verify signature if gpg is available and signature exists
if [ -s "$tmpDir/miniupnpc.tar.gz.sig" ] && command -v gpg &> /dev/null; then
  printf "${GREEN}Verifying signature\n"

  # Try to import MiniUPnP GPG key
  # The key ID is extracted from the signature file
  key_id=$(gpg --verify "$tmpDir/miniupnpc.tar.gz.sig" "$tmpDir/miniupnpc.tar.gz" 2>&1 | grep "using RSA key" | awk '{print $NF}')

  if [ -n "$key_id" ]; then
    printf "${GREEN}Attempting to import key: %s\n" "$key_id"
    gpg --keyserver keyserver.ubuntu.com --recv-keys "$key_id" || \
    gpg --keyserver keys.openpgp.org --recv-keys "$key_id" || \
    gpg --keyserver pgp.mit.edu --recv-keys "$key_id" || true
  else
    printf "${YELLOW}Could not extract key ID from signature\n"
  fi

  # Try to verify again after key import
  if gpg --verify "$tmpDir/miniupnpc.tar.gz.sig" "$tmpDir/miniupnpc.tar.gz"; then
    printf "${GREEN}Signature verification successful\n"
  else
    printf "${RED}Signature verification failed\n"
    # If verification fails but SKIP_VERIFY is set, continue anyway
    if [ "${SKIP_VERIFY:-false}" == "true" ] || [ "${FORCE:-false}" == "true" ]; then
      printf "${YELLOW}SKIP_VERIFY or FORCE is set, continuing despite verification failure\n"
    else
      exit 1
    fi
  fi
elif [ ! -s "$tmpDir/miniupnpc.tar.gz.sig" ]; then
  printf "${YELLOW}Signature file is empty or could not be downloaded, skipping verification\n"
else
  printf "${YELLOW}GPG not available, skipping signature verification\n"
fi

# Extract the tar file
printf "${GREEN}Extracting MiniUPnPc\n"
tar xzf "$tmpDir/miniupnpc.tar.gz" -C "$tmpDir"

# Save the current directory
current_dir=$(pwd)
cd "$tmpDir/miniupnpc-$latest_version" || exit 1

# Build and install
printf "${GREEN}Building MiniUPnPc\n"
make

printf "${GREEN}Installing static binaries only\n"
# Install only the static binaries to avoid dependency issues
cp build/upnpc-static "$current_dir/usr/local/bin/upnpc"
cp build/upnp-listdevices-static "$current_dir/usr/local/bin/upnp-listdevices"

# Copy the external-ip script if it exists
if [ -f "external-ip.sh" ]; then
  cp external-ip.sh "$current_dir/usr/local/bin/external-ip"
fi

# Download and build NAT-PMP client
printf "${GREEN}Downloading and building NAT-PMP client\n"
natpmp_tmpdir=$(mktemp -d)
curl -fsSL "http://miniupnp.free.fr/files/libnatpmp-20150609.tar.gz" -o "$natpmp_tmpdir/libnatpmp.tar.gz"
tar xzf "$natpmp_tmpdir/libnatpmp.tar.gz" -C "$natpmp_tmpdir"
cd "$natpmp_tmpdir/libnatpmp-20150609" || exit 1

# Build NAT-PMP client
make natpmpc-static

# Install NAT-PMP client
cp natpmpc-static "$current_dir/usr/local/bin/natpmpc"

# Install NAT-PMP man page if it exists
if [ -f "natpmpc.1" ]; then
  mkdir -p "$current_dir/usr/local/share/man/man1"
  cp natpmpc.1 "$current_dir/usr/local/share/man/man1/"
  gzip -f "$current_dir/usr/local/share/man/man1/natpmpc.1"
fi

# Download and build PCP client (Port Control Protocol)
printf "${GREEN}Downloading and building PCP client\n"
pcp_tmpdir=$(mktemp -d)
cd "$pcp_tmpdir" || exit 1
git clone https://github.com/libpcpnatpmp/libpcpnatpmp.git
cd libpcpnatpmp || exit 1

# Build PCP client manually (static linking)
gcc -I lib/include -I lib -I lib/src -I lib/src/net -static -o pcpnatpmpc \
    cli-client/pcpnatpmpc.c lib/src/*.c lib/src/net/*.c -lm

# Install PCP client
cp pcpnatpmpc "$current_dir/usr/local/bin/pcpnatpmpc"

# Return to MiniUPnPc directory
cd "$current_dir/../miniupnpc-$latest_version" || exit 1

# Clean up build directories
rm -rf "$natpmp_tmpdir" "$pcp_tmpdir"

# Download and install network diagnostic tools from Ubuntu packages
printf "${GREEN}Installing network diagnostic tools from Ubuntu packages\n"

# Install zstd if not available (needed for Ubuntu 24.04 packages)
if ! command -v zstd >/dev/null 2>&1; then
    printf "${GREEN}Installing zstd for package extraction\n"
    apt-get update && apt-get install -y zstd
fi

# Create temporary directory for package extraction
pkg_tmpdir=$(mktemp -d)
cd "$pkg_tmpdir" || exit 1

# Download and extract netcat-openbsd package
printf "${GREEN}Installing netcat-openbsd from Ubuntu package\n"
curl -fsSL "http://archive.ubuntu.com/ubuntu/pool/main/n/netcat-openbsd/netcat-openbsd_1.226-1ubuntu2_amd64.deb" -o netcat-openbsd.deb
ar x netcat-openbsd.deb
# Ubuntu 24.04 uses zstd compression
if [ -f "data.tar.zst" ]; then
    zstd -d -f data.tar.zst && tar xf data.tar --no-same-owner --no-same-permissions 2>/dev/null || tar xf data.tar 2>/dev/null
elif [ -f "data.tar.xz" ]; then
    tar xf data.tar.xz --no-same-owner --no-same-permissions 2>/dev/null || tar xf data.tar.xz 2>/dev/null
fi
# netcat binary is in bin/nc.openbsd
if [ -f "bin/nc.openbsd" ]; then
    cp bin/nc.openbsd "$current_dir/usr/local/bin/nc"
elif [ -f "usr/bin/nc" ]; then
    cp usr/bin/nc "$current_dir/usr/local/bin/nc"
else
    printf "${RED}Warning: netcat binary not found in package\n"
fi

# Skip nmap for now - can be added later if needed

# Download and extract traceroute package
printf "${GREEN}Installing traceroute from Ubuntu package\n"
curl -fsSL "http://archive.ubuntu.com/ubuntu/pool/universe/t/traceroute/traceroute_2.1.5-1_amd64.deb" -o traceroute.deb
ar x traceroute.deb
# Ubuntu 24.04 uses zstd compression
if [ -f "data.tar.zst" ]; then
    zstd -d -f data.tar.zst && tar xf data.tar --no-same-owner --no-same-permissions 2>/dev/null || tar xf data.tar 2>/dev/null
elif [ -f "data.tar.xz" ]; then
    tar xf data.tar.xz --no-same-owner --no-same-permissions 2>/dev/null || tar xf data.tar.xz 2>/dev/null
fi
if [ -f "usr/bin/traceroute.db" ]; then
    cp usr/bin/traceroute.db "$current_dir/usr/local/bin/traceroute"
elif [ -f "usr/bin/traceroute" ]; then
    cp usr/bin/traceroute "$current_dir/usr/local/bin/traceroute"
else
    printf "${RED}Warning: traceroute binary not found in package\n"
fi

# Install man pages if available
if [ -f "usr/share/man/man1/traceroute.1.gz" ]; then
  mkdir -p "$current_dir/usr/local/share/man/man1"
  cp usr/share/man/man1/traceroute.1.gz "$current_dir/usr/local/share/man/man1/"
fi

# Clean up traceroute files
rm -f traceroute.deb debian-binary control.tar.* data.tar.*

# Note: nmap has too many dependencies for a static system extension
# Users can install nmap separately if needed

# Return to MiniUPnPc directory and clean up
cd "$current_dir/../miniupnpc-$latest_version" || exit 1
rm -rf "$pkg_tmpdir"

# Install headers for development (optional)
printf "${GREEN}Installing development headers\n"
mkdir -p "$current_dir/usr/local/include/miniupnpc"
if ls include/*.h >/dev/null 2>&1; then
  cp include/*.h "$current_dir/usr/local/include/miniupnpc/"
fi

# Install man page
printf "${GREEN}Installing documentation\n"
mkdir -p "$current_dir/usr/local/share/man/man3"
if [ -f "man3/miniupnpc.3" ]; then
  cp man3/miniupnpc.3 "$current_dir/usr/local/share/man/man3/"
  gzip -f "$current_dir/usr/local/share/man/man3/miniupnpc.3"
fi

# Copy additional documentation to doc directory
printf "${GREEN}Copying additional documentation\n"
mkdir -p "$current_dir/usr/local/share/doc/miniupnpc/"
for doc in README README.md README.txt; do
  if [ -f "$doc" ]; then
    cp "$doc" "$current_dir/usr/local/share/doc/miniupnpc/"
    break
  fi
done

for license in LICENSE LICENCE COPYING; do
  if [ -f "$license" ]; then
    cp "$license" "$current_dir/usr/local/share/doc/miniupnpc/"
    break
  fi
done

# Return to the original directory
cd "$current_dir" || exit 1

# Clean up
rm -Rf "$tmpDir"

# Create extension release
printf "${GREEN}Creating extension release\n"
createExtensionRelease miniupnpc-"$latest_version" false
find . -type d -empty -delete
popd > /dev/null || exit 1

if [ "${PUSH}" != false ]; then
  buildAndPush miniupnpc-"$latest_version"
fi

if [ "${KEEP_FILES}" == "false" ];then
  rm -Rf miniupnpc-"$latest_version"
fi

printf "${GREEN}Done\n"
