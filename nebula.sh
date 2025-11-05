#!/usr/bin/env bash

source ./shared.sh

# Define service mappings for GitHub Actions workflow
defineServiceMappings "nebula"

# Install Go if not available
install_go() {
  local go_version="1.25.4"
  local arch="amd64"

  if [ "$(uname -m)" = "aarch64" ]; then
    arch="arm64"
  fi

  printf "${GREEN}Installing Go ${go_version}\n"
  local go_tar="go${go_version}.linux-${arch}.tar.gz"

  # Download Go
  if ! curl -fsSL "https://go.dev/dl/${go_tar}" -o "${go_tar}"; then
    printf "${RED}Failed to download Go\n"
    exit 1
  fi

  # Remove old Go installations
  if [ -d /usr/local/go ]; then
    printf "${GREEN}Removing old Go installation from /usr/local/go\n"
    sudo rm -rf /usr/local/go
  fi

  # Remove conflicting Go installation from $HOME/go if it looks like a GOROOT
  if [ -d "$HOME/go/src" ] && [ -f "$HOME/go/VERSION" ]; then
    printf "${GREEN}Removing old Go installation from $HOME/go\n"
    # Remove everything except pkg/mod (module cache with read-only files)
    find "$HOME/go" -mindepth 1 -maxdepth 1 ! -name 'pkg' -exec rm -rf {} + 2>/dev/null || true
    # Remove the rest if possible, but don't fail if we can't
    rm -rf "$HOME/go" 2>/dev/null || true
  fi

  # Install Go
  if ! sudo tar -C /usr/local -xzf "${go_tar}"; then
    printf "${RED}Failed to install Go\n"
    exit 1
  fi

  # Clean up
  rm -f "${go_tar}"

  # Add Go to PATH for this session (prepend to override any existing Go)
  export PATH=/usr/local/go/bin:$PATH
  export GOPATH=$HOME/gopath
  # Unset GOROOT to let Go auto-detect it
  unset GOROOT

  printf "${GREEN}Go ${go_version} installed successfully\n"
}

# Check for required dependencies
check_dependencies() {
  local missing_deps=()

  if ! command -v git &> /dev/null; then
    missing_deps+=("git")
  fi

  if ! command -v make &> /dev/null; then
    missing_deps+=("make")
  fi

  if ! command -v gcc &> /dev/null; then
    missing_deps+=("gcc")
  fi

  # Check for Go version - we need 1.25.4 for Nebula with PKCS#11
  local go_installed=false
  if command -v go &> /dev/null; then
    local current_version=$(go version | awk '{print $3}' | sed 's/go//')
    if [[ "$current_version" == "1.25.4" ]]; then
      go_installed=true
      export PATH=/usr/local/go/bin:$PATH
      export GOPATH=$HOME/gopath
      # Unset GOROOT to let Go auto-detect it
      unset GOROOT
    fi
  elif [ -f /usr/local/go/bin/go ]; then
    export PATH=/usr/local/go/bin:$PATH
    export GOPATH=$HOME/gopath
    # Unset GOROOT to let Go auto-detect it
    unset GOROOT
    local current_version=$(go version | awk '{print $3}' | sed 's/go//')
    if [[ "$current_version" == "1.25.4" ]]; then
      go_installed=true
    fi
  fi

  # Install Go 1.25.4 if not present
  if [ "$go_installed" = false ]; then
    printf "${YELLOW}Go 1.25.4 not found, installing...\n"
    install_go
  fi

  # Check again after potential installation
  if ! command -v go &> /dev/null; then
    missing_deps+=("go")
  fi

  if [ ${#missing_deps[@]} -ne 0 ]; then
    printf "${RED}Missing required dependencies: %s\n" "${missing_deps[*]}"
    printf "${YELLOW}Please install the missing dependencies and try again.\n"
    printf "${YELLOW}On Ubuntu/Debian: sudo apt-get install git make build-essential\n"
    exit 1
  fi

  # Display versions for debugging
  printf "${GREEN}Dependencies check passed:\n"
  printf "${GREEN}  Git: $(git --version)\n"
  printf "${GREEN}  Make: $(make --version | head -1)\n"
  printf "${GREEN}  Go: $(go version)\n"
  printf "${GREEN}  GCC: $(gcc --version | head -1)\n"
}

if [ -n "$NEBULA_VERSION" ]; then
  latest_version="$NEBULA_VERSION"
else
  # Build from v1.9.7 tag and cherry-pick PKCS#11 support from PR #1153
  printf "${GREEN}Building v1.9.7 with PKCS#11 support cherry-picked from PR #1153\n"
  latest_version="v1.9.7"
fi

# PKCS#11 commit to cherry-pick (PR #1153 merge commit)
PKCS11_COMMIT="35603d1c39fa8bfb0d35ef7ee29716023d0c65c0"

printf "${GREEN}Using version %s\n" "$latest_version"

# Check dependencies before proceeding (unless SKIP_DEPS is set)
if [ "${SKIP_DEPS:-false}" != "true" ]; then
  check_dependencies
fi

FORCE=${FORCE:-false}

if [ -d nebula-"$latest_version" ]; then
  if [ "$FORCE" == "false" ]; then
    printf "${RED}Version already exists\n"
    exit 0
  fi
  printf "${YELLOW}Version exists but FORCE was set, removing existing version\n"
  rm -Rf nebula-"$latest_version"
fi

mkdir -p nebula-"$latest_version"
pushd nebula-"$latest_version" > /dev/null || exit 1
createDirs

# Create additional directories
printf "${GREEN}Creating directories\n"
mkdir -p usr/local/sbin
mkdir -p usr/local/lib/systemd/system

# Clone and build Nebula from source with PKCS#11 support
printf "${GREEN}Cloning and building Nebula with PKCS#11 support\n"

# Set up Go environment
export PATH=$PATH:/usr/local/go/bin
export GOPATH=$HOME/go
export GOCACHE=$HOME/.cache/go-build
mkdir -p "$GOPATH" "$GOCACHE"

# Clone the repository
printf "${GREEN}Cloning Nebula repository\n"
if [ "$latest_version" == "main" ]; then
  # Build from main branch for latest PKCS#11 support
  if ! git clone --depth 1 https://github.com/slackhq/nebula.git build; then
    printf "${RED}Failed to clone Nebula repository\n"
    exit 1
  fi
elif [[ "$latest_version" =~ ^[0-9a-f]{40}$ ]]; then
  # Build from specific commit hash
  if ! git clone https://github.com/slackhq/nebula.git build; then
    printf "${RED}Failed to clone Nebula repository\n"
    exit 1
  fi
  cd build || exit 1
  if ! git checkout "${latest_version}"; then
    printf "${RED}Failed to checkout commit ${latest_version}\n"
    exit 1
  fi
  cd .. || exit 1
else
  # Build from specific release tag and cherry-pick PKCS#11 support
  if ! git clone --branch "${latest_version}" https://github.com/slackhq/nebula.git build; then
    printf "${RED}Failed to clone Nebula repository at ${latest_version}\n"
    exit 1
  fi
fi

cd build || exit 1

# Cherry-pick PKCS#11 support if building from a tag (not main or specific commit)
if [[ ! "$latest_version" == "main" ]] && [[ ! "$latest_version" =~ ^[0-9a-f]{40}$ ]]; then
  printf "${GREEN}Cherry-picking PKCS#11 support from commit ${PKCS11_COMMIT}\n"

  # Fetch the PKCS#11 commit
  if ! git fetch origin "${PKCS11_COMMIT}"; then
    printf "${RED}Failed to fetch PKCS#11 commit\n"
    exit 1
  fi

  # Cherry-pick the PKCS#11 commit
  if ! git cherry-pick "${PKCS11_COMMIT}"; then
    printf "${RED}Failed to cherry-pick PKCS#11 support\n"
    printf "${YELLOW}There may be conflicts. Attempting to continue...\n"
    # Check if there are conflicts
    if git status | grep -q "Unmerged paths"; then
      printf "${RED}Cherry-pick has conflicts that need manual resolution\n"
      exit 1
    fi
  fi

  printf "${GREEN}Successfully cherry-picked PKCS#11 support\n"
fi

# Set GOTOOLCHAIN to use the local Go installation and prevent automatic downloads
export GOTOOLCHAIN=local

# Clear Go cache to avoid version mismatch issues
printf "${GREEN}Clearing Go cache\n"
go clean -cache -modcache

# Build Nebula with PKCS#11 support
printf "${GREEN}Building Nebula with PKCS#11 support (this may take a few minutes)\n"
if ! make bin-pkcs11; then
  printf "${RED}Failed to build Nebula with PKCS#11 support\n"
  exit 1
fi

# Copy binaries to the system extension directory
printf "${GREEN}Copying binaries to system extension\n"
cp nebula ../usr/local/sbin/ || {
  printf "${RED}Failed to copy nebula binary\n"
  exit 1
}
cp nebula-cert ../usr/local/sbin/ || {
  printf "${RED}Failed to copy nebula-cert binary\n"
  exit 1
}

# Go back to the sysext directory
cd .. || exit 1

# Clean up build directory
rm -Rf "build"

# Copy systemd service files
printf "${GREEN}Copying systemd service files\n"
cp ../services/nebula.* usr/local/lib/systemd/system/

# Create extension release
printf "${GREEN}Creating extension release\n"
createExtensionRelease nebula-"$latest_version" true
find . -type d -empty -delete
popd > /dev/null || exit 1

if [ "${PUSH}" != false ]; then
  buildAndPush nebula-"$latest_version"
fi

if [ "${KEEP_FILES}" == "false" ]; then
  rm -Rf nebula-"$latest_version"
fi

printf "${GREEN}Done\n"
