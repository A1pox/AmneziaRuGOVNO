#!/bin/bash
set -e

VERSION=$1
RELEASE_REPO=${GITHUB_RELEASE_REPO:-${GITHUB_REPOSITORY:-amnezia-vpn/amnezia-client}}
API_BASE_URL="https://api.github.com/repos/${RELEASE_REPO}"
DOWNLOAD_BASE_URL="https://github.com/${RELEASE_REPO}/releases/download/${VERSION}"

if [[ -z "$VERSION" ]]; then
    echo '::error::VERSION does not set. Exiting with error...'
    exit 1
fi

mkdir -p dist

cd dist

echo $VERSION >> VERSION
curl -s "${API_BASE_URL}/releases/tags/$VERSION" | jq -r .body | tr -d '\r' > CHANGELOG
curl -s "${API_BASE_URL}/releases/tags/$VERSION" | jq -r .published_at > RELEASE_DATE

if [[ $(cat CHANGELOG) = null ]]; then
	echo '::error::Release does not exists. Exiting with error...'
	exit 1
fi

# Download files with error handling
download_file() {
    local url=$1
    local filename=$(basename "$url")
    echo "Downloading $filename..."
    if ! wget -q "$url"; then
        echo "::error::Failed to download $filename from $url"
        exit 8
    fi
    echo "Successfully downloaded $filename"
}

download_file "${DOWNLOAD_BASE_URL}/AmneziaVPN_${VERSION}_android9+_arm64-v8a.apk"
download_file "${DOWNLOAD_BASE_URL}/AmneziaVPN_${VERSION}_android9+_armeabi-v7a.apk"
download_file "${DOWNLOAD_BASE_URL}/AmneziaVPN_${VERSION}_android9+_x86.apk"
download_file "${DOWNLOAD_BASE_URL}/AmneziaVPN_${VERSION}_android9+_x86_64.apk"
download_file "${DOWNLOAD_BASE_URL}/AmneziaVPN_${VERSION}_linux_x64.tar"
download_file "${DOWNLOAD_BASE_URL}/AmneziaVPN_${VERSION}_macos.pkg"
download_file "${DOWNLOAD_BASE_URL}/AmneziaVPN_${VERSION}_x64.exe"

cd ../

echo "Syncing to R2..."
if ! rclone sync ./dist/ r2:/updates/; then
    echo "::error::Failed to sync files to R2"
    exit 8
fi

echo "Deployment completed successfully!"
