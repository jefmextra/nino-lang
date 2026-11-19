#!/bin/sh
set -e

NINO_DIR="$HOME/.nino"
BIN_DIR="$NINO_DIR/bin"
STD_DIR="$NINO_DIR/std"
EX_DIR="$NINO_DIR/examples"

OS="$(uname -s)"
ARCH="$(uname -m)"

echo ""
echo "  _   _ _              "
echo " | \ | (_)_ __   ___   "
echo " |  \| | | '_ \ / _ \  "
echo " | |\  | | | | | (_) | "
echo " |_| \_|_|_| |_|\___/  "
echo ""
echo "Installing The Nino Programming Language (v1.2.2)..."
echo "Platform: $OS ($ARCH)"

mkdir -p "$BIN_DIR"
mkdir -p "$STD_DIR"
mkdir -p "$EX_DIR"

if [ "$OS" = "Linux" ] && [ "$ARCH" = "x86_64" ]; then
    TAR_URL="https://github.com/jefmextra/nino-lang/releases/download/v1.2.2/nino-v1.2.2-linux-x64.tar.gz"
    TMP_TAR="${TMPDIR:-/tmp}/nino-v1.2.2-linux-x64.tar.gz"
    echo "Downloading $TAR_URL..."
    curl -fL "$TAR_URL" -o "$TMP_TAR"
    tar -xzf "$TMP_TAR" -C "$NINO_DIR"
    cp -f "$NINO_DIR/ninoc" "$BIN_DIR/ninoc"
    chmod +x "$BIN_DIR/ninoc"
    cp -f "$NINO_DIR/ninoc" "$BIN_DIR/nino"
    chmod +x "$BIN_DIR/nino"
    rm -f "$TMP_TAR"
else
    echo "Prebuilt binary packages currently target Linux x86_64 and Windows x64." >&2
    echo "On $OS ($ARCH), clone https://github.com/jefmextra/nino-lang and run ./bootstrap/install.sh" >&2
    exit 1
fi

PROFILE=""
if [ -f "$HOME/.bashrc" ]; then
    PROFILE="$HOME/.bashrc"
elif [ -f "$HOME/.zshrc" ]; then
    PROFILE="$HOME/.zshrc"
elif [ -f "$HOME/.profile" ]; then
    PROFILE="$HOME/.profile"
fi

if [ -n "$PROFILE" ]; then
    if ! grep -q '.nino/bin' "$PROFILE"; then
        echo 'export PATH="$HOME/.nino/bin:$PATH"' >> "$PROFILE"
        echo "Added $BIN_DIR to $PROFILE"
    fi
fi

echo ""
echo "[SUCCESS] Nino v1.2.2 installed successfully in $NINO_DIR"
echo "To get started, restart your shell or run:"
echo '  export PATH="$HOME/.nino/bin:$PATH"'
echo "  ninoc version"
