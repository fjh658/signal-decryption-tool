#!/bin/bash

# Ensure necessary targets are installed
echo "Adding required Rust targets..."
rustup target add x86_64-apple-darwin aarch64-apple-darwin

# Set the output directory
OUTPUT_DIR="target/universal"
mkdir -p $OUTPUT_DIR

# Build for x86_64 with additional link arguments to strip symbols
echo "Building for x86_64..."
cargo build --release --target x86_64-apple-darwin
if [ $? -ne 0 ]; then
    echo "Failed to build for x86_64."
    exit 1
fi

# Build for aarch64 with additional link arguments to strip symbols
echo "Building for aarch64..."
cargo build --release --target aarch64-apple-darwin
if [ $? -ne 0 ]; then
    echo "Failed to build for aarch64."
    exit 1
fi

# Check if the binaries exist
if [ ! -f "target/x86_64-apple-darwin/release/SignalDecryption" ]; then
    echo "x86_64 binary not found!"
    exit 1
fi

if [ ! -f "target/aarch64-apple-darwin/release/SignalDecryption" ]; then
    echo "aarch64 binary not found!"
    exit 1
fi

# Strip debug symbols more aggressively
echo "Stripping debug symbols..."
strip -S -x target/x86_64-apple-darwin/release/SignalDecryption
strip -S -x target/aarch64-apple-darwin/release/SignalDecryption

# Use lipo to create a universal binary
echo "Creating universal binary..."
lipo -create -output $OUTPUT_DIR/SignalDecryption \
    target/x86_64-apple-darwin/release/SignalDecryption \
    target/aarch64-apple-darwin/release/SignalDecryption

if [ $? -eq 0 ]; then
    echo "Universal binary created at $OUTPUT_DIR/SignalDecryption"
else
    echo "Failed to create universal binary."
    exit 1
fi
