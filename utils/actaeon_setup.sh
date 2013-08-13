#!/bin/bash

# Project   : Actaeon is a tool to perform memory forensics of virtualization 
#             environments.
# Name      : Minimal installation script for Actaeon


read -e -p "Enter Actaeon root installation dir: " -i "$PWD" ACT_ROOT_DIR
echo "$ACT_ROOT_DIR"
mkdir -p "$ACT_ROOT_DIR" 2>/dev/null

# Actaeon
cd "$ACT_ROOT_DIR"
git clone git://github.com/eurecom-s3/actaeon.git
ACT_DIR="$ACT_ROOT_DIR/actaeon"

# Dumper patch
cd "$ACT_ROOT_DIR"
svn checkout http://hyperdbg.googlecode.com/svn/trunk/ hyperdbg
HYP_DIR="$ACT_ROOT_DIR/hyperdbg"
cd "$HYP_DIR"
cp "$ACT_DIR/dumper/hdbg.diff" .
patch -p0 < hdbg.diff

# Volatility patch
cd "$ACT_ROOT_DIR"
wget http://volatility.googlecode.com/files/volatility-2.2.zip
unzip volatility-2.2.zip
VOL_DIR="$ACT_ROOT_DIR/volatility-2.2/"
cd "$VOL_DIR"
cp "$ACT_DIR/vol_patch/intel.diff" .
cp "$ACT_DIR/vol_patch/windows.diff" .
patch -p0 < intel.diff
patch -p0 < windows.diff

# Volatility Plugin
cp -R "$ACT_DIR/plugin/hypervisors/" "$VOL_DIR/volatility/plugins/"

echo "Happy hacking!"

