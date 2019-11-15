#!/bin/bash

echo "Installing pre-requisite package"
apt-get -y install libpam-cracklib
clear

echo "Backing up existing config"
mkdir ConfigBackups
cp /etc/pam.d/common-auth ./ConfigBackups
cp /etc/pam.d/common-password ./ConfigBackups
cp /etc/login.defs ./ConfigBackups
clear

echo "Writing changes to password configuration files"
cat ./common-auth > /etc/pam.d/common-auth
cat ./common-password > /etc/pam.d/common-password
cat ./login.defs > /etc/login.defs
clear

echo "Done!"
