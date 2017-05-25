#!/bin/bash
RED="\033[01;31m"      # Issues/Errors
GREEN="\033[01;32m"    # Success
YELLOW="\033[01;33m"   # Warnings/Information
BLUE="\033[01;34m"     # Heading
BOLD="\033[01;01m"     # Highlight
RESET="\033[00m"       # Normal



echo -e "${RED}[+]${GREEN} Instalando john the ripper ${RESET}"
#sudo apt-get update
sudo apt-get install john

echo -e "${RED}[+]${GREEN} Copiando reglas de john the ripper ${RESET}"
sudo cat john.conf >> /etc/john/john.conf
echo ""

echo -e "${RED}[+]${GREEN} Copiando dicconarios comunes ${RESET}"
sudo mkdir /usr/share/wordlists 2>/dev/null
sudo cp wordlist/passwords-comunes* /usr/share/wordlists/

cp crear-passwords.sh /usr/bin
chmod a+x /usr/bin/crear-passwords.sh
