#!/bin/bash
RED="\033[01;31m"      # Issues/Errors
GREEN="\033[01;32m"    # Success
YELLOW="\033[01;33m"   # Warnings/Information
BLUE="\033[01;34m"     # Heading
BOLD="\033[01;01m"     # Highlight
RESET="\033[00m"       # Normal

function print_ascii_art {
cat << "EOF"
                                                                                       
88888888ba                                       ,ad8888ba,                            
88      "8b                                     d8"'    `"8b                           
88      ,8P                                    d8'                                     
88aaaaaa8P'  ,adPPYYba,  ,adPPYba,  ,adPPYba,  88              ,adPPYba,  8b,dPPYba,   
88""""""'    ""     `Y8  I8[    ""  I8[    ""  88      88888  a8P_____88  88P'   `"8a  
88           ,adPPPPP88   `"Y8ba,    `"Y8ba,   Y8,        88  8PP"""""""  88       88  
88           88,    ,88  aa    ]8I  aa    ]8I   Y8a.    .a88  "8b,   ,aa  88       88  
88           `"8bbdP"Y8  `"YbbdP"'  `"YbbdP"'    `"Y88888P"    `"Ybbd8"'  88       88  
                                                                                       
                                                                                       

					daniel.torres@owasp.org
					https://github.com/DanielTorres1

EOF
}


print_ascii_art

echo -e "${RED}[+]${GREEN} Instalando john the ripper ${RESET}"
#sudo apt-get update
sudo apt-get install john

echo -e "${RED}[+]${GREEN} Copiando reglas de john the ripper ${RESET}"
sudo cat john.conf >> /etc/john/john.conf
echo ""

echo -e "${RED}[+]${GREEN} Copiando dicconarios comunes ${RESET}"
sudo mkdir /usr/share/wordlists 2>/dev/null
sudo cp wordlist/passwords-comunes* /usr/share/wordlists/

cp passGen.sh /usr/bin
chmod a+x /usr/bin/passGen.sh
