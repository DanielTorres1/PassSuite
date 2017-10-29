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

echo -e "${RED}[+]${GREEN} Copiando passGen ${RESET}"
cp passGen.sh /usr/bin
chmod a+x /usr/bin/passGen.sh

cp mkbrutus.py /usr/bin
chmod a+x /usr/bin/mkbrutus.py

cp passTelnet.pl /usr/bin
cp crack-ntlm.sh /usr/bin

chmod a+x /usr/bin/passTelnet.pl
chmod a+x /usr/bin/crack-ntlm.sh

echo -e "${RED}[+]${GREEN} Instalando john the ripper ${RESET}"
distro=`cat /etc/*-release | head -1|cut -d "=" -f2`
if [ $distro = "Kali" ]  || [ $distro = "Parrot" ] ; then 
	echo "{+} kali/Parrot detectado"
	sudo apt-get install john

	echo -e "${RED}[+]${GREEN} Copiando reglas de john the ripper ${RESET}"
	sudo cat john.conf >> /etc/john/john.conf
	echo ""

else
	echo "{+} $distro detectado"
	cp john.conf /opt/
	cp john /usr/bin
	chmod a+x /usr/bin/john

	cd /opt/; wget https://github.com/magnumripper/JohnTheRipper/archive/bleeding-jumbo.tar.gz
	tar -zxvf bleeding-jumbo.tar.gz
	sudo cat john.conf >> JohnTheRipper-bleeding-jumbo/run/john.conf
	cd JohnTheRipper-bleeding-jumbo/src
	./configure && make

fi	
