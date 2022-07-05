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
apt install medusa crowbar

cp cracker.sh /usr/bin
chmod a+x /usr/bin/cracker.sh

cp passGen.sh /usr/bin
chmod a+x /usr/bin/passGen.sh

cp mkbrutus.py /usr/bin
chmod a+x /usr/bin/mkbrutus.py

cp XBruteForcer.pl /usr/bin
chmod a+x /usr/bin/XBruteForcer.pl

cp passTelnet.pl /usr/bin
cp crack-ntlm.sh /usr/bin
cp wpbrute.sh /usr/bin
chmod a+x /usr/bin/wpbrute.sh

#cp generate-password.pl /usr/bin
#chmod a+x /usr/bin/generate-password.pl

cp generate-users.pl /usr/bin
cp patator.py /usr/bin
chmod a+x /usr/bin/generate-users.pl


echo -e "${RED}[+]${GREEN} Instalando john the ripper ${RESET}"

sudo apt-get -y install john
sudo cp /etc/john/john.conf /etc/john/john.conf.bk
sudo cp john.conf  /etc/john/john.conf

echo -e "${RED}[+]${GREEN} Instalando DefaultCreds-cheat-sheet  ${RESET}"
cd DefaultCreds-cheat-sheet
pip install -r requirements.txt
cd ..

# oracle 

# apt-get install -y ruby-dev libaio-dev build-essential libgmp-dev
# mkdir /opt/oracle
# mv instantclient_18_3 /opt/oracle

# export PATH=$PATH:/opt/oracle/instantclient_18_3
# export SQLPATH=/opt/oracle/instantclient_18_3
# export TNS_ADMIN=/opt/oracle/instantclient_18_3
# export LD_LIBRARY_PATH=/opt/oracle/instantclient_18_3
# export ORACLE_HOME=/opt/oracle/instantclient_18_3

# cd ruby-oci8-ruby-oci8-2.1.8
# make
# make install

cd /usr/share/wordlists
rm top200.txt 2> /dev/null
rm usuarios-en.txt 2> /dev/null
wget https://raw.githubusercontent.com/DanielTorres1/passwords/master/top200.txt
wget https://raw.githubusercontent.com/DanielTorres1/passwords/master/usuarios-en.txt