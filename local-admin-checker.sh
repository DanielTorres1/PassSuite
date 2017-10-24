#!/bin/bash
# Author: Daniel Torres
# daniel.torres@owasp.org
# ISB.COM.BO
THREADS="30"
OKBLUE='\033[94m'
OKRED='\033[91m'
OKGREEN='\033[92m'
RESET='\e[0m'

#iptables -I INPUT -p icmp --icmp-type 8 -j DROP

while getopts ":u:h:p:f:o:" OPTIONS
do
            case $OPTIONS in            
            u)     USUARIO=$OPTARG;;
            h)     HASH=$OPTARG;;
            p)     PASSWORD=$OPTARG;;
            f)     FILE=$OPTARG;;
            o)     OUTPUT=$OPTARG;;
            ?)     printf "Opcion invalida: -$OPTARG\n" $0
                          exit 2;;
           esac
done

USUARIO=${USUARIO:=NULL}
HASH=${HASH:=NULL}
PASSWORD=${PASSWORD:=NULL}
FILE=${FILE:=NULL}



function print_ascii_art {
cat << "EOF"

╦  ┌─┐┌─┐┌─┐┬    ┌─┐┌┬┐┌┬┐┬┌┐┌  ┌─┐┬ ┬┌─┐┌─┐┬┌─┌─┐┬─┐
║  │ ││  ├─┤│    ├─┤ │││││││││  │  ├─┤├┤ │  ├┴┐├┤ ├┬┘
╩═╝└─┘└─┘┴ ┴┴─┘  ┴ ┴─┴┘┴ ┴┴┘└┘  └─┘┴ ┴└─┘└─┘┴ ┴└─┘┴└─

					daniel.torres@owasp.org
					https://github.com/DanielTorres1

EOF
}


print_ascii_art

if [ $USUARIO = NULL ] ; then
echo "|              														 			"
echo "| USO: local-admin-checker.sh -u [usuario] -h [hash] -p [password] -o [salida] -f [file]"
echo "|																		 			"
echo ""
exit
fi

echo -e "$OKBLUE Probando con usuario: $USUARIO  y hash $HASH $RESET"
######################

if [ $FILE = NULL ] ; then

	if [ -f reports/OS-report.txt ]
	then
	
		for ip in $(grep -i Windows reports/OS-report.txt | cut -d ";" -f1 ); do	
			echo -e "[+] $OKBLUE Testeando $ip .. $RESET"
			if [ $HASH = NULL ] ; then
			#echo "PASSWORD $PASSWORD"
				pth-winexe -U $USUARIO%$PASSWORD //$ip ipconfig | grep -ai IPv4  | tee -a $OUTPUT
			else
				pth-winexe -U $USUARIO%aad3b435b51404eeaad3b435b51404ee:$HASH //$ip ipconfig | grep -ai IPv4  | tee -a $OUTPUT
			#echo "HASH $HASH"
			fi
			echo ""
			sleep 3
		done
	else
		echo -e "$OKRED [!] Error. Esta ejecuando en el directorio creado por lanScanner.sh ? $RESET"
	fi
else

  for ip in $(cat $FILE); do	
			echo -e "[+] $OKBLUE Testeando $ip .. $RESET"
			if [ $HASH = NULL ] ; then
			#echo "PASSWORD $PASSWORD"
				pth-winexe -U $USUARIO%$PASSWORD //$ip ipconfig | grep -ai IPv4  | tee -a $OUTPUT
			else
				pth-winexe -U $USUARIO%aad3b435b51404eeaad3b435b51404ee:$HASH //$ip ipconfig | grep -ai IPv4  | tee -a $OUTPUT
			#echo "HASH $HASH"
			fi
			echo ""
			sleep 3
	done
fi





