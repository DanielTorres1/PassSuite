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
            ?)     printf "Opcion invalida: -$OPTARG\n" $0
                          exit 2;;
           esac
done

USUARIO=${USUARIO:=NULL}
HASH=${HASH:=NULL}
PASSWORD=${PASSWORD:=NULL}
FILE=${FILE:=NULL}

function insert_data () {
	find .vulnerabilidades -size  0 -print0 |xargs -0 rm 2>/dev/null # delete empty files
	find .enumeracion -size  0 -print0 |xargs -0 rm 2>/dev/null # delete empty files
	insert-data.py
	mv .enumeracion/* .enumeracion2 2>/dev/null
	mv .vulnerabilidades/* .vulnerabilidades2 2>/dev/null		 	
	}
	

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
echo "| USO: local-admin-checker.sh -u [usuario] -h [hash] -p [password] -f [file]"
echo "|																		 			"
echo ""
exit
fi

echo -e "$OKBLUE Probando con usuario: $USUARIO  y hash $HASH $RESET"
######################

  for ip in $(cat $FILE); do	
			echo -e "[+] $OKBLUE Testeando $ip .. $RESET"
			if [ $HASH = NULL ] ; then
			#echo "PASSWORD $PASSWORD"				
				docker run  -it byt3bl33d3r/crackmapexec smb $ip -u $USUARIO -p $PASSWORD --local-auth -x ipconfig | tee logs/vulnerabilidades/$ip-windows-logeoRemoto.txt
			else
				pth-winexe -U $USUARIO%aad3b435b51404eeaad3b435b51404ee:$HASH //$ip ipconfig > logs/vulnerabilidades/$ip-windows-logeoRemoto.txt
					
			fi
			
			egrep -qai "IPv4" logs/vulnerabilidades/$ip-windows-logeoRemoto.txt
			greprc=$?
			if [[ $greprc -eq 0 ]] ; then						
				echo -e "\t$OKRED[i] Logeo remoto habilitado $RESET"
				if [ $HASH = NULL ] ; then
					echo -e "Usuario:$USUARIO Pasword:$password" >> .vulnerabilidades/$ip-windows-logeoRemoto.txt
				else
					echo -e "Usuario:$USUARIO Hash:aad3b435b51404eeaad3b435b51404ee:$HASH" >> .vulnerabilidades/$ip-windows-logeoRemoto.txt
				fi
				
			else
				echo -e "\t$OKGREEN[!] OK \n $RESET"				
			fi	
					
	done

insert_data



