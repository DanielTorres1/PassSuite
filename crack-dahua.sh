#!/bin/bash

# cat `ls | grep --color=never v2` > NTLMv2.txt
# sed -i 's/\$//' NTLMv2.txt

function print_ascii_art {
cat << "EOF"
   __               __                                 
CRACK-NTLM 

			daniel.torres@owasp.org
			https://github.com/DanielTorres1

EOF
}


print_ascii_art
 

while getopts ":f:" OPTIONS
do
            case $OPTIONS in            
            f)     FILE=$OPTARG;;
            ?)     printf "Opcion invalida: -$OPTARG\n" $0
                          exit 2;;
           esac
done

FILE=${FILE:=NULL}

if [ $FILE = NULL ] ; then

echo "|              														 			"
echo "| USO: crack-dahua.sh -f archivo.txt   "
echo "|																		 			"
echo ""
exit
fi

#sed -i 's/\$//' $FILE # Eliminar caracter $
rm ~/.john/john.pot
for dic in $( ls /media/sistemas/Passwords/Passwords/*.txt -l -S | sort -k 5 -n | awk '{print $9}'); do  # lista los .txt (primero los archivos pequeños)
   echo "############# Using  $dic $1 ###############"   
   john --wordlist=$dic $FILE;  #usuario:$dahua$i7lMtGcs   
done

#cisco
if [ -f ~/.john/john.pot ]
then
	while read line       
	do   
      hash=`echo $line | cut -f1 -d":"`
      password=`echo $line | cut -f2 -d":"`
      echo "$hash $password"

      sed -i "s/$hash/$password/g" $FILE
		
 	done <~/.john/john.pot
fi




