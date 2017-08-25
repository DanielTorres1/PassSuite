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
 

while getopts ":n:f:" OPTIONS
do
            case $OPTIONS in
            n)     NTLM=$OPTARG;;
            f)     FILE=$OPTARG;;
            ?)     printf "Opcion invalida: -$OPTARG\n" $0
                          exit 2;;
           esac
done

NTLM=${NTLM:=NULL}
FILE=${FILE:=NULL}

if [ $NTLM = NULL ] ; then

echo "|              														 			"
echo "| USO: crack.sh -n [1/2] -f archivo.txt   "
echo "|																		 			"
echo ""
exit
fi

sed -i 's/\$//' $FILE # Eliminar caracter $

for dic in $( ls /usr/share/wordlists/*.txt -l -S | sort -k 5 -n | awk '{print $9}'); do  # lista los .txt (primero los archivos pequeños)
echo "############# Using  $dic $1 ###############"
#john --wordlist=$dic  $1;
if [ $NTLM = 1 ] ; then
	john --wordlist=$dic --format=netntlm-naive $FILE;
fi

if [ $NTLM = 2 ] ; then
	john --wordlist=$dic --format=netntlmv2 $FILE;
fi


#mv $dic $dic.bk
done




