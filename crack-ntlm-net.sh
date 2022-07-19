#!/bin/bash

# cat `ls | grep --color=never v2` > NTLMv2.txt
# sed -i 's/\$//' NTLMv2.txt

function print_ascii_art {
cat << "EOF"
   __               __                                 
CRACK-NTLM-NET 

			daniel.torres@owasp.org
			https://github.com/DanielTorres1

EOF
}


print_ascii_art
 

while getopts ":f:d:" OPTIONS
do
            case $OPTIONS in            
            f)     FOLDER=$OPTARG;;
            d)     DICTIONARY=$OPTARG;;
            ?)     printf "Opcion invalida: -$OPTARG\n" $0
                          exit 2;;
           esac
done

FOLDER=${FOLDER:=NULL}
DICTIONARY=${DICTIONARY:=NULL}

if [ $FOLDER = NULL ] ; then

echo "|              														 			"
echo "| USO: crack-ntlm-net.sh -f folder   "
echo "|																		 			"
echo ""
exit
fi

rm cracked.txt 2>/dev/null
rm hash-ntlm.txt 2>/dev/null

for archivo in $(ls $FOLDER/*.txt); do
   head -1 $archivo >> hash-ntlm.txt
done

echo "Generated hashfile with `wc -l hash-ntlm.txt`"
./hashcat.bin -m 5600 -a 0 hash-ntlm.txt $DICTIONARY -o cracked.txt