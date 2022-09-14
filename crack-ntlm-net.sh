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
 

while getopts ":f:d:k:" OPTIONS
do
            case $OPTIONS in            
            f)     FOLDER=$OPTARG;;
            d)     DICTIONARY_FOLDER=$OPTARG;;
            k)     KEYWORD=$OPTARG;;
            ?)     printf "Opcion invalida: -$OPTARG\n" $0
                          exit 2;;
           esac
done

FOLDER=${FOLDER:=NULL}
DICTIONARY_FOLDER=${DICTIONARY_FOLDER:=NULL}
KEYWORD=${KEYWORD:=NULL}

if [ $FOLDER = NULL ] ; then

echo "|              														 			"
echo "| USO: crack-ntlm-net.sh -f folder-with-hashes -d /media/sistemas/Passwords/Passwords/ -k diaconia  "
echo "|																		 			"
echo ""
exit
fi

rm cracked.txt 2>/dev/null
rm hash-ntlm-net.txt 2>/dev/null

for archivo in $(ls $FOLDER/*.txt); do
   head -1 $archivo >> hash-ntlm-net.txt
done

echo "Generating custom password dic"
echo $KEYWORD > keyword.txt
passGen.sh -f keyword.txt -t offline: -o offline.txt -v 1
echo "copy offline.txt to $DICTIONARY_FOLDER"
cp offline.txt $DICTIONARY_FOLDER

echo "Generated hashfile with `wc -l hash-ntlm-net.txt`"
./hashcat.bin -m 5600 -a 0 hash-ntlm-net.txt $DICTIONARY_FOLDER -o cracked.txt
