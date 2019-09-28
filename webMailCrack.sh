#!/bin/bash


THREADS="30"
OKBLUE='\033[94m'
OKRED='\033[91m'
OKGREEN='\033[92m'
OKORANGE='\033[93m'
RESET='\e[0m'
                

function print_ascii_art {
cat << "EOF"
    

					daniel.torres@owasp.org
					https://github.com/DanielTorres1

EOF
}


print_ascii_art


while getopts ":u:e:a:" OPTIONS
do
            case $OPTIONS in
            u)     USUARIOS=$OPTARG;;            
            e)     ENTIDAD=$OPTARG;;            
            a)     ARCHIVO=$OPTARG;;            
            ?)     printf "Opcion invalida: -$OPTARG\n" $0
                          exit 2;;
           esac
done

USUARIOS=${USUARIOS:=NULL}
ENTIDAD=${ENTIDAD:=NULL}
ARCHIVO=${ARCHIVO:=NULL}

if [ $USUARIOS = NULL ] ; then

cat << "EOF"

Opciones: 

-u : Archivo con el listado de usuarios
-e : Nombre de la entidad
-a : Archivo xml con la peticion (Burpsuite)

EOF

exit
fi

NOMBRE_ARCHIVO=`echo "$ARCHIVO" | cut -d'.' -f1`

echo -e "$OKGREEN#################################### EMPEZANDO A CRACKEAR ########################################$RESET"

for user in `cat $USUARIOS`;
do
	echo $ENTIDAD > base.txt 		
	echo $user >> base.txt
	passGen.sh -f base.txt -t top200 -o top.txt	
	echo -e "$OKBLUE\n\t#################### Testeando usuario: $user ######################$RESET"	    	
	webintruder.pl -f $ARCHIVO -t login -u $user -p top.txt -q 1
	rm top.txt
	cat $NOMBRE_ARCHIVO-login.csv >> results.csv	
	echo ""
done
rm $NOMBRE_ARCHIVO-usertest.csv
