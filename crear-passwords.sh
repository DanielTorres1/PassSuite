#!/bin/bash


while getopts ":t:f:o:l:v:" OPTIONS
do
            case $OPTIONS in            
            f)     FILE=$OPTARG;;
            t)     TYPE=$OPTARG;;
            o)     OUTPUT=$OPTARG;;
            l)     LANGUAGE=$OPTARG;;
            v)     VERBOSE=$OPTARG;;
            ?)     printf "Opcion invalida: -$OPTARG\n" $0
                          exit 2;;
           esac
done                                                                                                      


TYPE=${TYPE:=NULL}
FILE=${FILE:=NULL}
OUTPUT=${OUTPUT:=NULL}
LANGUAGE=${LANGUAGE:=NULL}
VERBOSE=${VERBOSE:=NULL}


if [ $LANGUAGE == "es" ]
then
	comunes="/usr/share/wordlists/passwords-comunes-es.txt"
else
	comunes="/usr/share/wordlists/passwords-comunes-en.txt"
fi

if [ $VERBOSE == "1" ]
then
echo -e " _____                               _                                                        _              __   _____ "
echo -e "|  __ \                             | |                                                      | |            /  | |  _  |"
echo -e '| |  \/ ___ _ __   ___ _ __ __ _  __| | ___  _ __   _ __   __ _ ___ _____      _____  _ __ __| |___  __   __ | | | | / |'
echo -e '| | __ / _ \  _ \ / _ \  __/ _` |/ _` |/ _ \|  __| |  _ \ / _  / __/ __\ \ /\ / / _ \|  __/ _` / __| \ \ / / | | |  /| |'
echo -e "| |_\ \  __/ | | |  __/ | | (_| | (_| | (_) | |    | |_) | (_| \__ \__ \\ V  V /  (_) | | | (_| \__ \  \ V / _| |_| |_/ /"
echo -e " \____/\___|_| |_|\___|_|  \__,_|\__,_|\___/|_|    | .__/ \__,_|___/___/ \_/\_/ \___/|_|  \__,_|___/   \_/  \___(_)___/ "
echo -e "						   | |                                                                  "
echo -e "	  					   |_|                     "														  
echo -e "			 		  __ __                   "															  
echo -e "					|(_ |__)    _ _  _    |_  _  "
echo -e "					|__)|__).  (_(_)|||.  |_)(_) "
echo ""
echo "					daniel.torres@owasp.org"
echo "				https://github.com/DanielTorres1"
echo ""
fi



if [ $FILE = NULL ] ; then

echo "|              														 			"
echo "| USO: crear-passwords.sh -f [Lista de passwords base] -t [offline/online] -l [en/es] -o [salida] -v 1"
echo "|																		 			"
echo "|  Author:daniel.torres@owasp.org                              			"
echo ""
exit
fi
######################

 if [ $TYPE == "year" ]
  then
  john --wordlist=$FILE --rules=rule15 --stdout >> temp-pass.txt 2> /dev/null	
  cat $FILE temp-pass.txt | sort | uniq > $OUTPUT 
  exit
  fi
  
  if [ $TYPE == "offline" ]
  then
  
	   if [ $VERBOSE == "1" ]
      then
        echo -e "\n REGLA 1: Password  + 2 dígitos"
        echo -e "\n REGLA 2: Password  + 3 dígitos"
        echo -e "\n REGLA 3: Password  + 4 dígitos"
        echo -e "\n REGLA 4: Password  + 5 dígitos"
        echo -e "\n REGLA 5: Password  + 2 dígitos + 1 carácter especial"
        echo -e "\n REGLA 6: Password  + 3 dígitos + 1 carácter especial"
        echo -e "\n REGLA 7: Password  + 4 dígitos + 1 carácter especial"
        echo -e "\n REGLA 8: Password + 1 carácter especial + 2 digitos"
        echo -e "\n REGLA 9: Password + 1 carácter especial + 3 digitos"      
        echo -e "\n REGLA 15: Password + 111,000,etc"      
      fi
	  
  	  john --wordlist=$FILE --rules=rule1 --stdout >> temp-pass.txt 2> /dev/null	  
	  john --wordlist=$FILE --rules=rule2 --stdout >> temp-pass.txt 2> /dev/null
	  john --wordlist=$FILE --rules=rule3 --stdout >> temp-pass.txt 2> /dev/null  
	  john --wordlist=$FILE --rules=rule4 --stdout >> temp-pass.txt 2> /dev/null	 
	  john --wordlist=$FILE --rules=rule5 --stdout >> temp-pass.txt 2> /dev/null	 
	  john --wordlist=$FILE --rules=rule6 --stdout >> temp-pass.txt 2> /dev/null
	  john --wordlist=$FILE --rules=rule7 --stdout >> temp-pass.txt 2> /dev/null
	  john --wordlist=$FILE --rules=rule8 --stdout >> temp-pass.txt 2> /dev/null	
	  john --wordlist=$FILE --rules=rule9 --stdout >> temp-pass.txt 2> /dev/null 	  
	  john --wordlist=$FILE --rules=rule15 --stdout >> temp-pass.txt 2> /dev/null 	  
   else


    if [ $VERBOSE == "1" ]
    then
	  echo -e "\n REGLA 1: Password  + 2 dígitos"    
	  echo -e "\n REGLA 10: Password  + anio (2000+)"
	  echo -e "\n REGLA 11: Password  + anio anio (1900+)"
	  echo -e "\n REGLA 12: Password  + anio (2000+) + 1 carácter especial"
	  echo -e "\n REGLA 13: Password  + anio (1900+) + 1 carácter especial"
	  echo -e "\n REGLA 13: Password  + anio (2012-2017)"
	  echo -e "\n REGLA 15: Password + 111,000,etc"   
    fi

	  john --wordlist=$FILE --rules=rule1 --stdout >> temp-pass.txt 2> /dev/null	
	  john --wordlist=$FILE --rules=rule10 --stdout >> temp-pass.txt 2> /dev/null	
	  john --wordlist=$FILE --rules=rule11 --stdout >> temp-pass.txt 2> /dev/null
	  john --wordlist=$FILE --rules=rule12 --stdout >> temp-pass.txt 2> /dev/null	
	  john --wordlist=$FILE --rules=rule13 --stdout >> temp-pass.txt 2> /dev/null
	  john --wordlist=$FILE --rules=rule14 --stdout >> temp-pass.txt 2> /dev/null
	  john --wordlist=$FILE --rules=rule15 --stdout >> temp-pass.txt 2> /dev/null 	  
   fi
 


    if [ $VERBOSE == "1" ]
    then	  
	  echo -e "\n REGLA 16: Volver Mayuscula la primera letra"
	  echo -e "\n REGLA 17: Volver Mayuscula todo"	  
	  #echo -e "\n  REGLA 18: Mutar s/$ , a/@ , l/1, e/3, g/9, i=1, o=0"
    fi
 
    john --wordlist=temp-pass.txt --rules=rule16 --stdout >> temp-pass1.txt 2> /dev/null
    john --wordlist=temp-pass.txt --rules=rule17 --stdout >> temp-pass1.txt 2> /dev/null
    #john --wordlist=temp-pass.txt --rules=rule18 --stdout >> temp-pass1.txt 2> /dev/null

 cat $FILE temp-pass.txt temp-pass1.txt $comunes | sort | uniq > $OUTPUT 
 rm temp-pass.txt temp-pass1.txt   

   
