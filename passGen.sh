#!/bin/bash

while getopts ":t:f:e:o:v:" OPTIONS
do
            case $OPTIONS in            
            f)     FILE=$OPTARG;;
            t)     TYPE=$OPTARG;;
            e)     ENTITY=$OPTARG;;
            o)     OUTPUT=$OPTARG;;               
            v)     VERBOSE=$OPTARG;;
            ?)     printf "Opcion invalida: -$OPTARG\n" $0
                          exit 2;;
           esac
done                                                                                                      


TYPE=${TYPE:=NULL}
FILE=${FILE:=NULL}
ENTITY=${ENTITY:=NULL}
OUTPUT=${OUTPUT:=NULL}
VERBOSE=${VERBOSE:=NULL}


function print_ascii_art {
cat << "EOF"
                                                                                       
88888888ba                                       ,ad8888ba,                            
88      "8b                                     d8"'    `"8b                           
88      ,8P                                    d8'                                     
88aaaaaa8P'  ,adPPYYba,  ,adPPYba,  ,adPPYba,  88              ,adPPYba,  8b,dPPYba,   
88""""""'    ""     `Y8  I8[    ""  I8[    ""  88      88888  a8P_____88  88P'   `"8a  
88           ,adPPPPP88   `"Y8ba,    `"Y8ba,   Y8,        88  8PP"""""""  88       88  
88           88,    ,88  aa    ]8I  aa    ]8I   Y8a.    .a88  "8b,   ,aa  88       88  
88           `"8bbdP"Y8  `"YbbdP"'  `"YbbdP"'    `"Y88888P"    `"Ybbd8"'  88       88  
                                                                                                                                                                            
https://github.com/DanielTorres1 - daniel{dot}torres{at}owasp.org
EOF
}


function uso {
cat << "EOF"
                                                                                       
USO: 

-f: Lista de palabras clave
-t: tipo. Puede ser:
		online : Aplica solo los patrones mas comunes
		offline: Aplica todos los patrones 				
-o: Archivo donde escribira la lista final
-e: Empresa o sigla para generar
-v: si ponemos 1 mostrara que patrones se esta aplicando

ejemplo :  passGen.sh -f lista.txt -t online -o online.txt -l es -v 1

ejemplo :  passGen.sh -f lista.txt -t top500 -o top.txt -l en -v 1
EOF
}




if [ $VERBOSE == "1" ]
then
   print_ascii_art
fi



if [ $FILE = NULL ] ; then

print_ascii_art
uso
exit
fi
######################
FILE=`pwd`/$FILE
#echo $FILE

 
  if [ $TYPE == "online" ]
  then  
  john --wordlist=$FILE --rules=rule14 --stdout >> temp-pass.txt 2> /dev/null	
  john --wordlist=$FILE --rules=rule22 --stdout >> temp-pass.txt 2> /dev/null		
  john --wordlist=$FILE --rules=rule23 --stdout >> temp-pass.txt 2> /dev/null		
  john --wordlist=$FILE --rules=rule24 --stdout >> temp-pass.txt 2> /dev/null		

  john --wordlist=temp-pass.txt --rules=rule16 --stdout >> temp-pass1.txt 2> /dev/null
  
  cat $FILE temp-pass.txt temp-pass1.txt | sort | uniq > $OUTPUT 
  rm temp-pass.txt temp-pass1.txt
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
	  john --wordlist=$FILE --rules=rule20 --stdout >> temp-pass.txt 2> /dev/null 	  
	  john --wordlist=$FILE --rules=rule21 --stdout >> temp-pass.txt 2> /dev/null 	  
	  john --wordlist=$FILE --rules=rule22 --stdout >> temp-pass.txt 2> /dev/null		
	  john --wordlist=$FILE --rules=rule23 --stdout >> temp-pass.txt 2> /dev/null		
	  john --wordlist=$FILE --rules=rule24 --stdout >> temp-pass.txt 2> /dev/null		
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
	  john --wordlist=$FILE --rules=rule23 --stdout >> temp-pass.txt 2> /dev/null		
	  john --wordlist=$FILE --rules=rule24 --stdout >> temp-pass.txt 2> /dev/null		
   fi
 



    if [ $VERBOSE == "1" ]
    then	  
	  	 echo -e "\n  REGLA 18: Mutar s/$ , a/@ , l/1, e/3, g/9, i=1, o=0"
	  	 echo -e "\n REGLA 16: Volver Mayuscula la primera letra"
		 echo -e "\n REGLA 17: Volver Mayuscula todo"	  
    fi
 
    
    john --wordlist=$FILE --rules=rule18 --stdout >> temp-pass.txt 2> /dev/null
    john --wordlist=$FILE --rules=rule19 --stdout >> temp-pass.txt 2> /dev/null
    
    john --wordlist=temp-pass.txt --rules=rule16 --stdout >> temp-pass1.txt 2> /dev/null
    john --wordlist=temp-pass.txt --rules=rule17 --stdout >> temp-pass1.txt 2> /dev/null

 cat $FILE temp-pass.txt temp-pass1.txt | sort | uniq > $OUTPUT 
 rm temp-pass.txt temp-pass1.txt   
   
