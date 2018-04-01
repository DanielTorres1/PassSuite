
# PassSuite

 1. passGen.sh : Genera passwords con patrones comunes a partir de una
    lista. Estas  reglas se basan en estadísticas de como los usuarios 
    crean passwords  cuando se les pide que usen una mayúscula, números
    y signos especiales. El script usa john the ripper para generar los
    passwords 

    Patrones comunes usados para generar passwords

- Password + 2 dígitos
- Password + 3 dígitos
- Password + 4 dígitos
- Password + 5 dígitos
- Password + 2 dígitos + 1 carácter especial
- Password + 3 dígitos + 1 carácter especial
- Password + 4 dígitos + 1 carácter especial
- Password + 1 carácter especial + 2 digitos
- Password + 1 carácter especial + 3 digitos
- Adicionar prefijos y sufijos comunes (123,111,etc)
- Mutar s/$ , a/@ , l/1, e/3, g/9, i=1, o=0
- Volver Mayuscula la primera letra
    
 2. cracker.sh: Realiza un ataque de diccionario (top 20
    passwords mas usados+ diccionario personalizado) a los siguientes
    protcolos/servicios Windows, ZKSoftware, MS-SQL, Postgres, Mysql y
    VNC


## ¿COMO INSTALAR?

Testeado en Kali 2:

    git clone https://github.com/DanielTorres1/PassGen
    cd PassGen
    bash instalar.sh


## ¿COMO USAR?
**passGen.sh**

Opciones: 

-f: Lista de palabras clave
-t: tipo. Puede ser:
		online : Aplica solo los patrones mas comunes
		offline: Aplica todos los patrones para ataques offline
-o: Archivo donde esribira la lista final
-v: si ponemos 1 mostrara que patrones se esta aplicando

ejemplo :  passGen.sh -f lista.txt -t online -o online.txt -v 1


**cracker.sh**

Ejecutar el script en el directorio creado por lanscanner (https://github.com/DanielTorres1/lanscanner). 

Opciones: 
-e : Nombre de la empresa (Usado para generar diccionario de passwords)
 
-d :Diccionario de passwords a usar (opcional)

Ejemplo 1: Ataque de diccionario con passwords personallizados (basados en la palabra "microsoft") + 20 passwords mas usados
	cracker.sh -e microsoft

Ejemplo 2: Ataque de diccionario con lista de passwords
	cracker.sh -d passwords.txt

