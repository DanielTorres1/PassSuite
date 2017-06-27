# Generador de passwords.

Genera passwords con patrones comunes a partir de una lista. Estas reglas se basan en estadísticas de como los usuarios crean passwords cuando se les pide que usen una mayúscula, números y signos especiales. El script usa john the ripper para generar los passwords


Patrones comunes

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

## Instalar
```sh
git clone https://github.com/DanielTorres1/PassGen
cd PassGen
bash instalar.sh
```

## ¿Como usar?

Tiene los siguientes parametros:

```sh
-f: Lista de palabras clave
-t: tipo. Puede ser:
		online : Aplica solo los patrones mas comunes
		offline: Aplica todos los patrones 
-l: lenguaje. Puede ser:
		es: Adiciona los passwords mas comunes en Español
		en: Adiciona los passwords mas comunes en Ingles
-o: Archivo donde esribira la lista final
-v: si ponemos 1 mostrara que patrones se esta aplicando

ejemplo :  passGen.sh -f lista.txt -t online -o online.txt -v 1
```
