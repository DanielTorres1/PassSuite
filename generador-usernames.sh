for apellido in $(cat apellidos.txt); do
    for nombre in $(cat nombres.txt); do
        echo "$nombre.$apellido"
    done
done
