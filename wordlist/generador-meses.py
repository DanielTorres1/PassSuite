#!/usr/bin/python3
months = ['Enero', 'Febrero', 'Marzo', 'Abril', 'Mayo', 'Junio', 'Julio', 'Agosto', 'Septiembre', 'Octubre', 'Noviembre', 'Diciembre']
ciudades = ['Beni', 'Cobija', 'Cochabamba', 'lapaz', 'Oruro', 'Pando', 'Potosi', 'Santacruz', 'Sucre', 'Tarija','Bolivia']
years = range(2021, 2025)
for year in years:
    for month in ciudades:
        month_year = f"{month}{year}"
        print(f"{month_year}*")
        print(month)
        print(f"adm{month.lower()}")
        print(f"{month}1")
        print(f"{month}123*")
        print(f"{month}123+")
        print(f"{month}20*")
        print(f"{month}{year}*")
        print(f"{month}.{year}")
        print(month_year)
        print(f"{month_year}%")
        print(f"{month_year}*")
        print(f"{month_year}+")
        print(f"{month_year}.")
