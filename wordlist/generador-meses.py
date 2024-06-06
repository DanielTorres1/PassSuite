#!/usr/bin/python3
months = ['enero', 'feb', 'marzo', 'abril', 'mayo', 'junio', 'julio', 'agosto', 'sep', 'oct', 'nov', 'dic']
ciudades = ['Beni', 'Cobija', 'Cochabamba', 'lapaz', 'Oruro', 'Pando', 'Potosi', 'Santacruz', 'Sucre', 'Tarija','Bolivia']
years = range(2023, 2025)
for year in years:
    for month in months:
        month_year = f"{month}.{year}"
        print(month_year)
