import math

# Liczba znaków w alfabecie [a-z]
N = 26

# Entropia klucza AES-256 (256 bitów)
entropia_aes = 256

# Oblicz minimalną długość hasła
minimalna_dlugosc_hasla = entropia_aes / math.log2(N)

# Oblicz minimalną liczbę znaków [a-z]
minimalna_liczba_znakow = math.ceil(minimalna_dlugosc_hasla)

print(f"Minimalna liczba znaków [a-z] to: {minimalna_liczba_znakow}")
