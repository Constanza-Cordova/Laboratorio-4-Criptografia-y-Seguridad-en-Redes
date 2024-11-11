import os
from Crypto.Cipher import DES, AES, DES3
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# Solicitar datos al usuario
key = input("Ingrese la clave (key): ")
iv = input("Ingrese el vector de inicialización (IV): ")
texto = input("Ingrese el texto a cifrar: ")

# Convertir IV a bytes
try:
    iv_bytes = bytes.fromhex(iv)
except ValueError:
    print("El IV debe estar en formato hexadecimal.")
    exit(1)

# Asegurar que el IV tenga la longitud correcta para cada algoritmo
def ajustar_iv(iv_bytes, tamaño_necesario):
    if len(iv_bytes) < tamaño_necesario:
        iv_bytes += get_random_bytes(tamaño_necesario - len(iv_bytes))
    elif len(iv_bytes) > tamaño_necesario:
        iv_bytes = iv_bytes[:tamaño_necesario]
    return iv_bytes

iv_des = ajustar_iv(iv_bytes, 8)
iv_aes = ajustar_iv(iv_bytes, 16)
iv_3des = ajustar_iv(iv_bytes, 8)

def ajustar_clave(key, tamaño_necesario):
    key_bytes = key.encode('utf-8')
    if len(key_bytes) < tamaño_necesario:
        key_bytes += get_random_bytes(tamaño_necesario - len(key_bytes))
    elif len(key_bytes) > tamaño_necesario:
        key_bytes = key_bytes[:tamaño_necesario]
    return key_bytes

# Ajustar claves
key_des = ajustar_clave(key, 8)
key_aes = ajustar_clave(key, 32)
key_3des = ajustar_clave(key, 24)

print(f"Clave DES ajustada: {key_des.hex()}")
print(f"Clave AES ajustada: {key_aes.hex()}")
print(f"Clave 3DES ajustada: {key_3des.hex()}")
print(f"IV ajustado para DES: {iv_des.hex()}")
print(f"IV ajustado para AES: {iv_aes.hex()}")
print(f"IV ajustado para 3DES: {iv_3des.hex()}")

def cifrar_descifrar_des(texto, key, iv):
    cipher = DES.new(key, DES.MODE_CBC, iv)
    texto_cifrado = cipher.encrypt(pad(texto.encode('utf-8'), DES.block_size))
    cipher = DES.new(key, DES.MODE_CBC, iv)
    texto_descifrado = unpad(cipher.decrypt(texto_cifrado), DES.block_size)
    return texto_cifrado, texto_descifrado.decode('utf-8')

def cifrar_descifrar_aes(texto, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    texto_cifrado = cipher.encrypt(pad(texto.encode('utf-8'), AES.block_size))
    cipher = AES.new(key, AES.MODE_CBC, iv)
    texto_descifrado = unpad(cipher.decrypt(texto_cifrado), AES.block_size)
    return texto_cifrado, texto_descifrado.decode('utf-8')

def cifrar_descifrar_3des(texto, key, iv):
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    texto_cifrado = cipher.encrypt(pad(texto.encode('utf-8'), DES3.block_size))
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    texto_descifrado = unpad(cipher.decrypt(texto_cifrado), DES3.block_size)
    return texto_cifrado, texto_descifrado.decode('utf-8')

# Ejecutar cifrado y descifrado
texto_cifrado_des, texto_descifrado_des = cifrar_descifrar_des(texto, key_des, iv_des)
texto_cifrado_aes, texto_descifrado_aes = cifrar_descifrar_aes(texto, key_aes, iv_aes)
texto_cifrado_3des, texto_descifrado_3des = cifrar_descifrar_3des(texto, key_3des, iv_3des)

# Imprimir resultados
print(f"Texto cifrado DES: {texto_cifrado_des.hex()}")
print(f"Texto descifrado DES: {texto_descifrado_des}")
print(f"Texto cifrado AES: {texto_cifrado_aes.hex()}")
print(f"Texto descifrado AES: {texto_descifrado_aes}")
print(f"Texto cifrado 3DES: {texto_cifrado_3des.hex()}")
print(f"Texto descifrado 3DES: {texto_descifrado_3des}")
