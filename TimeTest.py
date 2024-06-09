import time
import psutil
from AES import AES_Complex
from DES import DES_Complex
from Blowfish import Blowfish_Complex
from RSA import RSA_Complex
from ECC import ECC_Complex
from DSA import DSA_Complex
print("1.AES\n2.DES\n3.Blowfish\n4.RSA\n5.ECC\n6.DSA\n7.Run All")
num_met=int(input("Enter num: "))
num_met=num_met-1


# Ścieżka do pliku graficznego
file_path = 'photomode_09022024_021657.png'



# Wczytanie pliku graficznego jako bajty
with open(file_path, 'rb') as file:
    image_data = file.read()

file_path = 'test.txt'
with open(file_path,'rb')as file:
    text_data = file.read()

# Hasło do szyfrowania
password = "mojehaslo123"

# Funkcje szyfrowania
funcs = [AES_Complex, DES_Complex, Blowfish_Complex, RSA_Complex, ECC_Complex, DSA_Complex]

# Tryb debugowania
debug_mode = False

def get_resource_usage():
    cpu_percent = psutil.cpu_percent()
    memory_usage = psutil.virtual_memory().percent
    disk_usage = psutil.disk_usage('/').percent
    return cpu_percent, memory_usage, disk_usage

def TestOne(chosen_func, data, img_bool):
    initial_resource_usage = get_resource_usage()
    if img_bool:
        print("Image")
    else:
        print("Text")
    print("Initial resource usage:", initial_resource_usage)
    start = time.time()

    # Szyfrowanie danych graficznych
    encrypted_data, decrypted_data = funcs[chosen_func](data, password, debug_mode)
    final_resource_usage = get_resource_usage()
    end = time.time()
    

    print("Final resource usage:", final_resource_usage)
    
    resource_usage_diff = tuple(final - initial for final, initial in zip(final_resource_usage, initial_resource_usage))
    print("Resource usage difference:", resource_usage_diff)
    print("Execution time: ", end - start, """s\n\n""")

    # Zapisanie zaszyfrowanych danych do pliku
    if img_bool:
        output_file_path = f'image_encrypted_{chosen_func}.bin'
        with open(output_file_path, 'wb') as file:
            file.write(encrypted_data)
        # Zapisanie odszyfrowanych danych do pliku
        output_decrypted_path = f'image_decrypted_{chosen_func}.png'
        with open(output_decrypted_path, 'wb') as file:
            file.write(decrypted_data)
    else:
        output_file_path = f'text_encrypted_{chosen_func}.bin'
        with open(output_file_path, 'wb') as file:
            file.write(encrypted_data)
        # Zapisanie odszyfrowanych danych do pliku
        output_decrypted_path = f'text_decrypted_{chosen_func}.txt'
        with open(output_decrypted_path, 'wb') as file:
            file.write(decrypted_data)



def TestAll():
    for i in range(len(funcs)):
        TestOne(i,image_data, True)
        TestOne(i,text_data, False)

if num_met==6:
    TestAll()
else:
    TestOne(num_met,image_data,True)
    TestOne(num_met,text_data,False)