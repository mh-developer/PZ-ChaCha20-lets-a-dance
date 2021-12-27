import os
import struct
import time
import secrets
import PySimpleGUI as sg


def rotate(v, c):
    return ((v << c) & 0xffffffff) | v >> (32 - c)


def round_chacha(x, a, b, c, d):
    x[a] = (x[a] + x[b]) & 0xffffffff
    x[d] = rotate(x[d] ^ x[a], 16)
    x[c] = (x[c] + x[d]) & 0xffffffff
    x[b] = rotate(x[b] ^ x[c], 12)
    x[a] = (x[a] + x[b]) & 0xffffffff
    x[d] = rotate(x[d] ^ x[a], 8)
    x[c] = (x[c] + x[d]) & 0xffffffff
    x[b] = rotate(x[b] ^ x[c], 7)


def chacha20_xor_stream(key, iv, counter=0):
    if not isinstance(counter, int):
        raise TypeError
    if counter & ~0xffffffff:
        raise ValueError('Counter is not uint32.')
    if not isinstance(key, bytes):
        raise TypeError
    if not isinstance(iv, bytes):
        raise TypeError
    if len(key) != 32:
        raise ValueError

    ctx = [0] * 16
    ctx[:4] = (
        1634760805,  # 0x61707865
        857760878,  # 0x3320646e
        2036477234,  # 0x79622d32
        1797285236  # 0x6b206574
    )  # expand 32-byte k
    ctx[4: 12] = struct.unpack('<8L', key)
    ctx[12] = counter
    ctx[13: 16] = struct.unpack('<LLL', iv)
    while True:
        x = list(ctx)
        for i in range(10):
            round_chacha(x, 0, 4, 8, 12)
            round_chacha(x, 1, 5, 9, 13)
            round_chacha(x, 2, 6, 10, 14)
            round_chacha(x, 3, 7, 11, 15)

            round_chacha(x, 0, 5, 10, 15)
            round_chacha(x, 1, 6, 11, 12)
            round_chacha(x, 2, 7, 8, 13)
            round_chacha(x, 3, 4, 9, 14)
        for c in struct.pack('<16L', *((x[i] + ctx[i]) & 0xffffffff for i in range(16))):
            yield c
        ctx[12] = (ctx[12] + 1) & 0xffffffff


def chacha20_encrypt(data, key, iv=None, counter=1):
    if not isinstance(data, bytes):
        raise TypeError
    if iv is None:
        iv = secrets.token_bytes(12)
    if isinstance(key, bytes):
        if not key:
            raise ValueError('Key is empty.')
        if len(key) < 32:
            key = (key * (32 // len(key) + 1))[:32]
        if len(key) > 32:
            raise ValueError('Key too long.')

    return bytes(a ^ b for a, b in zip(data, chacha20_xor_stream(key, iv, counter)))


def start_gui():
    layout = [
        [sg.Text('Datoteka'), sg.InputText(), sg.FileBrowse('Išči')],
        [sg.Text('Ključ'), sg.InputText()],
        [sg.Output(size=(88, 20))],
        [sg.Submit(button_text='Šifriraj'), sg.Cancel(button_text='Zapri')]
    ]
    window = sg.Window('ChaCha20 šifra', layout)

    while True:
        event, values = window.read()
        if event in (None, 'Exit', 'Cancel', 'Zapri'):
            break
        if event == 'Submit' or event == 'Šifriraj':
            filepath = key = is_validation_ok = None
            if values[0]:
                filepath = values[0]
                key = secrets.token_bytes(32)  # values[1]
                # key = bytes(key, 'UTF-8')
                is_validation_ok = True
                if not filepath and filepath is not None:
                    print('Napaka: pot do datoteke ni pravilna.')
                    is_validation_ok = False
                # elif not key and key is not None:
                #     print('Napaka: Ključ ni v pravilni obliki.')
                #     is_validation_ok = False
                elif is_validation_ok:
                    try:
                        start_time = time.process_time()
                        with open(filepath, 'rb') as data, \
                                open(filepath[:-4] + '-result' + filepath[-4:], 'wb') as encrypted_result, \
                                open(filepath[:-4] + '-result2' + filepath[-4:], 'wb') as decrypted_result:

                            raw_data = data.read()
                            print(f"--- Open and read FILE Time --- {time.process_time() - start_time}")

                            start_time = time.process_time()
                            encrypted_file = chacha20_encrypt(raw_data, key)
                            print(f"--- encrypted_file Time --- {time.process_time() - start_time}")
                            print(
                                f"--- encrypted_file cycles per second --- {len(raw_data) / (time.process_time() - start_time)} B/s")
                            encrypted_result.write(encrypted_file)

                            start_time = time.process_time()
                            decrypted_file = chacha20_encrypt(encrypted_file, key)
                            print(f"--- decrypted_file Time --- {time.process_time() - start_time}")
                            print(
                                f"--- decrypted_file  cycles per second --- {len(raw_data) / (time.process_time() - start_time)} B/s")
                            decrypted_result.write(decrypted_file)

                            print('Pot datoteke:', filepath)
                            print('Ključ: ', key)
                            print("DATA: ", len(raw_data))
                            print("Originalna velikost datoteke: ", os.path.getsize(filepath))
                            print("------------------------------------------------")
                            print("Velikost datotek: ", len(raw_data), len(decrypted_file))
                            print("Je vsebina datotek enaka? ", raw_data == decrypted_file)
                    except:
                        print('*** Napaka v procesu šifriranja/dešifriranja ***')
            else:
                print('Napaka pri vnosnih poljih')
    window.close()


if __name__ == '__main__':
    start_gui()
