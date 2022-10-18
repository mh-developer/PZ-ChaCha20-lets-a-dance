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


def chacha20_encrypt(data, key, iv=None, counter=1):  # RFC 7539 defined value for counter to 1 and with this IV
    if not isinstance(data, bytes):
        raise TypeError
    if iv is None:
        iv = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'  # RFC 7539 defined value for counter to 1 and with this IV
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
        [sg.Text('Šifriranje'), sg.InputText(key='_encrypt_input_file_'), sg.FileBrowse('Odpri')],
        [sg.Text('Dešifriranje'), sg.InputText(key='_dencrypt_input_file_'), sg.FileBrowse('Odpri')],
        [sg.Text('Ključ'), sg.InputText(key='_key_input_'), sg.Button(button_text='Generiraj ključ')],
        [sg.Output(size=(88, 20))],
        [sg.Button(button_text='Šifriraj'), sg.Button(button_text='Dešifriraj'), sg.Cancel(button_text='Zapri')]
    ]
    window = sg.Window('ChaCha20 šifra', layout)

    while True:
        event, values = window.read()
        if event in (None, 'Exit', 'Cancel', 'Zapri'):
            break
        if event == 'Generiraj ključ':
            window['_key_input_'].Update(secrets.token_urlsafe(24))

        if event == 'Submit' or event == 'Šifriraj' or event == 'Dešifriraj':
            filepath = key = is_validation_ok = None
            if values['_encrypt_input_file_'] or values['_dencrypt_input_file_']:
                if event == 'Šifriraj':
                    filepath = values['_encrypt_input_file_']
                elif event == 'Dešifriraj':
                    filepath = values['_dencrypt_input_file_']

                is_validation_ok = True
                if not filepath and filepath is not None:
                    print('Napaka: pot do datoteke ni pravilna.')
                    is_validation_ok = False
                elif is_validation_ok:
                    try:
                        start_time = time.process_time()
                        with open(filepath, 'rb') as data:

                            raw_data = data.read()
                            print(f"--- Open and read FILE Time --- {time.process_time() - start_time}")

                            # A 96-bit nonce (IV - Initialization Vector) -- different for each invocation with the same key
                            # The protocol will specify a 96-bit or 64-bit nonce.  This MUST be
                            # unique per invocation with the same key, so it MUST NOT be
                            # randomly generated.  A counter is a good way to implement this,
                            # but other methods, such as a Linear Feedback Shift Register (LFSR)
                            # are also acceptable.  ChaCha20 as specified here requires a 96-bit
                            # nonce.  So if the provided nonce is only 64-bit, then the first 32
                            # bits of the nonce will be set to a constant number.  This will
                            # usually be zero, but for protocols with multiple senders it may be
                            # different for each sender, but should be the same for all
                            # invocations of the function with the same key by a particular
                            # sender.
                            iv = b'\x00\x00\x00\x09\x00\x00\x00\x4a\x00\x00\x00\x00'  # RFC 7539 defined value for counter to 1 and with this IV

                            if event == 'Šifriraj':
                                key = bytes(values['_key_input_'], 'utf-8')  # secrets.token_bytes(32)

                                with open(filepath[:-len(filepath.split("/")[-1])] + "secret_key.txt", 'wb') as secret_keys:
                                    secret_keys.write(key)

                                start_time = time.process_time()

                                encrypted_file = chacha20_encrypt(raw_data, key, iv)

                                print(f"--- encrypted_file Time --- {time.process_time() - start_time}")
                                print(f"--- encrypted_file cycles per second --- {(len(raw_data) / (time.process_time() - start_time)) * 10 ** -6} MB/s")

                                filepath = filepath[:-4] + '-result-encrypted' + filepath[-4:]
                                with open(filepath, 'wb') as encrypted_result:
                                    encrypted_result.write(encrypted_file)

                            if event == 'Dešifriraj':
                                with open(filepath[:-len(filepath.split("/")[-1])] + "secret_key.txt", 'rb') as secret_keys:
                                    key = secret_keys.read()

                                start_time = time.process_time()

                                decrypted_file = chacha20_encrypt(encrypted_file, key, iv)

                                print(f"--- decrypted_file Time --- {time.process_time() - start_time}")
                                print(f"--- decrypted_file  cycles per second --- {(len(raw_data) / (time.process_time() - start_time)) * 10 ** -6} MB/s")

                                filepath = filepath[:-4].split("-result-encrypted")[0] + '-result-decrypted' + filepath[-4:]
                                with open(filepath, 'wb') as decrypted_result:
                                    decrypted_result.write(decrypted_file)

                            print('Pot datoteke:', filepath)
                            print('Ključ: ', key)
                            print("Velikost datoteke: ", os.path.getsize(filepath))
                            print("------------------------------------------------\n")
                    except:
                        print('*** Napaka v procesu šifriranja/dešifriranja ***')
            else:
                print('Napaka pri vnosnih poljih')
    window.close()


if __name__ == '__main__':
    start_gui()
