import cv2
import io
import math
import os
import logging
import PySimpleGUIQt as sg
from PIL import Image
from encrypt_rsa2 import gen_keys, image_encryption, image_decryption
from aes import AES
import base64


def resize_image(image_path, resize=None):
    if isinstance(image_path, str):
        img = Image.open(image_path)
    else:
        try:
            img = Image.open(io.BytesIO(base64.b64decode(image_path)))
        except Exception as e:
            data_bytes_io = io.BytesIO(image_path)
            img = Image.open(data_bytes_io)

    cur_width, cur_height = img.size
    if resize:
        new_width, new_height = resize
        scale = min(new_height/cur_height, new_width/cur_width)
        img = img.resize((int(cur_width*scale), int(cur_height*scale)), Image.ANTIALIAS)
    bio = io.BytesIO()
    img.save(bio, format="PNG")
    del img
    return bio.getvalue()


class Handler(logging.StreamHandler):

    def __init__(self):
        logging.StreamHandler.__init__(self)

    def emit(self, record):
        global buffer
        record = f'{record.name}, [{record.levelname}], {record.message}'
        buffer = f'{buffer}\n{record}'.strip()
        window['log'].update(value=buffer)


ENCRYPTED_IMAGE = None
cyphertext = None
aes_key = None
p_prime = None
q_prime = None
iv= None
e = None
n_modulus = None
d_private = None
row = None
col = None
image_encrypted = False
input_data = False

file_types = [("JPEG (*.jpeg)", "*.jpeg"),
              ("All files (*.*)", "*.*")]
layout = [
    [
        sg.Text("Image File"),
        sg.Input(size=(25, 1), key="-FILE-"),
        sg.FileBrowse(file_types=file_types),
        sg.VSeperator(),
        sg.Button("Load Image"),
        sg.VSeperator(),
        sg.Button("RESET UI"),
    ],
    [
        sg.Button("RSA Encrypt"),
        sg.VSeperator(),
        sg.Button("RSA Decrypt"),
        sg.VSeperator(),
        sg.Button("AES Encrypt"),
        sg.VSeperator(),
        sg.Button("AES Decrypt"),
    ],
    [sg.Output(size=(70, 2), key='log')],
    [sg.Button("Generate AES Key"), sg.Input(size=(25, 1), key="-GENKEY-")],
    [sg.Button("Generate AES IV"), sg.Input(size=(25, 1), key="-GENIV-")],
[sg.Image(key="-IMAGE-"), sg.Image(key="-IMAGE_MODIFIED-")],
]

window = sg.Window("Image Encryption", layout)

logging.basicConfig(level=logging.INFO)
buffer = ''
ch = Handler()
ch.setLevel(logging.INFO)
logging.getLogger('').addHandler(ch)

while True:
    event, values = window.read(timeout=0)
    if event == "Exit" or event == sg.WIN_CLOSED:
        break
    if event == "Generate AES Key":
        aes_key = os.urandom(16)
        window["-GENKEY-"].update(str(aes_key))
    if event == "Generate AES IV":
        iv = os.urandom(16)
        window["-GENIV-"].update(str(iv))
    if event == "Load Image":
        filename = values["-FILE-"]
        if os.path.exists(filename):
            image = Image.open(values["-FILE-"])
            # image.thumbnail((400, 400))
            bio = io.BytesIO()
            # Actually store the image in memory in binary 
            image.save(bio, format="PNG")
            # Use that image data in order to 
            window["-IMAGE-"].update(data=resize_image(bio.getvalue(), resize=(400, 400)))
            logging.info('Loaded Image to Console')
    if event == "RSA Encrypt":
        filename = values["-FILE-"]
        if os.path.exists(filename):
            rgb_img = cv2.imread(filename)
            row, col = rgb_img.shape[0], rgb_img.shape[1]
            p_prime, q_prime, e, n_modulus, d_private = gen_keys(7)
            ENCRYPTED_IMAGE = image_encryption(rgb_img, e, n_modulus, row, col)
            image = Image.fromarray(ENCRYPTED_IMAGE)
            # image = Image.open(data)
            bio = io.BytesIO()
            # Actually store the image in memory in binary
            image.save(bio, format="JPEG")
            image_encrypted = True
            # Use that image data in order to
            window["-IMAGE_MODIFIED-"].update(data=resize_image(bio.getvalue(), resize=(400, 400)))
            logging.info('Encrypted RSA')
    if event == "RSA Decrypt":
        if image_encrypted:
            decrypted_img = image_decryption(ENCRYPTED_IMAGE, d_private, n_modulus, row, col)
            image = Image.fromarray(decrypted_img)
            bio = io.BytesIO()
            # Actually store the image in memory in binary
            image.save(bio, format="JPEG")
            ENCRYPTED_IMAGE = None
            # Use that image data in order to
            window["-IMAGE_MODIFIED-"].update(data=resize_image(bio.getvalue(), resize=(400, 400)))
            logging.info('Decrypted RSA')
    if event == "AES Encrypt":
        filename = values["-FILE-"]
        if os.path.exists(filename):
            aes_key = os.urandom(16) if not aes_key else aes_key
            iv = os.urandom(16) if not iv else iv
            # opening image
            input_file = open(filename, 'rb')
            input_data = input_file.read()
            input_file.close()

            # encrypting our image
            cyphertext = AES(aes_key).encrypt_ctr(input_data, iv)
            # preparing our image for showing
            num_bytes = len(cyphertext)
            num_pixels = int((num_bytes + 2) / 3)  # 3 bytes per pixel
            W = H = int(math.ceil(num_pixels ** 0.5))
            fill_bytes = '\0' * (W * H * 3 - len(cyphertext))
            imagedata = cyphertext + fill_bytes.encode('utf-8')
            # image from bytes
            image = Image.frombytes('RGB', (W, H), imagedata, 'raw')
            # image = Image.open(data)
            bio = io.BytesIO()
            # Actually store the image in memory in binary
            image.save(bio, format="PNG")
            image_encrypted = True
            # Use that image data in order to
            window["-IMAGE_MODIFIED-"].update(data=resize_image(bio.getvalue(), resize=(400, 300)))
            logging.info('Encrypted AES')
    if event == "AES Decrypt":
        if cyphertext:
            decrypted_img = AES(aes_key).decrypt_ctr(cyphertext, iv)
            image = Image.open(io.BytesIO(decrypted_img))
            bio = io.BytesIO()
            # Actually store the image in memory in binary
            image.save(bio, format="PNG")
            cyphertext = None
            # Use that image data in order to
            window["-IMAGE_MODIFIED-"].update(data=resize_image(bio.getvalue(), resize=(400, 400)))
            logging.info('Decrypted AES')
    if event == "RESET UI":
        logging.info('Clearing Console')
        window["-IMAGE-"].update('')
        window["-IMAGE_MODIFIED-"].update('')
        window["-GENKEY-"].update('')
        window["-GENIV-"].update('')
        ENCRYPTED_IMAGE = None
        cyphertext = None
        aes_key = None
        p_prime = None
        q_prime = None
        iv = None
        e = None
        n_modulus = None
        d_private = None
        row = None
        col = None
        image_encrypted = False
        input_data = False

window.close()
