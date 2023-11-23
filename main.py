import os
import time
import ecdsa
import PyPDF2 as pdf
import hashlib
from difflib import SequenceMatcher

from reportlab.pdfgen.canvas import Canvas
from pdfrw import PdfReader
from pdfrw.toreportlab import makerl
from pdfrw.buildxobj import pagexobj
from datetime import datetime


# encrypt pdf
def encrypt(private_key, text):
    sk = ecdsa.SigningKey.from_string(bytes.fromhex(private_key), curve=ecdsa.NIST521p, hashfunc=hashlib.blake2b)
    enkrip = sk.sign(text.encode('utf-8'))

    return enkrip.hex()


# decrypt pdf
def decrypt(public_key, signature, text):
    try:
        vk = ecdsa.VerifyingKey.from_string(bytes.fromhex(public_key), curve=ecdsa.NIST521p, hashfunc=hashlib.blake2b)
        return vk.verify(bytes.fromhex(signature), text.encode('utf-8'), hashlib.blake2b)
    except:
        return False


# read private_key
def readFile():
    fileObj = open("signature.txt", "r")  # opens the file in read mode
    words = fileObj.read().splitlines()  # puts the file into an array
    fileObj.close()
    return words


# cek signpdf
def check(text):
    isSign = False

    for sig in readFile():
        if ' _ ' in sig:
            split = sig.split(' _ ')
            priv = split[2]
            sig = split[0]

            vk = ecdsa.SigningKey.from_string(bytes.fromhex(priv), curve=ecdsa.NIST521p, hashfunc=hashlib.blake2b).verifying_key
            vk.precompute()

            try:
                isSign = vk.verify(bytes.fromhex(sig), text.encode('utf-8'), hashlib.blake2b)
                break
            except ecdsa.BadSignatureError:
                isSign = False

    return isSign


# save sign pdf
def saveSign(input_text, signature):
    input_file  = "pdf/" + input_text + ".pdf"
    output_file = "pdf-sign/" + input_text + "_sign.pdf"
    output_temp = "pdf-temp/" + input_text + "_temp.pdf"

    # Get pages
    reader = PdfReader(input_file)
    pages = [pagexobj(p) for p in reader.pages]

    # Compose new pdf
    canvas_file = Canvas(output_file)
    canvas_temp = Canvas(output_temp)

    now = datetime.now()
    dt_string = now.strftime("%d/%m/%Y %H:%M:%S")

    chunks, chunk_size = len(signature), len(signature)//3
    out_chunks = [ signature[i:i+chunk_size] for i in range(0, chunks, chunk_size) ]

    for page_num, page in enumerate(pages, start=1):
        # Add page
        canvas_file.setPageSize((page.BBox[2], page.BBox[3]))
        canvas_file.doForm(makerl(canvas_file, page))

        canvas_temp.setPageSize((page.BBox[2], page.BBox[3]))
        canvas_temp.doForm(makerl(canvas_temp, page))

        # Draw footer
        footer_text = "Telah ditanda tangani " + dt_string
        x = 160
        canvas_file.saveState()
        canvas_file.setFont('Times-Roman', 8)
        canvas_file.drawString(page.BBox[2] - x, 25, footer_text)
        canvas_file.setFont('Times-Roman', 6)
        canvas_file.drawString(page.BBox[2] - (x + 100), 15, out_chunks[0])
        canvas_file.drawString(page.BBox[2] - (x + 100), 10, out_chunks[1])
        canvas_file.drawString(page.BBox[2] - (x + 100), 5, out_chunks[2])
        canvas_file.restoreState()
        canvas_temp.saveState()
        canvas_temp.setFont('Times-Roman', 8)
        canvas_temp.drawString(page.BBox[2] - x, 25, footer_text)
        canvas_file.setFont('Times-Roman', 6)
        canvas_temp.drawString(page.BBox[2] - (x + 100), 15, out_chunks[0])
        canvas_temp.drawString(page.BBox[2] - (x + 100), 10, out_chunks[1])
        canvas_temp.drawString(page.BBox[2] - (x + 100), 5, out_chunks[2])
        canvas_temp.restoreState()


        canvas_file.showPage()
        canvas_temp.showPage()

    canvas_file.save()
    canvas_temp.save()


def diff_file(fileName1, fileName2):
    h1 = hashlib.sha1()
    h2 = hashlib.sha1()
  
    with open(fileName1, "rb") as file:
        chunk = 0
        while chunk != b'':
            chunk = file.read(1024)
            h1.update(chunk)
              
    with open(fileName2, "rb") as file:
        chunk = 0
        while chunk != b'':
            chunk = file.read(1024)
            h2.update(chunk)
  
        return h1.hexdigest(), h2.hexdigest()

if __name__ == '__main__':
    print("--- ENKRIPSI DAN DEKRIPSI DOKUMEN PDF ---")
    print("1. Sign PDF")
    print("2. Verify PDF")

    inp = input("Masukkan Pilihan       : ")
    if inp == '1':
        input_pdf = input("Masukkan nama file PDF : ")
        input_stream = pdf.PdfFileReader(open("pdf/" + input_pdf + ".pdf", "rb"))
        text_stream = input_stream.getPage(0).extractText()

        sk = ecdsa.SigningKey.generate(curve=ecdsa.NIST521p, hashfunc=hashlib.blake2b)
        private_key = sk.to_string().hex()
        public_key = sk.verifying_key.to_string().hex()
        sign_time = time.time()
        signature = encrypt(private_key, text_stream)

        if check(text_stream):
            print("PDF sudah di tanda tangani")
        else:
            print("Private Key            :", private_key)
            print("Public  Key            :", public_key)
            print("Signature              :", signature)

            rl = readFile()
            rl.append(signature + " _ " + public_key + " _ " + private_key)
            with open('signature.txt', 'w') as f:
                for line in rl:
                    f.write(line)
                    f.write("\n")

            saveSign(input_pdf, signature)

            print("Waktu proses sign      : %s second" % (time.time() - sign_time))
    else:
        input_pdf = input("Masukkan nama file PDF : ")
        input_stream = pdf.PdfFileReader(open("pdf/" + input_pdf + ".pdf", "rb"))
        text_stream = input_stream.getPage(0).extractText()

        if check(text_stream):
            input_stream = pdf.PdfFileReader(open("pdf/" + input_pdf + ".pdf", "rb"))
            text_stream  = input_stream.getPage(0).extractText()
            input_sig = input("Masukkan Signature     : ")
            signature = input_sig
            input_pub = input("Masukkan Public Key    : ")

            verify_time = time.time()

            pdf1, pdf2 = diff_file("pdf-sign/" + input_pdf + "_sign.pdf", "pdf-temp/" + input_pdf + "_temp.pdf")
            if pdf1 != pdf2:
                print("Signature              : False")
            else:
                print("Signature              :", decrypt(input_pub, signature, text_stream))
            print("Waktu proses verify    : %s second" % (time.time() - verify_time))
        else:
            print("PDF belum di tanda tangani")

