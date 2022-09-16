from BitVector import *
import time

debug = 0

SboxMat = [[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[]]
InvSboxMat = [[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[]]

for i in range(16):
    for j in range(16):
        SboxMat[j].append(i*16+j);
        InvSboxMat[j].append(i * 16 + j);

# for i in range(16):
#     p =""
#     for j in range(16):
#         p+= " " + str(InvSboxMat[i][j])
#     print(p)

AES_modulus = BitVector(bitstring='100011011')
for i in range(16):
    for j in range(16):
        if SboxMat[i][j] != 0:
            a = BitVector(intVal=SboxMat[i][j], size=8)
            b = a.gf_MI(AES_modulus, 8)
            c = BitVector(hexstring="63")^b^(b<<1)^(b<<1)^(b<<1)^(b<<1)
            SboxMat[i][j] = c.int_val()         #hex(c.int_val())[2:].upper()

        else:
            SboxMat[i][j] = 99  #hex-63

#inv
for i in range(16):
    for j in range(16):
        k =  hex(InvSboxMat[i][j])[2:].upper()
        if len(k)==1:
            k = '0'+k
        b = BitVector(hexstring = k)
        c = BitVector(hexstring="05") ^ (b << 1) ^ (b << 2) ^ (b << 3)
        if c.int_val() == 0:
            InvSboxMat[i][j] = 0
        else:
            bm = c.gf_MI(AES_modulus, 8)
            InvSboxMat[i][j] = bm.int_val()


Sbox = []
InvSbox = []
for i in range(16):
    for j in range(16):
        Sbox.append(SboxMat[j][i])
        InvSbox.append(InvSboxMat[j][i])

# print("Sbox : ")
# str_sbox=""
# for i in range(16*16):
#     str_sbox+= hex(Sbox[i]) + "  "
#     if (i+1)%16==0:
#         print(str_sbox)
#         str_sbox=""
#
# print("InvSbox : ")
# str_sbox=""
# for i in range(16*16):
#     str_sbox+= hex(InvSbox[i]) + "  "
#     if (i+1)%16==0:
#         print(str_sbox)
#         str_sbox=""
#
# Sbox = (
#     0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
#     0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
#     0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
#     0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
#     0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
#     0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
#     0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
#     0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
#     0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
#     0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
#     0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
#     0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
#     0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
#     0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
#     0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
#     0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
# )

# InvSbox = (
#     0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
#     0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
#     0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
#     0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
#     0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
#     0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
#     0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
#     0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
#     0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
#     0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
#     0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
#     0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
#     0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
#     0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
#     0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
#     0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
# )

Mixer = [
    [BitVector(hexstring="02"), BitVector(hexstring="03"), BitVector(hexstring="01"), BitVector(hexstring="01")],
    [BitVector(hexstring="01"), BitVector(hexstring="02"), BitVector(hexstring="03"), BitVector(hexstring="01")],
    [BitVector(hexstring="01"), BitVector(hexstring="01"), BitVector(hexstring="02"), BitVector(hexstring="03")],
    [BitVector(hexstring="03"), BitVector(hexstring="01"), BitVector(hexstring="01"), BitVector(hexstring="02")]
]

InvMixer = [
    [BitVector(hexstring="0E"), BitVector(hexstring="0B"), BitVector(hexstring="0D"), BitVector(hexstring="09")],
    [BitVector(hexstring="09"), BitVector(hexstring="0E"), BitVector(hexstring="0B"), BitVector(hexstring="0D")],
    [BitVector(hexstring="0D"), BitVector(hexstring="09"), BitVector(hexstring="0E"), BitVector(hexstring="0B")],
    [BitVector(hexstring="0B"), BitVector(hexstring="0D"), BitVector(hexstring="09"), BitVector(hexstring="0E")]
]
#key = 'Thats my Kung Fu'
#plainText = 'Two One Nine Two three four five six seven Eight Nine Ten'
key = input("Enter Key : ")
keySchedulingTime = 0

if len(key)< 16:
    for i in range(16-len(key)):
        key+='0'
if len(key)>16:
    key = key[0:16]


def int_to_hex_list(arr):
    arr_hex = []
    for j in range(len(arr)):
        arr_hex.append(hex(arr[j]))
    print(arr_hex)

def int_to_hex_matrix(arr):
    for i in range(len(arr)):
        int_to_hex_list(arr[i])

def generate_key(key):
    start = time.time()
    key_list = [[]]
    rci = 1
    for i in range(len(key)):
        key_list[0].append(ord(key[i]))
    int_to_hex_list(key_list[0])

    for i in range(10):
        g = key_list[i][13:16]
        g.append(key_list[i][12])
        for j in range(4):
            g[j] = Sbox[g[j]]
            s = BitVector(intVal=g[j], size=8)

        if i>0 :
            AES_modulus = BitVector(bitstring='100011011')
            bv1 = BitVector(hexstring="02")
            h = hex(rci);
            h = h[2:len(h)]
            bv2 = BitVector(hexstring=h)
            bv3 = bv1.gf_multiply_modular(bv2, AES_modulus, 8)
            rci = bv3.int_val();

        g[0] = g[0]^rci ;
        new_key = []
        for j in range(4):
            new_key.append(key_list[i][j]^g[j])
        #print(new_key)
        #int_to_hex_list(new_key)
        for j in range(12):
            new_key.append(key_list[i][j+4]^new_key[j])
        #int_to_hex_list(new_key)
        key_list.append(new_key)

    #for i in range(11):
        #int_to_hex_list(key_list[i])
    end = time.time()
    global keySchedulingTime
    keySchedulingTime = end - start
    return key_list

key_list = generate_key(key)

def encryction(plainText):
    text_list = []
    if type(plainText[0])==str:
        for i in range(len(plainText)):
            text_list.append(ord(plainText[i]))
    elif type(plainText[0])==int:
        for i in range(len(plainText)):
            text_list.append(plainText[i])
        if len(plainText)< 16:
            for i in range(16-len(plainText)):
                text_list.append(ord(' '))
    #print("text list : ")
    #int_to_hex_list(text_list)

    for i in range(len(key)):
        text_list[i] = text_list[i]^key_list[0][i];

    if debug == 1:
        print("round 0 , after adding round key :")
        int_to_hex_list(text_list);

    for i in range(10):
        for j in range(len(text_list)):
            text_list[j] = Sbox[text_list[j]]  #substitution bytes

        if debug==1:
            print("substitution bytes")
            #int_to_hex_list(text_list)
        text_matrix = [[],[],[],[]]
        for j in range(4):
            for k in range(4):
                text_matrix[j].append(text_list[j+k*4])  #matrix formation

        if debug==1:
            int_to_hex_matrix(text_matrix)
        #shift row
        for j in range(3):                               #shift row
            for k in range(j+1):
                text_matrix[j+1].append(text_matrix[j+1][0])
                text_matrix[j+1].pop(0)

        if debug == 1:
            print("shift row")
            int_to_hex_matrix(text_matrix)
        #mix column
        result_matrix = [[], [], [], []]
        for j in range(4):
            for k in range(4):
                result_matrix[j].append(0)
        if i!=9:
            fixed_matrix = [[2,3,1,1],[1,2,3,1],[1,1,2,3],[3,1,1,2]]

            for j in range(4):
                for k in range(4):
                    for l in range(4):
                        AES_modulus = BitVector(bitstring='100011011')
                        h = hex(fixed_matrix[j][l]);
                        h = h[2:len(h)]
                        bv1 = BitVector(hexstring=h)
                        h = hex(text_matrix[l][k]);
                        h = h[2:len(h)]
                        bv2 = BitVector(hexstring=h)
                        bv3 = bv1.gf_multiply_modular(bv2, AES_modulus, 8)
                        mul = bv3.int_val();

                        result_matrix[j][k] = result_matrix[j][k]^ mul
        else:
            for j in range(4):
                for k in range(4):
                    result_matrix[j][k] = text_matrix[j][k]

            #int_to_hex_matrix(text_matrix)
            if debug == 1:
                print("mix column")
                int_to_hex_matrix(result_matrix)

        #making list again
        for j in range(4):
            for k in range(4):
                text_list[j + k * 4] = result_matrix[j][k]

        #int_to_hex_list(text_list)
        for j in range(len(key)):               #add round key
            text_list[j] = text_list[j] ^ key_list[i+1][j];

        if debug == 1:
            print("after adding round key : ",i+1)
            int_to_hex_list(text_list)

    print("Result after encryption : ")
    int_to_hex_list(text_list)
    return text_list


def decryption(text_list):
    #print("decryption : ")
    for i in range(len(key)):
        text_list[i] = text_list[i]^key_list[10][i];

    if debug==1:
        print("after adding round key 10")
        #int_to_hex_list(text_list)

    text_matrix = [[], [], [], []]
    for j in range(4):
        for k in range(4):
            text_matrix[j].append(text_list[j + k * 4])  # matrix formation

    if debug == 1:
        int_to_hex_matrix(text_matrix)
    for i in range(10):
        #inverse shift row
        for j in range(3):  # shift row
            for k in range(j + 1):
                text_matrix[j + 1].insert(0,text_matrix[j + 1][-1])
                text_matrix[j + 1].pop()

        if debug == 1:
            print("inverse shift row : ")
            int_to_hex_matrix(text_matrix)

        #inverse sub bytes
        for j in range(4):
            for k in range(4):
                text_matrix[j][k] = InvSbox[text_matrix[j][k]]  #inv substitution bytes

        if debug == 1:
            print("inverse sub bytes : ")
            int_to_hex_matrix(text_matrix)

        # adding round key
        for j in range(4):
            for k in range(4):
                text_matrix[k][j] = text_matrix[k][j] ^ key_list[9-i][k+j*4];

        if debug == 1:
            print("adding round key : ")
            int_to_hex_matrix(text_matrix)
        #Inverse mix column
        # mix column
        result_matrix = [[], [], [], []]
        for j in range(4):
            for k in range(4):
                result_matrix[j].append(0)
        if i != 9:
            fixed_matrix = [[], [], [], []]
            for j in range(4):
                for k in range(4):
                    fixed_matrix[j].append(InvMixer[j][k].intValue())

            # print("invse mixer : ")
            # int_to_hex_matrix(fixed_matrix)
            for j in range(4):
                for k in range(4):
                    for l in range(4):
                        AES_modulus = BitVector(bitstring='100011011')
                        h = hex(fixed_matrix[j][l]);
                        h = h[2:len(h)]
                        bv1 = BitVector(hexstring=h)
                        h = hex(text_matrix[l][k]);
                        h = h[2:len(h)]
                        bv2 = BitVector(hexstring=h)
                        bv3 = bv1.gf_multiply_modular(bv2, AES_modulus, 8)
                        mul = bv3.int_val();

                        result_matrix[j][k] = result_matrix[j][k] ^ mul

            if debug == 1:
                print("Inverse mix column : ")
                int_to_hex_matrix(result_matrix)
                print(">>>>>")
        else:
            for j in range(4):
                for k in range(4):
                    result_matrix[j][k] = text_matrix[j][k]
        for j in range(4):
            for k in range(4):
                text_matrix[j][k] = result_matrix[j][k]

    if debug==1:
        print("Result : ")
        int_to_hex_matrix(result_matrix)
    result = ""
    for i in range(4):
        for j in range(4):
            result+= chr(result_matrix[j][i])


    print("Result after decryption : ")
    print(result)
    return result
#decryption end


def line_encrypt_decrypt():
    plainText = input("Plain Text: ")
    encryctionTime = 0;
    decryptionTime = 0;


    strr = ""
    for i in range(len(plainText)):
        strr += hex(ord(plainText[i])) + " "
    print(strr+"\n")
    steps = 0
    if len(plainText)%16 != 0:
        steps = 1
        for i in range(16*(int(len(plainText)/16) + 1) - len(plainText)):
            plainText += ' '

    result = ""
    for i in range(int(len(plainText)/16)):
        start = time.time()
        ciphertext = encryction(plainText[(i*16):(16+i*16)])
        end = time.time()
        encryctionTime += end-start

        strr = ""
        for j in range(len(ciphertext)):
            strr += chr(ciphertext[j]) + " "
        print(strr+"\n")

        start = time.time()
        decipheredText = decryption(ciphertext)
        end = time.time()
        decryptionTime += end-start

        strr = ""
        for j in range(len(decipheredText)):
            strr += hex(ord(decipheredText[j])) + " "
        print(strr+"\n\n")
        result += decipheredText

    print("Final Result : ",result)
    print("Key Scheduling: ",keySchedulingTime)
    print("Encryption Time: ",encryctionTime)
    print("Decryption Time: ",decryptionTime)


def file_encrypt_decrypt():
    filename = input("Give the file name : ")
    output_file_name = 'output.'+filename.split(".")[-1]
    f = open(output_file_name, 'w+b')
    byte_arr = []
    with open(filename, 'rb') as file:
        while 1:
            byte_s = file.read(16)
            if not byte_s:
                break
            ciphertext = encryction(byte_s)
            result = decryption(ciphertext)
            for i in range(len(result)):
                byte_arr.append(ord(result[i]))

    file.close();
    print(byte_arr)
    binary_format = bytearray(byte_arr)
    f.write(binary_format)
    f.close();

#file_encrypt_decrypt()
line_encrypt_decrypt()

