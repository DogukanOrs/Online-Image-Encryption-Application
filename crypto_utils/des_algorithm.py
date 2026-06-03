# converting text to a bit format 
def text_to_bit(text) : 
    bits = [] 
    for word in text: 
        # 08b for 8 bit to byte formtting 
        binary = format(ord(word), '08b')

        for bit in binary: 
            bits.append(int(bit))
    return bits 

# returning back to the text 
def bit_to_text(bits): 
    text = ""
    for i in range(0, len(bits),8): 
        byte_list = bits[i:i+8]
        byte_str ="".join(str(b) for b in byte_list)

        if len(byte_str) == 8 : 
            text = text + chr(int(byte_str,2))

    return text

def hex_to_bit(hex): 
    if len(hex) == 0 or len(hex) != 16 : 
        hex = '1AAA2BBB3FFF4DDD'

    bits = []
    for char in hex: 
        binary = format(int(char, 16),'04b')
        for bit in binary: 
            bits.append(int(bit))
    return bits 



# general permutation function ( we can use for every table ıp exp pc-12)
def permute(bits,table):
    result = []
    for position in table: 
        # because of the indexing issues on tables and python we extract 1 in positions
        result.append(bits[position-1])
    return result

IP = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9,  1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
]

IP_1 = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41,  9, 49, 17, 57, 25
]

PC1 = [
    57, 49, 41, 33, 25, 17,  9,
     1, 58, 50, 42, 34, 26, 18,
    10,  2, 59, 51, 43, 35, 27,
    19, 11,  3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
     7, 62, 54, 46, 38, 30, 22,
    14,  6, 61, 53, 45, 37, 29,
    21, 13,  5, 28, 20, 12,  4
]


PC2 = [
    14, 17, 11, 24,  1,  5,
     3, 28, 15,  6, 21, 10,
    23, 19, 12,  4, 26,  8,
    16,  7, 27, 20, 13,  2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
]

# per cycle left shift 
SHIFTING_AMOUNT = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

def shift_left(bit_list, step): 
    return bit_list[step:] + bit_list[:step] 

def gen_sub_keys(key_bits):
    key_56_bits = permute(key_bits,PC1)
    #left one c0
    c = key_56_bits[:28] 
    #right one d0
    d = key_56_bits[28:] 
    sub_keys = []

    for i in range(16): 
        c = shift_left(c, SHIFTING_AMOUNT[i])
        d = shift_left(d, SHIFTING_AMOUNT[i])

        cd = c + d 
        sub_keys_48_bit = permute(cd,PC2)

        sub_keys.append(sub_keys_48_bit)
    return sub_keys 




#fiestel 

#first 
E_BOX = [
    32,  1,  2,  3,  4,  5,
     4,  5,  6,  7,  8,  9,
     8,  9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32,  1
]
#second
def xor(bit_list_1,bit_list_2): 
    result = []
    for i in range(len(bit_list_1)): 
        result.append(bit_list_1[i] ^ bit_list_2[i])
    return result 

#third 
# 48 - 32 
S_BOXES = [
    #1
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
    ],
    #2
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
    ],
    #3
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
    ],
    #4
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
    ],
    #5
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
    ],
    #6
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
    ],
    #7
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
    ],
    #8
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
    ]
]

#forth 
#permutation after s-boxes 
P_BOX = [
    16,  7, 20, 21,
    29, 12, 28, 17,
     1, 15, 23, 26,
     5, 18, 31, 10,
     2,  8, 24, 14,
    32, 27,  3,  9,
    19, 13, 30,  6,
    22, 11,  4, 25
]

def s_box_interaction(bit_list_48): 
    result = [] 
    # 8 s-boxes
    for i in range(8): 
        group = bit_list_48[i*6 : (i+1)*6]
        row_bits = f"{group[0]}{group[5]}"
        rows = int(row_bits ,2 )
        column_bits = f"{group[1]}{group[2]}{group[3]}{group[4]}"
        columns = int(column_bits, 2) 

        s_box_values = S_BOXES[i][rows][columns]

        binary = format(s_box_values, '04b')
        for bit in binary: 
            result.append(int(bit))
    
    return result

def fiestel(d,sub_key): 
    expanded_d = permute(d,E_BOX)
    xor_result = xor(expanded_d, sub_key)
    s_result = s_box_interaction(xor_result)
    final_result = permute(s_result,P_BOX)

    return final_result


def encryption(msg_bits, key_bits): 
    sub_keys = gen_sub_keys(key_bits)
    msg_ip = permute(msg_bits,IP) 

    left = msg_ip[:32]
    right = msg_ip[32:]

    for i in range(16): 
        old_left = left 
        left = right 
        fiestel_result = fiestel(right,sub_keys[i])
        right = xor(old_left,fiestel_result)
    # swap of the halves first right 
    combined_lr = right + left 

    encrypted_bits = permute(combined_lr, IP_1)

    return encrypted_bits 



def decryption(encrypted_bits,key_bits):
    sub_keys = gen_sub_keys(key_bits)
    sub_keys.reverse()

    msg_ip = permute(encrypted_bits,IP) 

    left = msg_ip[:32]
    right = msg_ip[32:]

    for i in range(16): 
        old_left = left 
        left = right 
        fiestel_result = fiestel(right,sub_keys[i])
        right = xor(old_left,fiestel_result)
    # swap of the halves first right 
    combined_lr = right + left 

    decrypted_bits = permute(combined_lr,IP_1)
    return decrypted_bits

'''Wrap function for messages bigger than 64-bit problem (get the parts from ai. Because couldnt handle)'''
def encrypt_message(msg_text, key_bits):
    padding_len = 8 - (len(msg_text) % 8)
    if padding_len != 8:
        msg_text += " " * padding_len 
        
    all_encrypted_bits = []
    
    for i in range(0, len(msg_text), 8):
        block = msg_text[i : i+8]
        block_bits = text_to_bit(block) 
        
        encrypted_block = encryption(block_bits, key_bits)
        
        all_encrypted_bits.extend(encrypted_block)
        
    return all_encrypted_bits


def decrypt_message(encrypted_bits, key_bits):
    all_decrypted_bits = []
    
    for i in range(0, len(encrypted_bits), 64):
        block_bits = encrypted_bits[i : i+64]
        
        decrypted_block = decryption(block_bits, key_bits)
        
        all_decrypted_bits.extend(decrypted_block)
        
    decrypted_text = bit_to_text(all_decrypted_bits)

    return decrypted_text.rstrip()
"""-------------------------------------------------------------------------"""

# physical network connection requirements 
def bits_to_byte(bits) : 
    byte_list = []
    for i in range(0,len(bits),8): 
        eight_bits = bits[i:i+8] 
        #binary '2'
        byte_num = int("".join(str(x) for x in eight_bits), 2)
        byte_list.append(byte_num)
    return bytes(byte_list)

def byte_to_bits(byte_data): 
    bit_list = []
    for byte in byte_data: 
        binary = format(byte,'08b')
        for bit in binary: 
            bit_list.append(int(bit))
    return bit_list


#changed padding to pkcs5 uses standard padding instead of space padding.

def _pkcs5_pad(data):
    """Data multiple of 8 bytes."""
    pad_len = 8 - (len(data) % 8)
    return data + bytes([pad_len] * pad_len)

def _pkcs5_unpad(data):
    """Remove pkcs5 padding."""
    if len(data) == 0:
        raise ValueError("Cannot unpad empty data")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 8:
        raise ValueError(f"Invalid PKCS5 padding value: {pad_len}")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Corrupt PKCS5 padding")
    return data[:-pad_len]

def des_encrypt(plaintext_bytes, key):
    """Encrypt arbitrary-length bytes using DES in ECB mode with PKCS5 padding.
        bytes - the ciphertext
    """
    if len(key) != 8:
        raise ValueError(f"DES key must be exactly 8 bytes, got {len(key)}")
    
    key_bits = byte_to_bits(key)
    padded = _pkcs5_pad(plaintext_bytes)
    ciphertext = []
    
    for i in range(0, len(padded), 8):
        block = padded[i:i+8]
        block_bits = byte_to_bits(block)
        encrypted_bits = encryption(block_bits, key_bits)
        ciphertext.extend(bits_to_byte(encrypted_bits))
    
    return bytes(ciphertext)

def des_decrypt(ciphertext_bytes, key):
    """Decrypt data that was encrypted with des_encrypt.
        bytes - the original plaintext
    """
    if len(key) != 8:
        raise ValueError(f"DES key must be exactly 8 bytes, got {len(key)}")
    if len(ciphertext_bytes) == 0 or len(ciphertext_bytes) % 8 != 0:
        raise ValueError("Ciphertext length must be a positive multiple of 8 bytes")
    
    key_bits = byte_to_bits(key)
    plaintext = []
    
    for i in range(0, len(ciphertext_bytes), 8):
        block = ciphertext_bytes[i:i+8]
        block_bits = byte_to_bits(block)
        decrypted_bits = decryption(block_bits, key_bits)
        plaintext.extend(bits_to_byte(decrypted_bits))
    
    return _pkcs5_unpad(bytes(plaintext))
