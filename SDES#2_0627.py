


FIXED_IP = [2, 6, 3, 1, 4, 8, 5, 7]
FIXED_EP = [4, 1, 2, 3, 2, 3, 4, 1]
FIXED_IP_INVERSE = [4, 1, 3, 5, 7, 2, 8, 6]
FIXED_P10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
FIXED_P8 = [6, 3, 7, 4, 8, 5, 10, 9]
FIXED_P4 = [2, 4, 3, 1]

S0 = [[1, 0, 3, 2],
      [3, 2, 1, 0],
      [0, 2, 1, 3],
      [3, 1, 3, 2]]

S1 = [[0, 1, 2, 3],
      [2, 0, 1, 3],
      [3, 0, 1, 0],
      [2, 1, 0, 3]]




def permutate(original, fixed_key):
    new = ''
    for i in fixed_key:
        new += original[i - 1]
    return new


def left_half(bits):
    return bits[:len(bits)//2]

def right_half(bits):
    return bits[len(bits)//2:]


def shift(bits):
    rotated_left_half = left_half(bits)[1:] + left_half(bits)[0]
    rotated_right_half = right_half(bits)[1:] + right_half(bits)[0]
    return rotated_left_half + rotated_right_half


def key1(KEY):
    return permutate(shift(permutate(KEY, FIXED_P10)), FIXED_P8)


def key2(KEY):
    return permutate(shift(shift(shift(permutate(KEY, FIXED_P10)))), FIXED_P8)


def xor(bits, key):
    new = ''
    for bit, key_bit in zip(bits, key):
        new += str(((int(bit) + int(key_bit)) % 2))
    return new


def lookup_in_sbox(bits, sbox):
    row = int(bits[0] + bits[3], 2)
    col = int(bits[1] + bits[2], 2)
    return '{0:02b}'.format(sbox[row][col])

def f_k(bits, key):
    L = left_half(bits)
    R = right_half(bits)
    bits = permutate(R, FIXED_EP)
    bits = xor(bits, key)
    bits = lookup_in_sbox(left_half(bits), S0) + lookup_in_sbox(right_half(bits), S1)
    bits = permutate(bits, FIXED_P4)
    return xor(bits, L)



def decrypt(cipher_text,key):
    bits = permutate(cipher_text, FIXED_IP)
    temp = f_k(bits, key2(key))
    bits = right_half(bits) + temp
    bits = f_k(bits, key1(key))
    return (permutate(bits + temp, FIXED_IP_INVERSE))





ciphertext = [0b11110001,0b11011111,0b10100100,0b10001010,0b10110000,0b10100100,0b10001010,0b11101111,0b1111111,0b11101111,0b111110,0b1111111,0b10001010,0b1,0b10100100,0b10100100,0b11110001,0b1111111,0b11011111,0b101010,0b11011111,0b11110001,0b10100100,0b1111111,0b10001010,0b10100100,0b11110001,0b1,0b1,0b1111111,0b11101111,0b11011111,0b11011111,0b101010,0b101010,0b11011111,0b11011111,0b101010,0b111110,0b10001010,0b10001010,0b101010,0b11011111,0b10001010,0b10001010,0b11101111,0b101010,0b11101111,0b101010,0b1111111,0b10100100,0b10001010,0b11011111,0b11110001,0b10001010,0b1,0b1,0b101010,0b1111111,0b10110000,0b1111111,0b11110001,0b1,0b101010,0b1111111,0b1,0b1111111,0b111110,0b10110000,0b1,0b1111111,0b11011111,0b10110000,0b11011111,0b1111111,0b10110000,0b10100100]
student_id = '590610627'
matchUnicode = student_id.encode('utf8')


cipherString = []
for i in range(len(ciphertext)):
    cipherString.append( "{0:08b}".format(ciphertext[i]) )

decryptResult = []
result = []
finalKey = ''
for i in range(1024):
    key = "{0:010b}".format(i)
    print('KEY is ' + key)
    for j in range(len(cipherString)):
        decryptResult.append( decrypt(  str( cipherString[j] )  ,  str( "{0:010b}".format(i)  )   ) ) 
    if int(decryptResult[0],2) == int(matchUnicode[0]):
        if int(decryptResult[1],2) == int(matchUnicode[1]):   
            if int(decryptResult[2],2) == int(matchUnicode[2]): 
                if int(decryptResult[3],2) == int(matchUnicode[3]): 
                    if int(decryptResult[4],2) == int(matchUnicode[4]): 
                        if int(decryptResult[5],2) == int(matchUnicode[5]): 
                            if int(decryptResult[6],2) == int(matchUnicode[6]): 
                                if int(decryptResult[7],2) == int(matchUnicode[7]): 
                                    if int(decryptResult[8],2) == int(matchUnicode[8]): 
                                        finalKey = key
                                        break
    decryptResult = []
print('\nMatched Key : ' + finalKey)
print('Final Result : ')
for i in range(len(decryptResult)):
    print( int(decryptResult[i],2) - 48 , end = ', ' )
print('\n')

