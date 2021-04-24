import asyncio
import sys
import websockets
import threading
import hashlib
import json
# import Rsa
#import numpy as np
''' RSA algorithm '''
import random

''' Function : to generated keys '''
def generate_keypair(p, q,f,n):
    #Choose an integer e such that e and f(n) are coprime
    e = random.randrange(2, f)
    # To verify that e and f(n) are comprime
    g = gcd(e, f)
    while g != 1:
        e = random.randrange(2, f)
        g = gcd(e, f)

    #Use Extended Euclid's Algorithm to generate the private key
    d = inverse(e, f)
    
    #Return public and private keypair
    return ((e, d, n))

''' Function : To check Prime '''
def isPrime(i):
	for j in range(2,i):
		if(i%j==0):
			return False
	return True

''' Function : To calcuate gcd '''
def gcd(a,b):
	if(b==0):
		return a
	else:
		return gcd(b,a%b)

''' Function : To calculate Inverse of e :
	using Extended Eculidean Method '''
def inverse(a, m) : 
    m0 = m 
    y = 0
    x = 1
    if (m == 1) : 
        return 0
    while (a > 1) : 
        # q is quotient 
        q = a // m 
        t = m 
        m = a % m 
        a = t 
        t = y 
        # Update x and y 
        y = x - q * y 
        x = t 
    # Make x positive 
    if (x < 0) : 
        x = x + m0 
  
    return x 

''' Function : Encryption & Decryption 
	Cipher text c = m^e mod n 
	Plain text d= c^d mod n
	'''
def r_encrypt(publicKey, message):
    # Unpack the key 
    e, n = publicKey
    # Convert each letter in the plaintext to numbers based on the character using a^b mod m
    if type(message) == int:
        c = (message**e)%n
    else:
        c = [(ord(char) ** e) % n for char in message]   
    return c

def r_decrypt(privateKey, message):
    # Unpack the key 
    d, n = privateKey
    # Generate the plaintext based on the ciphertext and key using a^b mod m
    if type(message) == int:
        c = (message**d)%n
        return c
    else:
         p = [chr((char ** d) % n) for char in message]  
         return ''.join(p)     # Return the array 
            
     

s_Box  = [0x9, 0x4, 0xa, 0xb, 0xd, 0x1, 0x8, 0x5,
         0x6, 0x2, 0x0, 0x3, 0xc, 0xe, 0xf, 0x7]

sBox= [0xa, 0x5, 0x9, 0xb, 0x1, 0x7, 0x8, 0xf,
         0x6, 0x0, 0x2, 0x3, 0xc, 0x4, 0xd, 0xe]

def sub4NibList(sbox, s):
    """Nibble substitution function"""
    return [sbox[e] for e in s]

def shiftRow(s):# row shift
    return [s[0], s[1], s[3], s[2]]

def mult(p1, p2):
    p = 0
    while p2:
        if p2 & 0b1:
            p ^= p1
        p1 <<= 1
        if p1 & 0b10000:
            p1 ^= 0b11
        p2 >>= 1
    return p & 0b1111

def mixCol(s):
        return [mult(9, s[0]) ^ mult(2, s[2]), mult(9, s[1]) ^ mult(2, s[3]),
                mult(9, s[2]) ^ mult(2, s[0]), mult(9, s[3]) ^ mult(2, s[1])]  

def keyExp(key):
    w = [None] * 6
    """Generate the three round keys"""
    def sub2Nib(b):
        """Swap each nibble and substitute it using sBox"""
        return s_Box[b >> 4] + (s_Box[b & 0x0f] << 4)
 
    Rcon1, Rcon2 = 0b10000000, 0b00110000
    w[0] = (key & 0xff00) >> 8
    w[1] = key & 0x00ff
    w[2] = w[0] ^ Rcon1 ^ sub2Nib(w[1])
    w[3] = w[2] ^ w[1]
    w[4] = w[2] ^ Rcon2 ^ sub2Nib(w[3])
    w[5] = w[4] ^ w[3]
    return w


def intToVec(n):
    """Convert a 2-byte integer into a 4-element vector"""
    return [n >> 12, (n >> 4) & 0xf, (n >> 8) & 0xf,  n & 0xf]
    
def decrypt(cipher,key,sBox = sBox):
    # decrypt function for generation of plaintext from ciphertext
    def fun(state):
        state=[format(s,'04b') for s in state]
        state=eval('0b' + state[0]+state[1]+state[2]+state[3])
        return state
    
    genertated_key=keyExp(key)
    
    var=eval('0b'+ format(genertated_key[4],'08b')+format(genertated_key[5],'08b'))
    #print(var)
    state=cipher^var
    #print(state)
    state=intToVec(state)
    state=sub4NibList(sBox,shiftRow(state))
    state=[state[0],state[2],state[1],state[3]]
    
    
    var=eval('0b'+ format(genertated_key[2],'08b')+format(genertated_key[3],'08b'))
    state=fun(state)^var
    state=intToVec(state)
    state=sub4NibList(sBox,shiftRow(mixCol(state)))
    state=[state[0],state[2],state[1],state[3]]
    var=eval('0b'+ format(genertated_key[0],'08b')+format(genertated_key[1],'08b'))
    plain_text=fun(state)^var
    
    return  format(plain_text,'016b')

#crearing the method to receive the message and returns the reverse of the message
async def response(websocket, path):
    while True:
        while True:
            try:
                p = int(input('Enter the value of prime number p = ')) 
            except ValueError:
                print("InValid Input")
                continue
            if not isPrime(p):
                print("Enter a prime number")
                continue
            else:
                break
        while True:
            try:
                q = int(input('Enter the value of prime number q = ')) 
            except ValueError:
                print("InValid Input")
                continue
            if not isPrime(q):
                print("Enter a prime number")
                continue
            else:
                break

        # Calculate n=pq     
        n = p*q      
        # Calculate f(n) ( denoted by f in code ) =(p-1)(q-1)                                           
        f = (p-1)*(q-1)  
        e,d,n= generate_keypair(p,q,f,n)
        # print('The value at server [e] = ',e)
        # print('The value at server [d] = ',d)
        # print('The value at server [n] = ',n)
        print('private key of server(e,n):',(e,n))
        print('public key of server (d,n):',(d,n))
        p_s=await websocket.recv()
        if(p_s=='1'):
            await websocket.send(str(e))
            await websocket.send(str(n))

        encr_key = int(await websocket.recv())
        print('Encrypted Secret key is:',encr_key)
        privateKey=(d,n)
        decr_key = r_decrypt(privateKey,encr_key)
        print('Decrypted Secret key is:',decr_key) 
        d_s =input("Enter 2 to request client public key:")
        await websocket.send(d_s)
        public_e=int(await websocket.recv())
        public_n=int(await websocket.recv())
        print('Client Public key recived is:',(public_e,public_n))
        message = await websocket.recv()
        # ciphertext, key = message.split(" ")
        ciphertext = int(message)
        print("ciphertext = ", ciphertext)
        # key = int(key)
        # print("key = ", key)
        plaintext = decrypt(ciphertext, decr_key)
        p=int(plaintext,2)
        print("Decrypted message(plaintext) = ", int(plaintext,2))
        dig_client=await websocket.recv()
        dig_client=json.loads(dig_client)
        # dig_client =list(dig_client.split(' '))
        result = hashlib.sha256(str(p).encode())

        # printing the equivalent hexadecimal value.
        print("Digest Generated at server : \n")
        t =result.hexdigest()
        print(result.hexdigest())
        # d_s =input("enter 2 to request client public key:")
        # await websocket.send(d_s)
        # public_e=int(await websocket.recv())
        # public_n=int(await websocket.recv())
        public_key = (public_e,public_n)#client public key
        dig=r_decrypt(public_key,dig_client)

        print("Verification Digest is:\n",dig)
        if(dig== t):
            print("Digital Signature is Verified.")
            
        else:
            print("Digital Signature is Not Verified.")


        exit()

if __name__ == '__main__':
   # server starts in localhost at port 1234
    start_server = websockets.serve(response, '127.0.0.1', 1234)

    asyncio.get_event_loop().run_until_complete(start_server)
    asyncio.get_event_loop().run_forever()
