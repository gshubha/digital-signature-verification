import asyncio
import sys
import websockets
import threading
import hashlib
import json
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
    return (e, d, n)

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
def r_encrypt(publickey, message):
    # Unpack the key 
    e, n = publickey
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
    else:
         p = [chr((char ** d) % n) for char in message]        
   
    # Return the array 

    return ''.join(p)

sBox  = [0x9, 0x4, 0xa, 0xb, 0xd, 0x1, 0x8, 0x5,
         0x6, 0x2, 0x0, 0x3, 0xc, 0xe, 0xf, 0x7]

def sub4NibList(sbox, s):
    """Nibble substitution function"""
    return [sbox[e] for e in s]

def shiftRow(s):
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
    return [s[0] ^ mult(4, s[2]), s[1] ^ mult(4, s[3]),
            s[2] ^ mult(4, s[0]), s[3] ^ mult(4, s[1])]   

def keyExp(key):
    w = [None] * 6
    """Generate the three round keys"""
    def sub2Nib(b):
        """Swap each nibble and substitute it using sBox"""
        return sBox[b >> 4] + (sBox[b & 0x0f] << 4)
 
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
    
def encrypt(plain_text,key,sbox = sBox):
    """Encrypt plaintext block"""
    def fun(state):
        state=[format(s,'04b') for s in state]
        state=eval('0b' + state[0]+state[1]+state[2]+state[3])
        return state
    
    genertated_key=keyExp(key)
    var=eval('0b'+ format(genertated_key[0],'08b')+format(genertated_key[1],'08b'))
    state=plain_text^var
    #Round 1
    state=intToVec(state) #int to vector conversion

    state=mixCol(shiftRow(sub4NibList(sBox,state))) #mixing coloums

    state=[state[0],state[2],state[1],state[3]]

    var=eval('0b'+ format(genertated_key[2],'08b')+format(genertated_key[3],'08b'))
    state=fun(state)^var
    #Round 2
    state=intToVec(state)
    state=shiftRow(sub4NibList(sBox,state))
    state=[state[0],state[2],state[1],state[3]]
    print(state)
    var=eval('0b'+ format(genertated_key[4],'08b')+format(genertated_key[5],'08b'))
    state=fun(state)^var
    return format(state,'016b')
# method to send and reveive from the server
async def message():
    async with websockets.connect("ws://127.0.0.1:1234") as socket:
        while True:
            p_s =input("Enter 1 to request server public key:")
            await socket.send(p_s)
            public_e=int(await socket.recv())
            public_n=int(await socket.recv())
            print('The public key of server is(e,n):',(public_e,public_n))
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
            e ,d,n = generate_keypair(p,q,f,n)
            # print('The value at client [e] = ',e)
            # print('The value at client [d] = ',d)
            # print('The value at client [n] = ',n)
            print('private key of Client (e,n)',(e,n))
            print('public key of Client (d,n)',(d,n))
            msg = int(input("Enter text : "))
            key = int(input("Input Cipher key : "))
          
            public_key=(public_e,public_n)
            encr_key = r_encrypt(public_key,key)
            print('Encrypted Secret key is:',encr_key)
            await socket.send(str(encr_key))
            ciphertext = encrypt(msg, key)
            ciphertext = int(ciphertext, 2)
            print("ciphertext = ", ciphertext)
            d_s=await socket.recv()
            if(d_s=='2'):
                await socket.send(str(e))
                await socket.send(str(n))
            # message = str(ciphertext)+" "+str(key)
            message = str(ciphertext)
            await socket.send(message)
            result = hashlib.sha256(str(msg).encode())
  
            # printing the equivalent hexadecimal value.
            print("The hexadecimal Digest generated : ")
            t =result.hexdigest()
            print(result.hexdigest())
            private_key =(d,n)
            dig=r_encrypt(private_key,t)
            print("Digital signature of client is:\n",dig)
            dig=json.dumps(dig)
            await socket.send(dig)
            
            
            exit()
            

if __name__ == '__main__':

    asyncio.get_event_loop().run_until_complete(message())
    #asyncio.get_event_loop().run_forever()
