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
    return ((e, n), (d, n))

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
def encrypt(publicKey, message):
    # Unpack the key 
    e, n = publicKey
    # Convert each letter in the plaintext to numbers based on the character using a^b mod m
    if type(message) == int:
        c = (message**e)%n
    else:
        c = [(ord(char) ** e) % n for char in message]   
    return c

def decrypt(privateKey, message):
    # Unpack the key 
    d, n = privateKey
    # Generate the plaintext based on the ciphertext and key using a^b mod m
    if type(message) == int:
        c = (message**d)%n
    else:
         p = [chr((char ** d) % n) for char in message]        
   
    # Return the array 

    return ''.join(p)

''' Input : Validates if entered p,q are Prime ''' 
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
publicKey , privateKey = generate_keypair(p,q,f,n)

# Input message to be encrypted
m = input('Enter the value of message m = ')
print('Public Key [e,n] = ',publicKey)

# Encrypt 
c = encrypt(publicKey,m)
# Decrypt
m = decrypt(privateKey,c)

print('Cipher text = ',c)
print('Private Key [d,n] = ',privateKey)
print('Plain text after decryption = ',m)