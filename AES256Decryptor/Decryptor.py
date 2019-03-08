from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
import base64


BLOCK_SIZE = 16
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]

def encrypt(passphrase, salt, plaintext):
	try:
		raw = pad(plaintext)
		salt=salt.decode("hex")
		
		key = PBKDF2(passphrase, salt, 32)
		iv = PBKDF2(passphrase, salt, 32 + 16)
		iv = iv[32:]#Generate .Net specific IV
		
		cipher = AES.new(key, AES.MODE_CBC, iv)
		return base64.b64encode(cipher.encrypt(raw))
	except:
		print "An exception occurred"
	return ""

def decrypt(ciphertext):
	plaintext=''
	passphraseFound=''
	saltFound=''
	with open("KeyList.txt", "r") as ins:
		array = []
		for line in ins:
			try:
				line=line.rstrip()
				passphrase=line[:line.find(":")]
				plaintextSalt=line[line.find(":")+1:]
				salt=plaintextSalt.decode("hex")
				
				key = PBKDF2(passphrase, salt, 32)
				iv = PBKDF2(passphrase, salt, 32 + 16)
				iv = iv[32:]#Generate .Net specific IV

				cipher=AES.new(key, AES.MODE_CBC, iv)
				plaintext=unpad(cipher.decrypt(base64.b64decode(ciphertext)))
				
				if plaintext: #Break if decryption is found
					passphraseFound=passphrase
					saltFound=plaintextSalt
					break
			except:
				print "An exception occurred"
	return plaintext, passphraseFound, saltFound

if __name__ == '__main__':
	try:
		print "\nAES256 Decryptor"
		print "================"
		print "\n1. Decryption"
		print "2. Encryption"
		choice=input("\nEnter choice: ")
		if choice == 1:
			#"/B5wkRAjxIii//M92E62jg=="
			print "\nEnter values in double qoutes"
			ciphertext = input("Enter text to decrypt : ")
			(plaintext, passphrase, salt) = decrypt(ciphertext)
			if plaintext: 
				print "\nKeys found!!"
				print "============\n"
				print "Passphrase :=> " + passphrase
				print "Salt :=> " + salt
				print "Decrypted text found: " + plaintext + "\n"
			else:
				print "\nNo keys found!!"
		elif choice == 2:
			print "\nEnter values in double qoutes"
			#"MAKV2SPBNI99212"
			passphrase=input("Enter passphrase : ")
			#"4976616e204d65647665646576"
			salt=input("Enter salt value : ")
			plaintext=input("Enter text to encrypt : ")
			print "\nEncrypted text :=> " + encrypt(passphrase, salt, plaintext) + "\n"
		else:
			print "Invalid choice!!"
	except:
		print "An exception occurred"


