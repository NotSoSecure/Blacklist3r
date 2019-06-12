#!/usr/bin/python
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
import base64
import argparse

BLOCK_SIZE = 16
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]

def decrypt(ciphertext, type):
	plaintext=''
	passphraseFound=''
	saltFound=''
	with open("KeyList.txt", "r") as ins:
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

				if type == "hex":
					plaintext=unpad(cipher.decrypt(ciphertext.decode("hex")))
				else:
					plaintext=unpad(cipher.decrypt(base64.b64decode(ciphertext)))
				
				if plaintext: #Break if decryption is found
					#plaintext=plaintext.decode('ascii')
					passphraseFound=passphrase
					saltFound=plaintextSalt
					break
			except:
				"An exception occurred"
	return plaintext, passphraseFound, saltFound

if __name__ == '__main__':
	try:
		parser = argparse.ArgumentParser(description='AES256 Decryptor')
		parser.add_argument("--data", help="Data to decrypt")
		parser.add_argument("--format", help="Data format")
		args = parser.parse_args()
		if not args.data and not args.format:
			print "null"
		else:
			(plaintext, passphrase, salt) = decrypt(args.data, args.format)
			if plaintext:
				print "\nKeys found!!"
				print "============\n"
				print "Passphrase :=> " + passphrase
				print "Salt :=> " + salt
				print "Decrypted text found: " + plaintext + "\n"
			else:
				print "\nNo key found!!\n"
	except:
		print "An exception occurred"


