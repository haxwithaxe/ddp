from datetime import datetime
from StringIO import StringIO

import M2Crypto

import hashlib
import math
import os
import random
import subprocess
import sys
import threading
import time
import xmlrpclib


class DanRSA(object):

	def __init__(self, publickey=None, privatekey=None, passphrasecallback="password"):
		self.passphrase_callback = passphrasecallback
		self.public_key = None
		self.public_key_file = publickey
		self.private_key = None
		self.private_key_file = privatekey
		if self.public_key_file <> None:
			self.public_key = M2Crypto.RSA.load_pub_key(self.public_key_file)
		if self.private_key_file <> None:
			self.private_key = M2Crypto.RSA.load_key(self.private_key_file, callback = self.passphraseCallback)
		if self.public_key_file <> None:
			self.MAX_DATA_LENGTH = self.maximumDataLength()
		else:
			self.MAX_DATA_LENGTH = 0
	
	def decrypt(self, bytesin):
		dec = self.private_key.private_decrypt(bytesin, M2Crypto.RSA.pkcs1_padding)
		return dec
	
	def encrypt(self, bytesin):
		enc = self.public_key.public_encrypt(bytesin, M2Crypto.RSA.pkcs1_padding)
		return enc
	
	def generateKeyPair(self, publickey, privatekey, bits = 512):
		rsa = M2Crypto.RSA.gen_key(bits, self.m2crypto.m2.RSA_F4)
		rsa.save_pub_key(publickey)
		rsa.save_key(privatekey, cipher = "aes_256_cbc", callback = self.passphraseCallback)
		rsa = None
	
	def generatePassphrase(self, length = 128):
		pwd = bytearray()
		for x in xrange(0, length):
			pwd.append(random.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"))
		return str(pwd)
	
	def loadPassphrase(self, passphrasefile):
		f = open(passphrasefile, "r")
		r = f.readline()
		f.close()
		return r
	
	def maximumDataLength(self):
		length = 1
		try:
			for x in xrange(0, 8192):
				self.encrypt("a" * length)
				length += 1
			return 8192
		except M2Crypto.RSA.RSAError, ex:
			return length - 1
	
	def passphraseCallback(self, v):
		return self.passphrase_callback
	
	def savePassphrase(self, passphrasefile, passphrase):
		f = open(passphrasefile, "w")
		f.write(passphrase)
		f.close()
	
	def signMessage(self, message):
		evp = M2Crypto.EVP.load_key(self.private_key_file, callback = self.passphraseCallback)
		evp.sign_init()
		evp.sign_update(message)
		return evp.sign_final()
		
	def verifyMessage(self, message, signature):
		evp = M2Crypto.EVP.PKey()
		evp.assign_rsa(self.public_key)
		evp.verify_init()
		evp.verify_update(message)
		return evp.verify_final(signature)

