import unittest 
from pathlib import Path
from locker import Encryptor, EncodingError
import hashlib

class TestEncryptor(unittest.TestCase):
  def setUp(self):
    self.key = "testpassword"
    self.iv = hashlib.sha256(self.key.encode()).digest()[:16]
    self.cipher = Encryptor(self.key, self.iv)
    
  def test_encrypt_decrypt(self):
    data = b"Hola mundo"
    encrypted = self.cipher.encrypt(data)
    decrypted = self.cipher.decrypt(encrypted)
    self.assertEqual(decrypted, data)
    
  def test_encode_decode(self):
    text = "archivo.txt"
    coded = self.cipher.code_text(text)
    decoded = self.cipher.decode_text(coded)
    self.assertEqual(decoded, text)