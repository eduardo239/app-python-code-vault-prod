
import unittest
import os
import json
from unittest.mock import patch
import sys

# Adicione o diretório raiz do projeto ao sys.path para importar o módulo main
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from main import generate_salt, derive_key, encrypt_data, decrypt_data

class TestCodeVault(unittest.TestCase):

    def test_generate_salt(self):
        salt = generate_salt()
        self.assertEqual(len(salt), 16)
        self.assertIsInstance(salt, bytes)

    def test_derive_key(self):
        salt = b'test_salt'
        password = 'test_password'
        key = derive_key(password, salt)
        self.assertEqual(len(key), 44)  # Base64 encoded key length

    def test_encrypt_decrypt_data(self):
        test_data = {'service': 'test', 'username': 'testuser', 'password': 'testpass'}
        key = derive_key('testpassword', b'testsalt')
        encrypted = encrypt_data(test_data, key)
        decrypted = decrypt_data(encrypted, key)
        self.assertEqual(test_data, decrypted)

    @patch('builtins.input', return_value='123456')
    @patch('os.path.exists', return_value=False)
    @patch('builtins.open', create=True)
    def test_initialize_vault(self, mock_open, mock_exists, mock_input):
        from main import initialize_vault
        initialize_vault()
        mock_open.assert_called()
        mock_exists.assert_called_with('password_vault.enc')

if __name__ == '__main__':
    unittest.main()
