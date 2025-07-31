import pyotp
import qrcode
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os
import json
from datetime import datetime

# Configurações
SALT_FILE = "salt.key"
VAULT_FILE = "password_vault.enc"
CONFIG_FILE = "config.json"

def generate_salt():
    """Gera um salt aleatório para derivar a chave mestra"""
    return os.urandom(16)

def derive_key(password: str, salt: bytes):
    """Deriva uma chave AES a partir da senha mestra"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600000,  # Aumentado para 600k iterações
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_data(data: dict, key: bytes):
    """Criptografa os dados com Fernet (AES)"""
    fernet = Fernet(key)
    encrypted = fernet.encrypt(json.dumps(data).encode())
    return encrypted

def decrypt_data(encrypted_data: bytes, key: bytes):
    """Descriptografa os dados"""
    fernet = Fernet(key)
    decrypted = fernet.decrypt(encrypted_data).decode()
    return json.loads(decrypted)

def initialize_vault():
    """Configura o cofre de senhas pela primeira vez"""
    if os.path.exists(VAULT_FILE):
        print("✅ Cofre já existe. Pule esta etapa.")
        return

    print("🔐 Configure sua senha mestra (NUNCA PERCA ESTA SENHA!)")
    while True:
        master_password = input("Digite uma senha forte (mínimo 6 caracteres): ")
        if len(master_password) >= 6:
            break
        print("❌ Senha muito curta. Use 6+ caracteres.")

    salt = generate_salt()
    key = derive_key(master_password, salt)

    # Salva o salt e um cofre vazio
    with open(SALT_FILE, "wb") as f:
        f.write(salt)

    with open(VAULT_FILE, "wb") as f:
        f.write(encrypt_data({}, key))

    print("✅ Cofre criado com sucesso!")

def setup_2fa():
    """Configura autenticação em dois fatores"""
    if not os.path.exists(VAULT_FILE):
        print("❌ Crie um cofre primeiro!")
        return

    # Gera uma nova chave secreta
    secret = pyotp.random_base32()

    # Cria URI para o QR Code
    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name="SecurePass",
        issuer_name="Password Manager"
    )

    # Gera QR Code no terminal
    print("\n🔒 Escaneie este QR Code no Google Authenticator:")
    qr = qrcode.QRCode()
    qr.add_data(totp_uri)
    qr.print_ascii(invert=True)

    # Mostra a chave manualmente
    print(f"\n📌 Chave manual: {secret}")
    print("⏳ O código muda a cada 30 segundos.")

    # Salva a configuração
    with open(CONFIG_FILE, "w") as f:
        json.dump({"2fa_secret": secret, "2fa_enabled": True}, f)

    # Teste imediato
    verify_2fa(test_mode=True)

def verify_2fa(test_mode=False):
    """Verifica o código 2FA com tolerância de tempo"""
    if not os.path.exists(CONFIG_FILE):
        return True  # 2FA não está ativado

    with open(CONFIG_FILE, "r") as f:
        config = json.load(f)

    if not config.get("2fa_enabled", False):
        return True

    secret = config["2fa_secret"]
    totp = pyotp.TOTP(secret)

    # Debug: Mostra o código atual válido
    if test_mode:
        current_code = totp.now()
        print(f"\nDEBUG: Código atual válido é {current_code}")
        print(f"Próxima atualização em {30 - datetime.now().second % 30} segundos")

    for attempt in range(3):
        code = input("🔢 Digite seu código 2FA: ").strip()
        if totp.verify(code, valid_window=1):  # Aceita ±30s
            return True
        print("❌ Código inválido. Tente novamente.")

    print("⛔ Muitas tentativas falhas. Acesso negado.")
    return False

def add_password():
    """Adiciona uma nova senha ao cofre (com verificação 2FA)"""
    if not verify_2fa():
        return

    if not os.path.exists(VAULT_FILE):
        print("❌ Crie um cofre primeiro!")
        return

    master_password = input("🔑 Digite sua senha mestra: ")

    try:
        with open(SALT_FILE, "rb") as f:
            salt = f.read()

        key = derive_key(master_password, salt)

        with open(VAULT_FILE, "rb") as f:
            encrypted_data = f.read()

        vault = decrypt_data(encrypted_data, key)

        print("\n➕ Adicionar Nova Senha")
        service = input("Serviço (ex: Gmail): ").strip()
        username = input("Usuário/E-mail: ").strip()
        password = input("Senha: ").strip()

        vault[service] = {"username": username, "password": password}

        with open(VAULT_FILE, "wb") as f:
            f.write(encrypt_data(vault, key))

        print(f"✅ '{service}' salvo com sucesso!")

    except Exception as e:
        print(f"❌ Erro: {str(e)}")

def view_passwords():
    """Mostra todas as senhas salvas (com verificação 2FA)"""
    if not verify_2fa():
        return

    if not os.path.exists(VAULT_FILE):
        print("❌ Cofre não encontrado.")
        return

    master_password = input("🔑 Digite sua senha mestra: ")

    try:
        with open(SALT_FILE, "rb") as f:
            salt = f.read()

        key = derive_key(master_password, salt)

        with open(VAULT_FILE, "rb") as f:
            encrypted_data = f.read()

        vault = decrypt_data(encrypted_data, key)

        print("\n🔍 Senhas Armazenadas:")
        for service, data in vault.items():
            print(f"\n📌 {service}")
            print(f"👤 Usuário: {data['username']}")
            print(f"🔒 Senha: {data['password']}")

    except Exception as e:
        print(f"❌ Erro: {str(e)}")

def main():
    print("🌟 SecurePass - Gerenciador de Senhas com 2FA 🔒\n")

    while True:
        print("\nMenu:")
        print("1. 🔐 Criar cofre (primeiro uso)")
        print("2. ⚙️ Configurar 2FA")
        print("3. ➕ Adicionar senha")
        print("4. 🔍 Ver senhas")
        print("5. ❌ Sair")

        choice = input("Escolha: ").strip()

        if choice == "1":
            initialize_vault()
        elif choice == "2":
            setup_2fa()
        elif choice == "3":
            add_password()
        elif choice == "4":
            view_passwords()
        elif choice == "5":
            print("👋 Até logo!")
            break
        else:
            print("⚠️ Opção inválida!")

if __name__ == "__main__":
    main()