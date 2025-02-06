from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding


def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key


def encrypt_message(public_key, message):
    ciphertext = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext


def decrypt_message(private_key, ciphertext):
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext.decode()


def load_private_key(filename, password):
    with open(filename, "rb") as f:
        return serialization.load_pem_private_key(
            f.read(),
            password=password,
            backend=default_backend()
        )


def load_public_key(filename):
    with open(filename, "rb") as f:
        return serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )


def main():
    action = input("Выберите действие (encrypt/decrypt): ").strip().lower()

    if action == "encrypt":
        private_key, public_key = generate_key_pair()
        message = input("Введите сообщение для шифрования: ")
        ciphertext = encrypt_message(public_key, message)
        print("Зашифрованное сообщение:", ciphertext)

        # Запрашиваем пароль для шифрования закрытого ключа
        password = input("Введите пароль для шифрования закрытого ключа: ")
        password_bytes = password.encode()  # Преобразуем пароль в байты

        with open("private_key.pem", "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.BestAvailableEncryption(password_bytes)
            ))

        with open("public_key.pem", "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ))

    elif action == "decrypt":
        password = input("Введите пароль для закрытого ключа: ").encode()
        private_key = load_private_key("private_key.pem", password=password)
        ciphertext = input("Введите зашифрованное сообщение в виде байтов (например: b'...'): ")

        # Преобразуем строку обратно в байты
        ciphertext = eval(ciphertext)  # Предупреждение: eval() небезопасен! Лучше использовать другой подход

        plaintext = decrypt_message(private_key, ciphertext)
        print("Расшифрованное сообщение:", plaintext)

    else:
        print("Неверный выбор. Пожалуйста, выберите 'encrypt' или 'decrypt'.")


if __name__ == "__main__":
    main()