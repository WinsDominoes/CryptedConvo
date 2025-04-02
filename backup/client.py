import socket
import threading
# 2.1 Add an import statement to import the Hashlib library for generating hash values.
from cryptography.fernet import Fernet


SERVER_HOST = "localhost"   # Please change this to your ip address
SERVER_PORT = 12345

def send_messages(client_socket, fernet):
    while True:
        try:
            message = input("\nEnter your message: ")

            # 2.2 Add a statement to generate a hash value of the input message.
            # 2.3 Print the generated hash value out.

            encrypted_message = fernet.encrypt(message.encode())

            # 2.4 Generate a payload that includes both the encrypted message and the generated hash value.
            #       Both values can be concatenated and separated by a pipe symbol "|".

            # 2.5 Modify the following statement to send the concatenated payload instead.
            client_socket.send(encrypted_message)
        except OSError:
            break
        except Exception as e:
            print(f"Error: {e}")

    client_socket.close()

def receive_messages(client_socket, fernet):
    while True:
        try:
            encrypted_message = client_socket.recv(1024)
            if not encrypted_message:
                break

            # 2.6 Add a statement to convert the received message from bytes to a string.
            #     Then, perform a string operation to split it into an array of value using the pipe symbol as a delimiter.

            # 2.7 Add a statement to store the received hash value in a variable.

            # 2.8 Add a statement to store the received encrypted message in a variable.

            message = fernet.decrypt(encrypted_message).decode()

            # 2.9 Generate a hash value of the decrypted message and store it in a variable.

            # 2.10 Add an if-else statement with the condition to compare the received hash value (2.7) to the generated hash value (2.9).
            #       If they are the same, the program prints a message out to inform that "The received message is authentic".
            #       Otherwise, the program prints a message out to inform that "The received message is tampered".

            print(f"Received: {message}")
        except OSError:
            break
        except Exception as e:
            print(f"Error: {e}")

    client_socket.close()

if __name__ == "__main__":
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((SERVER_HOST, SERVER_PORT))


        key = client_socket.recv(1024)
        print(f"Received key: {key.decode()}")  # Для отладки, можно убрать
        fernet = Fernet(key)

        receive_thread = threading.Thread(target=receive_messages, args=(client_socket, fernet))
        receive_thread.start()

        send_thread = threading.Thread(target=send_messages, args=(client_socket, fernet))
        send_thread.start()

        receive_thread.join()
        send_thread.join()
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        client_socket.close()
