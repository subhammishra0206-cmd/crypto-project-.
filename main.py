import aes_demo
import rsa_demo
import sha_demo


def main():
    while True:
        print("\n===== Cryptography Toolkit =====")
        print("1. AES encryption / decryption")
        print("2. RSA encryption / signatures")
        print("3. SHA hashing")
        print("4. Exit")
        choice = input("Choose an option: ").strip()

        if choice == "1":
            aes_demo.run()
        elif choice == "2":
            rsa_demo.run()
        elif choice == "3":
            sha_demo.run()
        elif choice == "4":
            print("Goodbye!")
            break
        else:
            print("Invalid choice, try again.")


if __name__ == "__main__":
    main()
    