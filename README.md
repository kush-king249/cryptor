Secure File Cryptographer
This project provides a command-line utility for encrypting and decrypting files using
AES-256 GCM encryption. It is built with Python and leverages the cryptography library
for secure cryptographic operations.

Features
• File Encryption: Encrypts any specified file using a user-provided password.
• File Decryption: Decrypts previously encrypted files using the same password.
• Strong Encryption: Utilizes AES-256 in GCM (Galois/Counter Mode) for
authenticated encryption, ensuring both confidentiality and integrity of data.
• Key Derivation: Employs PBKDF2HMAC with SHA256 and a high number of
iterations (100,000) to derive a strong encryption key from the password, making it
resistant to brute-force attacks.
• Random Salt and IV: Generates a unique random salt and Initialization Vector (IV)
for each encryption operation, enhancing security and preventing identical
plaintexts from producing identical ciphertexts.

Requirements
To run this cryptographer, you need Python 3.x and the cryptography library. You can
install the required library using pip :
pip install -r requirements.txt

How to Use
1. Clone the Repository (or download the files)
If you have Git installed, you can clone the repository:
git clone <repository_url>
cd <repository_directory>
Otherwise, simply download cryptor.py and requirements.txt to your local machine.

2. Install Dependencies
Navigate to the project directory in your terminal and install the necessary Python
packages:
pip install -r requirements.txt

3. Encrypting a File
To encrypt a file, use the --encrypt argument followed by the path to the file you want
to encrypt, and provide your password using --password :
python cryptor.py --encrypt path/to/your/file.txt --password your_secret_password
Upon successful encryption, a new file with a .encrypted extension will be created in
the same directory (e.g., file.txt.encrypted ).

4. Decrypting a File
To decrypt an encrypted file, use the --decrypt argument followed by the path to the
encrypted file, and provide the exact same password used for encryption:
python cryptor.py --decrypt path/to/your/file.txt.encrypted --password
your_secret_password
If decryption is successful, the original file will be restored (e.g., file.txt ). If the password
is incorrect or the file is corrupted, an error message will be displayed.

Author
Hassan Mohamed Hassan Ahmed


