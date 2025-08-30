# Secure File Cryptographer Project Report

## 1. Introduction

In a world where reliance on digital data is increasing, information security has become a paramount necessity. This project aims to develop a robust and secure tool for encrypting and decrypting files using Python. The goal is not merely to provide encryption functionality, but also to demonstrate a deep understanding of correct security concepts and best practices in cryptography.

## 2. Project Objectives

The main objectives of this project are:

-   Build a Command-Line Interface (CLI) tool for file encryption and decryption.
-   Utilize a standard and reliable encryption algorithm to ensure maximum security.
-   Implement secure Key Management principles.
-   Ensure Data Integrity in addition to Confidentiality.
-   Create comprehensive project documentation that clarifies technical and security aspects.

## 3. Security Concepts and Algorithms Used

To ensure the tool's security, the following security concepts have been applied:

### 3.1. Encryption Algorithm: AES-256-GCM

`AES` (Advanced Encryption Standard) with a 256-bit key in `GCM` (Galois/Counter Mode) was chosen. `AES` is a global standard for Symmetric Encryption and is widely used in sensitive applications. `GCM` provides two main features:

-   **Confidentiality:** Ensures data privacy so that it can only be read by those who possess the correct key.
-   **Authentication and Data Integrity:** `GCM` provides a mechanism to verify that data has not been tampered with or modified after encryption. This is done by generating an Authentication Tag that is verified during decryption. If any part of the ciphertext or the authentication tag is altered, decryption will fail, protecting against data manipulation attacks.

### 3.2. Key Management: PBKDF2

Key management is a critical aspect of any encryption system. Instead of using the raw user password directly as an encryption key (which is an insecure practice), the `PBKDF2` (Password-Based Key Derivation Function 2) is used. `PBKDF2` transforms the password (which is often short and non-random) into a strong and sufficiently long encryption key for use with `AES`. `PBKDF2` features:

-   **Key Stretching:** `PBKDF2` performs a large number of iterative hashing operations, making the key derivation process intentionally slow. This significantly increases the time required for attackers to try different passwords (brute-force or dictionary attacks).
-   **Salt:** A unique and random Salt is used for each key derivation operation. Salt is a random value combined with the password before applying `PBKDF2`. This ensures that the same password will produce a different key each time, and prevents the use of Rainbow Tables to crack passwords.

### 3.3. Initialization Vector (IV)

An Initialization Vector (IV) is a random value used once with each encryption operation. Unlike the key, the `IV` does not need to be secret and can be stored with the ciphertext. The importance of `IV` lies in:

-   **Preventing Repetitive Patterns:** The `IV` ensures that the same plaintext, when encrypted with the same key, will produce a different ciphertext each time. This prevents attackers from analyzing repetitive patterns in ciphertexts to infer information about the plaintext.
-   **Security in CBC and GCM modes:** The `IV` is essential for securely operating encryption algorithms in modes like `CBC` and `GCM`.

## 4. Source Code Design

The source code is designed to be modular and easy to understand, focusing on separating different tasks. The project consists of a single main Python file (`cryptor.py`) that includes all necessary functions.

### 4.1. File Structure

```
secure_file_cryptographer/
├── docs/
│   └── report.md
├── src/
│   └── cryptor.py
├── README.md
└── requirements.txt
```

### 4.2. Main Functions in `cryptor.py`

-   **`derive_key(password, salt)`:**
    -   **Description:** Derives a secure encryption key from the password and salt using `PBKDF2HMAC`.
    -   **Inputs:** `password` (string), `salt` (bytes).
    -   **Outputs:** Encryption key (bytes).

-   **`encrypt_file(file_path, password)`:**
    -   **Description:** Encrypts the contents of the specified file using `AES-256-GCM`.
    -   **Process:**
        1.  Generate a random Salt.
        2.  Derive the key using `derive_key`.
        3.  Read the original file contents.
        4.  Generate a random Initialization Vector (IV).
        5.  Encrypt data using `AES-256-GCM`, producing ciphertext and an Authentication Tag.
        6.  Write the new encrypted file containing the Salt, IV, ciphertext, and authentication tag.
    -   **Inputs:** `file_path` (file path), `password` (password).
    -   **Outputs:** New encrypted file with `.encrypted` extension.

-   **`decrypt_file(encrypted_file_path, password)`:**
    -   **Description:** Decrypts the contents of the encrypted file using `AES-256-GCM`.
    -   **Process:**
        1.  Read the encrypted file and extract the Salt, IV, ciphertext, and authentication tag.
        2.  Derive the key using `derive_key` (with the same password and extracted salt).
        3.  Decrypt data using `AES-256-GCM`, verifying the authentication tag.
        4.  Write the restored original file.
    -   **Inputs:** `encrypted_file_path` (encrypted file path), `password` (password).
    -   **Outputs:** Restored original file.

-   **`main()` (Command-Line Interface):**
    -   **Description:** Uses the `argparse` library to create a user-friendly command-line interface.
    -   **Process:**
        1.  Parse command-line arguments (`--encrypt`, `--decrypt`, `--file`, `--password`).
        2.  Call the appropriate function (`encrypt_file` or `decrypt_file`) based on user selection.

## 5. Testing and Verification

To ensure the tool functions perfectly and is free of errors, comprehensive tests covering various encryption and decryption scenarios were conducted. These tests included:

-   **Basic Encryption and Decryption Test:** Encrypting a small text file and then decrypting it to verify correct restoration of the original content.
-   **Large File Test:** Encrypting and decrypting larger files to ensure performance and stability.
-   **Different Passwords Test:** Ensuring the tool works correctly with passwords of varying lengths and complexities.
-   **Error Handling Tests:**
    -   Attempting to decrypt a file with an incorrect password (decryption should fail due to `HMAC` verification failure).
    -   Attempting to decrypt a tampered file (decryption should fail).
    -   Handling incorrect file paths.

**Test Results:**

The tests showed that the tool operates reliably, with files being encrypted and decrypted successfully, and any attempts to tamper with data or use incorrect passwords being detected. This confirms that the tool is executable and error-free in the specified scenarios.

## 6. Conclusion

This project represents a practical tool for file encryption and decryption, with a particular focus on implementing security best practices. By using standard algorithms like `AES-256-GCM` and key derivation functions like `PBKDF2`, the project demonstrates a strong understanding of cryptography principles and information security. This project is a valuable addition to any GitHub Portfolio, as it showcases the ability to build secure and effective solutions.

## 7. Author

This report was prepared by hassan mohamed hassan ahmed.




## License

This project is licensed under the MIT License. See the `LICENSE` file for more details.


