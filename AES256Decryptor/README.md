# AES256 Decrypter
A Python script to decrypt data that are encrypted using pre-shared cryptographic keys.

# Usage

  - It will take 2 command line arguments
    - data : cipher text to be decrypt
    - type: Type of ciphertext (hex/base64)

  - Sample command
    - for base64 type    
      ```sh
        python decrypter.py --data "2s588k/0kB31nKqs2h696g==" --format base64
        ```
    - for hex type    
      ```sh
        python decrypter.py --data "DACE7CF24FF4901DF59CAAACDA1EBDEA" --format hex
        ```
