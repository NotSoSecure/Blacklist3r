# AES256 Decrypter
It will try to find the key from the pre-define cryptographic keys list based on iteration method and try to identify the cryptographic key using which the data is encrypted.

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