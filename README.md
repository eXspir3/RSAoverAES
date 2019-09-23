# RSAoverAES 1.0.2

*RSAoverAES is a tool ot help oyu securly store data by encrypting Files with AES-128 GCM NoPadding and saving the AES-Key in a 
 encrypted File using RSA/OAEP/SHA512withMGF1 Encryption*

## CommandLine Arguments:

  **-encrypt** Set Mode to Generate RSA encrypted AES File (and encrypt File)    
  **-fileToEncrypt** Specify a File to be Encrypted via AES-128/GCM/NoPadding  
  **-pubKey** Specify a RSA-Public Key to encrypt the AES KeyFile with (mandatory with -encrypt)  
    
  **-decrypt** Set Mode to decrypt the AESKey File using RSA Private Key (and decrypt File)  
  **-fileToDecrypt** Specify a File to be decrypted from AES-128/GCM/NoPadding encryption  
  **-aesKey** Specify the RSA/OAEP/SHA512withMGF1 Encrypted AES-Key File to decrypt (mandatory with -decrypt)  
  **-privKey** Specify the RSA Private key for decrypting the AES-Key File (mandatory with -decrypt)  
    
## Generating RSA Keys for use with RSAoverAES:

  Preferably generate the RSA Keys using openssl - make sure the RSA-PrivateKey is stored in PKCS-8 format!  
  Use these Commands to create the RSA Private-PKCS8 +  PublicKey in openssl:
  
    * openssl genrsa -out privatekey.pem 4096  
    * openssl rsa -in privatekey.pem -out publickey.pem -pubout  
    * openssl pkcs8 -in privatekey.pem -topk8 -nocrypt -out privatekey-pkcs8.pem
