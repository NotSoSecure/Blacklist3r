# AspDotNetWrapper

The tool used to encrypt/decrypt .aspnet.applicaitoncookie and .ASPXAUTH cookie and ViewState against list of MachineKeys.

### Usage
```
AspDotNetWrapper.exe --help

AspDotNetWrapper 2.0.0.0
Copyright ©  2019

  -r, --keypath                Machine keys file path.
  -c, --encrypteddata          Encrypted data value to decrypt.
  -d, --decrypt                (Default: false) To decrypt the encrypted data.
  -f, --decryptDataFilePath    file path where the decrypted information stored
  -p, --purpose                purpose
  -a, --valalgo                Validation algorithm
  -b, --decalgo                Decryption algorithm
  -m, --modifier               Modifier used to encode the viewstate
  -s, --macdecode              Used to decide whether viewstate is MAC enabled or not
  -l, --legacy                 Used to decide whether viewstate legacy decrypt
  -o, --outputFile             Output file path
  -i, --IISDirPath             Application dir path in IIS tree
  -t, --TargetPagePath         Target page path
  -v, --antiCSRFToken          Anti CSRF token
  --help                       Display this help screen.
  --version                    Display version information.
```

#### The list of pre-shared MachineKey can be found in "./AspDotNetWrapper/Resource/MachineKeys.txt" file

#
#
### To decrypt asp.net.applicationcookie (Owin auth cookie)

Sample Command
```console
AspDotNetWrapper.exe --keypath MachineKeys.txt --encrypteddata 195A989biBjM_NAqqiie5DnHKfcwrNGDuT-Suumqmw6oVyLSsjCFx9Emhf034TDjcuC9mfwNbi6yD-1QlbhcUAgdTOwY0o0sNbg7bJrNyUEf6ZoyYh2QAZHhmxteN_cMQJI7C1WOBEl0ocihUVhKghdxegwRURcYx2h1uMbijX3jsEf59L8Uco_PpfFLN--RtcLTKUvtZd0fH5Sgc1JQmsvTBr7IJ4Ua01I8uyEPYNXZGYvssSzJ8YN6MXioky3WBXv9NGNxDpgTpIPWGetgZ0iOSaTmqPr6sPu4ndesUV4SKsBroIP6Y38rr8LwFCZBKDK5dli4kKwmy9xeM02qshCoLf8ppeOiK2aMLfb9jqkraoss2BflD3hpDdrYHVGH7ryTWQh4HABYDC7OOMgdld3WJ1CUfJ9pmr0qnVFD4Gc --decrypt --purpose=owin.cookie  --valalgo=hmacsha512 --decalgo=aes

--encrypteddata : value to decrypt using tool
--decrypt : If you add this argumenet the tools try to decrypt the cookie
--purpose: owin.cookie to decrypt the .aspnet.applicationcookie cookie
--valalgo: Validation algorithm
--decalgo: Decryption algorithm
```

### To decrypt .aspxauth (Forms authentication cookie)

Sample Command
```console
AspDotNetWrapper.exe --keypath MachineKeys.txt --encrypteddata CA387A93AD4214F356ED05C26C1E4D80F0804CD526766778B62D4F9213B87B5369755F95008A34644B9CA6B7646E191958A1AE14DB398AB943D3DB042EDA06EC4B5BEA9E3EB60E9877646AD4A50BE9435A2D3B4B3005836CBBBDA64A5E8738511211AA1F --decrypt --purpose=aspxauth --valalgo=sha1 --decalgo=aes

--encrypteddata : value to decrypt using tool
--decrypt : If you add this argumenet the tools try to decrypt the cookie
--purpose: aspxauth to decrypt the .ASPXAUTH cookie
--valalgo: Validation algorithm
--decalgo: Decryption algorithm
````
#
#
#
#### After perform decryption for .aspxauth and .aspnet.applicationcookie value, The tool was stored decryption information in "DecryptText.txt". 

#### In order to re-generate cookies for other users, It is required to update the cookie information in "DecryptText.txt" file and then run the encryption utility of the tool as shown below:
#
Sample Command
```console
AspDotNetWrapper.exe --decryptDataFilePath DecryptedText.txt

--decryptDataFilePath: Decrypted data path, which contain the plaintext information of user cookie
````
#
#
### To decode ViewState
Sample Command
```console
AspDotNetWrapper.exe --keypath MachineKeys.txt --encrypteddata /wEPDwUKLTkyMTY0MDUxMg9kFgICAw8WAh4HZW5jdHlwZQUTbXVsdGlwYXJ0L2Zvcm0tZGF0YWRkbdrqZ4p5EfFa9GPqKfSQRGANwLs= --decrypt --purpose=viewstate  --valalgo=sha1 --decalgo=aes --modifier=CA0B0334 --legacy --macdecode

--encrypteddata : __VIEWSTATE parameter value of the target application
--modifier : __VIWESTATEGENERATOR parameter value
````

#
#
### To Decrypt ViewState
Sample Command
```console
AspDotNetWrapper.exe --keypath MachineKeys.txt --encrypteddata Ve3mZjZwbMRyGTts1EV0F7Hp4eAx11qmXi45oAE7/bDDmA55+Kf9+WWACzUQtly4pRQYkMgmZJnJIDCQQhLNCWaHKbgY7dOiHn8JE7Yx19xvVhYyoqnC8ITLvHiiuJl8+LFmPJwS7ip3vAe+o7mxg2H15VUW5LO56AiTErT7UUw4Au002vflZUF6h/Fx/TJAYciUlZ8CmNW9/GIoPAC9tQ4SVhGD7is8Gu8DiUJE0AjHTLQFcy9vgSk1ovpy4gn9gl98mNVk17uCI7LLYPkvO3Xuix2WTogyqaPQOn7gJz7Say/aqqhmW90LdGo0qeldEUvMGw== --decrypt --purpose=viewstate  --valalgo=sha1 --decalgo=aes --IISDirPath "/" --TargetPagePath "/Content/default.aspx"

--encrypteddata : __VIEWSTATE parameter value of the target application
--IISDirPath : TemplateSourceDirectory
--TargetPagePath : Aspx page path
````