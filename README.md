# fs
 Virtual file system with encryption support (AES-128)

 ## Features

 - Dependency-free: native, no third-party packages to install to work with the file system and encryption!
 - Saving and checking the checksum for each file during packing (encryption) and extraction (decryption)
 - Support for data compression and automatic partitioning of virtual file storage into volumes

![fs](/images/fs-0.png)

![fs](/images/fs-1.png)

![fs](/images/fs-2.png)

 ## Usage
 See examples below

 ## Examples

 Store all files from [```input```](temp/input/) to the encrypted virtual filesystem [```storage```](temp/storage/) and receive them back to [```output```](temp/output/).
  
 ```python
 from fs import FSD
 
 # demo init
 fsd = FSD('password', root='temp', input='input', output='output', storage='storage', volume=1024)
 # file system conversion, packaging and encryption
 fsd.store()
 # decryption, decompression and file system conversion
 fsd.receive()
 ```


 ## Remarks
 - If no password is specified, the encryption key is generated automatically and stored in the file ```fs.key```.
 - You can also set the volume size of the virtual file system: in this case, the storage will be automatically partitioned (param ```volume```, MB).
