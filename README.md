# fs
 Virtual file system with encryption support (prototype)

 ## Features

 Dependency-free (native, no third-party packages to work with the file system and encryption)!

![fs](/images/fs-0.png)

![fs](/images/fs-1.png)

![fs](/images/fs-2.png)

 ## Usage
 See examples below

 ## Examples

 Save all files from [temp/input/](temp/input/) to the encrypted [temp/storage/](temp/storage/) virtual file system and decrypt back to [temp/output/](temp/output/)
  
 ```python
 from fs import FSD
 
 # demo init (auto pass gen)
 fsd = FSD()
 # file system conversion, packaging and encryption
 fsd.store()
 # decryption, decompression and file system conversion
 fsd.receive()
 ```

 > [!NOTE]
 > Right now only small files are supported in experimental mode (e.g. as in the demo [test.txt](/temp/input/test.txt)).

 ## Remarks
 The encryption key is generated automatically and stored in a file "fs.key".
