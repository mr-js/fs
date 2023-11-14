# fs
 Virtual file system with encryption support (prototype)

 ## Usage
 See examples below

 ## Examples
 Use method "store" to pack data from directory "input" to crypted container "storage" and "received" to unpack data from "storage" to directory "output":
 ```python
 from fs import PATHS, FSD, FSO

 path = os.getcwd()
 os.chdir(path)
 timer()
 fsd = FSD('', PATHS('input', 'output', 'storage'))
 timer('started')
 fsd.store()
 timer('stored')
 timer('#reset')
 fsd.receive()
 timer('received')
 timer('#reset')
 ```
 ## Remarks
 The encryption key is generated automatically and stored in a file "fs.key". Timer is used for benchmarks.
