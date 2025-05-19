
# CLI Locker

A simple python CLI utility to lock/unlock folders basing on symetrical cypher of its content


## Usage

```bash
usage: locker [-h] [-r | -i] [-c | -d] [-v] [-o FILE] path key

CLI tool to lock folders.

positional arguments:
  path                  The source directory of the lock.
  key                   The password to encrypt/decrypt data.

options:
  -h, --help            show this help message and exit
  -r, --recursive       Lock directories and all subdirectories.
  -i, --interactive     Ask about the actions being performed.
  -c, --encrypt, --lock
                        Select encription mode to locker
  -d, --decrypt, --unlock
                        Select decription mode to locker
  -v, --verbose         Show more detail about actions being performed.
  -o FILE, --output FILE
                        Store the log in a external file.
```
## License

This project is licensed under the [CC0](https://creativecommons.org/public-domain/cc0/) license, which means you can freely use, modify, and distribute the code, provided you retain the original copyright notice and this same license on any copies or derivative versions.
