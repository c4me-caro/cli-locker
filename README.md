
# CLI Locker

A simple python CLI utility to lock/unlock folders basing on symetrical cypher of its content


## Installation

Download this repository

```bash
  git clone https://github.com/c4me-caro/cli-locker
  cd cli-locker
```
    
Install the required packages with pip

```bash
  pip Install -r requirements.txt
```
    
## Running Tests

To run tests, run the following command

```bash
  python -m unittest test_locker.py
```


## Usage

```bash
usage: locker [-h] [-r | -i] [-c | -d] [-v] [-o FILE] (-k KEY | -p) path

CLI tool to lock folders.

positional arguments:
  path                  The source directory of the lock.

options:
  -h, --help              show this help message and exit
  -r, --recursive         Lock directories and all subdirectories.
  -i, --interactive       Ask about the actions being performed.
  -c, --encrypt, --lock   Select encription mode to locker
  -d, --decrypt, --unlock Select decription mode to locker
  -v, --verbose           Show more detail about actions being performed.
  -o FILE, --output FILE  Store the log in a external file.
  -k KEY, --key KEY       The password to encrypt/decrypt data.
  -p, --password          Prompt for password input securely.
```

## Examples

Lock (encrypt) a folder recursively

```bash
python locker.py -r -c /path/to/the/folder -p
```

Unlock (decrypt) a folder interactively

```bash
python locker.py -i -d /path/to/the/folder -p
```

Save details in a log file

```bash
python locker.py -r -c -v -o log.txt /path/to/the/folder -p
```
## Deployment

To compile this project to windows/linux portable bin/exe run

```bash
  nuitka --onefile --standalone .\locker.py
```


## Contributing

Pull requests are welcome! For major changes, please open an issue first to discuss what you would like to change.
## License

This project is licensed under the [CC0](https://creativecommons.org/public-domain/cc0/) license, which means you can freely use, modify, and distribute the code, provided you retain the original copyright notice and this same license on any copies or derivative versions.