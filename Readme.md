# SecureFolder

The very creatively named program which takes a folder as an input and spits out one big combined file which includes all the files in said folder in a compressed, encoded form. Optionally, you can encrypt the files by providing the `-e` flag. This is HIGHLY RECOMMENDED as it's literally what makes the folder secure 😉

## Usage:

First, as there aren't any pre-compiled binaries available, you'll have to compile the program using the rust toolchain, like so:

`cargo build --release`

_Side note: Be sure to build in release mode, otherwise it'll be quite slow._

Now, a binary will be created inside `target/release/` called, `securefoler`. Upon executing that binary with the `-h` flag, the following help prompt will be shown:

```
Usage:
  ../target/release/securefolder [OPTIONS]

SecureFolder V0.1: Encrypt and package a given folder into one file.

Optional arguments:
  -h,--help             Show this help message and exit
  --folderpath FOLDERPATH
                        Path to the folder to be encrypted.
  --combined-file COMBINED_FILE
                        Path to the combined file to be accessed; the contents
                        will be placed in the current directory.
  -o,--output OUTPUT    Path to the output file; Beware if a file exists with
                        the same name, that the file will be shredded.
  -e,--encrypt          Use this flag if you wanna encrypt the combined file. A
                        keypair will be generated if you choose to encrypt the
                        file.
```

To actually use the program, you will first need to **create** a combined file. To do that, run the following command and replace `FOLDER_NAME` with the folder that you want to combine + encrypt and `OUTPUT_FILE` with the path to the combined file.

`securefolder --folderpath FOLDER_NAME -o OUTPUT_FILE -e`

You will now be prompted to provide a path to save the keyfile as the `-e` flag is in use. They keyfile is like your password, you must keep it in a secure place at all times and NOT lose it under any conditions as you won't be able to access your combined file without it.

After that has completed, you will be left with a combined file which will contain all the data.
To retrieve the stored inside the combined file, simply run:

`securefolder --combined-file ONEPIECEISREAL -e`

This will recreate the folder structure stored inside the file and with it, recreate all your files in the **current directory.**

### TODO/Help needed:

-   Support for larger file sizes (3-4GB+)
-   Speed improvements
-   Code improvements
