# Zap

Compress and/or encrypt folders fast. Like, really fast.
or as some say... **blazingly** fast.

## Installation

To install Zap, run the following command from the project root:
`cargo install --path .`

## Usage

### In order to **compress** a folder with Zap, run:

`zap archive [INPUT] [OUTPUT]`

Where the `[OUTPUT]` is the path to which you want to store the `.zap` file.

-   The zap file can optionally be encrypted with by providing the `-e` flag and choosing `password` or `key`. Note that `key` method is not supported yet.

### In order to **decompress** a Zap archive

`zap extract [ARCHIVE] [OUTPUT]`

Where the `[ARCHIVE]` is the path to the file which you want to extract and the `[OUTPUT]` is the folder in which you want the contents to be placed inside.

-   If the Zap file was encrypted, the `-e` flag needs to be provided along with the correct encryption method. *This will hopefully be resolved in future versions*

### In order to **list** the contents of a Zap archive

`zap list [ARCHIVE]`

*coming soon*

## License

This project is licensed under the LGPL v3.

See [LICENSE.md](/LICENSE.md) file for details.

![LGPL v3 Logo](https://www.gnu.org/graphics/lgplv3-with-text-154x68.png)

Note that Zap is still alpha software and is bound to change core features until version 0.5.0
