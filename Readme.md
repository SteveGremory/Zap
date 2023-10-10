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

Using `zap archive --help` will list the available options for encryption and compression.

### In order to **decompress** a Zap archive

`zap extract [ARCHIVE] [OUTPUT]`

Where the `[ARCHIVE]` is the path to the file which you want to extract and the `[OUTPUT]` is the folder in which you want the contents to be placed inside.

Using `zap archive --help` will list the available options for encryption and compression.

Unfortunately, in it's current state, that compression and encryption methods aren't stored in metadata and must be given when extracting. this will be fixed in coming releases.

### In order to **list** the contents of a Zap archive

`zap list [ARCHIVE]`

*coming soon*

## License

This project is licensed under the LGPL v3.

See [LICENSE.md](/LICENSE.md) file for details.

![LGPL v3 Logo](https://www.gnu.org/graphics/lgplv3-with-text-154x68.png)

Note that Zap is still alpha software and is bound to change core features until version 0.5.0
