# Zap

Compress and/or encrypt folders fast. Like, really fast.
or as some say, **blazingly** fast.

## Installation

To install Zap, run the following command from the project root:
`cargo install --path .`

## Usage

### In order to **compress** a folder with Zap, run:

`zap FOLDER_TO_ZAP PATH_TO_ZAP_FILE`

Where the `PATH_TO_ZAP_FILE` is the path to which you wanna store the `.zap` file.

-   The zap file can optionally be encrypted with by providing the `-e` flag. A `keyfile.zk` containing the "password" (keys) will be generated in the current folder.

### In order to **decompress** a folder with Zap

`zap PATH_TO_ZAP_FILE FOLDER_TO_UNZAP_INTO`

Where the `PATH_TO_ZAP_FILE` is the path to the file which you wanna unzap and the `FOLDER_TO_UNZAP_INTO` is the folder in which you want the contents to be placed inside.

-   If the Zap file was encrypted, the `-e` flag needs to be provided along with the `keyfile.zk` which was generated upon zapping.

## License

This project is licensed under the LGPL v3.

See [LICENSE.md](/LICENSE.md) file for details.

![LGPL v3 Logo](https://www.gnu.org/graphics/lgplv3-with-text-154x68.png)

Note that Zap is still alpha software and is bound to change core features until version 0.5.0
