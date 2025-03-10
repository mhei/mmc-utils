.. SPDX-License-Identifier: GPL-2.0-only

Running mmc-utils
-----------------
**Name**
    mmc - a tool for configuring MMC storage devices
**Synopsis**
    ``mmc [options] [mmc-block-device]...``
**Description**
    *mmc-utils* is a single-threaded tool that will perform a specified type of mmc action as specified by the user.
    The typical use of mmc-utils is to access the mmc device either for configuring or reading its configuration registers.
**Options**
    ``help | --help | -h | (no arguments)``
        Shows the abbreviated help menu in the terminal.

**Commands**
    ``extcsd read <device>``
        Print extcsd data from <device>.

    ``extcsd write <offset> <value> <device>``
        Write <value> at offset <offset> to <device>'s extcsd.

    ``writeprotect boot get <device>``
        Print the boot partitions write protect status for <device>.

    ``writeprotect boot set [-p] <device> [<number>]``
        Set the boot partition write protect status for <device>.
        If <number> is passed (0 or 1), only protect that particular eMMC boot partition, otherwise protect both. It will be write-protected until the next boot.
        -p  Protect partition permanently instead. NOTE! -p is a one-time programmable (unreversible) change.

    ``writeprotect user get <device>``
        Print the user areas write protect configuration for <device>.

    ``writeprotect user set <type> <start block> <blocks> <device>``
        Set user area write protection.

    ``csd read  [-h] [-v] [-b bus_type] [-r register]  <device path>``
        Print CSD data from <device path>. The device path should specify the csd sysfs file directory.
        if [bus_type] is passed (mmc or sd) the [register] content must be passed as well, and no need for device path.
        it is useful for cases we are getting the register value without having the actual platform.

    ``cid read <device path>``
        Print CID data from <device path>. The device path should specify the cid sysfs file directory.
        if [bus_type] is passed (mmc or sd) the [register] content must be passed as well, and no need for device path.
        it is useful for cases we are getting the register value without having the actual platform.

    ``scr read <device path>``
        Print SCR data from <device path>. The device path should specify the scr sysfs file directory.
        if [bus_type] is passed (mmc or sd) the [register] content must be passed as well, and no need for device path.
        it is useful for cases we are getting the register value without having the actual platform.

    ``ffu <image name> <device> [chunk-bytes]``
      Default mode.  Run Field Firmware Update with `<image name>` on `<device>`. `[chunk-bytes]` is optional and defaults to its max - 512k. Should be in decimal bytes and sector aligned.

    ``opt_ffu1 <image name> <device> [chunk-bytes]``
      Optional FFU mode 1, it's the same as 'ffu', but uses CMD23+CMD25 for repeated downloads and remains in FFU mode until completion.

    ``opt_ffu2 <image name> <device> [chunk-bytes]``
      Optional FFU mode 2, uses CMD25+CMD12 Open-ended Multiple-block write to download and remains in FFU mode until completion.

    ``opt_ffu3 <image name> <device> [chunk-bytes]``
      Optional FFU mode 3, uses CMD24 Single-block write for downloading, exiting FFU mode after each block written.

    ``opt_ffu4 <image name> <device> [chunk-bytes]``
      Optional FFU mode 4, uses CMD24 Single-block write for repeated downloads, remaining in FFU mode until completion.


    ``erase <type> <start address> <end address> <device>``
        Send Erase CMD38 with specific argument to the <device>. NOTE!: This will delete all user data in the specified region of the device. <type> must be one of: legacy, discard, secure-erase, secure-trim1, secure-trim2, or trim.

    ``gen_cmd read <device> [arg]``
        Send GEN_CMD (CMD56) to read vendor-specific format/meaning data from <device>. NOTE!: [arg] is optional and defaults to 0x1. If [arg] is specified, then [arg] must be a 32-bit hexadecimal number, prefixed with 0x/0X. And bit0 in [arg] must be 1.

    ``lock <parameter> <device> [password] [new_password]``
        Usage: mmc lock <s|c|l|u|e> <device> [password] [new_password]. <password> can be up to 16 character plaintext or hex string starting with 0x. s=set password, c=clear password, l=lock, sl=set password and lock, u=unlock, e=force erase.

    ``softreset <device>``
        Issues a CMD0 softreset, e.g., for testing if hardware reset for UHS works.

    ``preidle <device>``
        Issues a CMD0 GO_PRE_IDLE.

    ``boot_operation <boot_data_file> <device>``
        Does the alternative boot operation and writes the specified starting blocks of boot data into the requested file. Note some limitations: The boot operation must be configured, e.g., for legacy speed. The MMC must currently be running at the bus mode that is configured for the boot operation (HS200 and HS400 not supported at all). Only up to 512K bytes of boot data will be transferred. The MMC will perform a soft reset, if your system cannot handle that do not use the boot operation from mmc-utils.



    ``mmc rpmb write-block <rpmb device> <address> <256 byte data file> <key file>``
        Writes a block of data to the RPMB partition.

    ``mmc rpmb read-counter <rpmb device>``
        Reads the write counter from the RPMB partition.

    ``mmc rpmb read-block <rpmb device> <address> <blocks count> <output file> [key file]``
        Reads blocks of data from the RPMB partition.
