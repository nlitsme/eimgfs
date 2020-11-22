eimgfs
======

`eimgfs` is a tool for creating, decoding, viewing and modifying Windows CE firmware images.

I am re-releasing it here on github. Originally this was posted as part of the itsutils package
on xda-developers.

These formats are supported:

 * motorola flash.bin
 * htc (signed) .nbh
 * partitiontable with xips+imgfs
 * plain xip
 * compressed xip
 * plain imgfs

To be able to compress/decompress files it must either run on windows, or as a 32bit binary on osx.

This used to be part of the itsutils distribution.

History
=======

I started developing this tool as `dumprom` in 2003 for xda-developers.
Later converted to perl. And Later again, when WindowsCE started
using the `imgfs` filesystem, converted to c++, now named `eimgfs`. Which stads for 'Edit imgfs'.

Several older tools with similar functionality: `dumpxip.pl`, `makexip.pl`, `editimgfs.pl`.

Usage
=====

    Usage: editimgfs imgfile [operations]

You can specify as many operations as needed.

main options:

| option  |  arguments  | description
| :-----  |  :--------- |  :-----------
| -v          |               | verbose
| -r          |               | readonly
| -d path     |               | where to save extrated files to
| -s SIZE     |               | specify totalsize ( for motorola FLASH )
| -extractall |               | extract all to '-d' path
| -list       |               | list all files
| -info       |               | list available readers/filesystems
| -filter     | <EXE|SIGNED>  | only exe or signed binaries
| -resign     |               | update nbh sigs after modifications
| -keyfile    | KeyFile       | nbh key file
| -extractnbh |               | extract SPL/IPL/OS images from nbh

READER operations:

| option  |  arguments  | description
| :-----  |  :--------- |  :-----------
| -rd         | RdName         | specify reader to operate upon
| -saveas     | Outfile        | save entire rd section
| -getbytes   | offset size Outfile  |
| -putbytes   | offset size Infile   |
| -hexdump    | offset size          |
| -chexdump   | {XPR|XPH|LZX|XIP|ROM} offset size fullsize | dump compressed
| -hexedit    | offset bytes...      |

FILESYSTEM operations:

| option  |  arguments  | description
| :-----  |  :--------- |  :-----------
| -fs         | FsName           | specify fs to operate upon
| -add        | RomName[=srcfile] ...  | adds a list of files
|             |                  |  you can also add all files from a directory
| -del        | RomName          |
| -ren        | RomName=NEWNAME  |
| -extract    | RomName=dstfile  |
| -fileinfo   | RomName          | print detailed info about file
| -dirhexdump |                  | for debugging


Example
=======

An example, how i have used this tool:

    eimgfs -s 0x10000000  therom.nb \
           -fs imgfs -del delfiles -add files \
           -fs xip23 -del delfiles-xip23 -add files-xip23 \
           -fs xip20 -del delfiles-xip20 -add files-xip20

This will alter `therom.nb`, increasing its maximum size to 256Mbyte, deleting files from the `imgfs`, `xip20`, `xip23` partition 
for the names found in the respective `delfiles-...` directories, and adding files from the `files-...` directories.


Building
========

There are makefiles for OSX and Windows.
Both depend on the presence of 32 bit libraries for boost and openssl.

Make sure the dlls from the `dlls` directory are somewhere in the search path. They are needed for decompression.

You can build `eimgfs` with OSX SDK up to version 10.13, version 10.14 no longer includes the 32 bit libraries needed.

Docker is supported. Multistage building is used. Stage `run` should be used for actual executing the application. Entrypoint is configured as well.

```
docker build --target run .
docker run -v /home/user/images:/app/data --rm -ti ef7b7abd7b4d -fs xip -fileinfo /app/data/FILENAME
```

On linux, you may need to install g++-multilib and 32bit binaries for openssl.

author
======

(C) 2003-2013 Willem Hengeveld <itsme@xs4all.nl>

