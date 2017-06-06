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

I added a makefile for OSX. Since i don't have a windows development machine at hand, i am not providing
a windows build currently.

Make sure the dlls from the `dlls` directory are somewhere in the search path. They are needed for decompression.


author
======

(C) 2003-2013 Willem Hengeveld <itsme@xs4all.nl>

