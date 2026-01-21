# Drat (formerly apfs-tools)

Drat is a tool for analysing and recovering data from [APFS (Apple File System)](https://en.wikipedia.org/wiki/Apple_File_System)
partitions. Its creation was inspired by a [personal data loss incident](https://apple.stackexchange.com/questions/373718)
and [Jonathan Levin's](https://twitter.com/Morpheus______) closed-source
`fsleuth` tool, which he demonstrated in [this lecture](http://docs.macsysadmin.se/2018/video/Day4Session2.mp4).

The name "Drat" is a loose acronym for "Disaster Recovery APFS Tools", and a bad
pun on how one might say "drat!" after discovering that their data is corrupted.

This software is currently in development, and is being implemented with reference
to [Apple's official APFS specification (PDF)](https://developer.apple.com/support/downloads/Apple-File-System-Reference.pdf).
Copies of various versions of this spec are included in the `spec` directory for
archival purposes, particularly in case the online version of the document changes.

Currently, all of Drat's commands (except `modify`, which is currently disabled
as it is not fit for use) operate in a read-only fashion, as they are intended
to be used in situations involving data recovery or data forensics.

### Running the software

If you're using an Intel machine that's running macOS or Linux, you can find
binaries for versioned releases on the [releases page](https://github.com/jivanpal/drat/releases).

Documentation for versioned releases and as generated from the `main` branch
[can be viewed online](https://drat.readthedocs.io/).

### Command-line usage

General syntax:

```
drat [global options] <command> [command options]
```

Global options:

- `--container <path>` (required): APFS container device or image.
- `--block-size <size|auto>`: APFS block size in bytes (default `auto`).
- `--volume <index>`: APFS volume index.
- `--volume-name <name>`: APFS volume name.
- `--max-xid <xid>`: maximum transaction ID.

Commands:

- `inspect`
  - Usage: `drat inspect --container <container> [--no-cksum]`
  - Prints container and checkpoint metadata.

- `read`
  - Usage: `drat read --container <container> --block <block address>`
  - Reads a block and prints decoded structure info.

- `explore-omap-tree`
  - Usage: `drat explore-omap-tree --container <container> --omap <omap tree root node address>`
  - Walks and prints an object map B-tree.

- `explore-fs-tree`
  - Usage: `drat explore-fs-tree --container <container> --fs <fs tree root node address> --omap <omap tree root node address>`
  - Walks and prints a filesystem B-tree.

- `list`
  - Usage:
    - `drat list --container <container> --volume <volume index> --fsoid <filesystem object ID>`
    - `drat list --container <container> --volume <volume index> --path <file/directory path>`
  - Lists directory entries or file metadata by FSOID or path.

- `resolver`
  - Usage: `drat resolver --container <container> --volume <volume index> --oids <oid[,oid...]>`
  - Options:
    - `--omap <omap tree addr>`: supply a specific omap root instead of using `--volume`.
    - `--oids <oid[,oid...]>` or `--oid <oid>` (repeatable alias).
  - Resolves Virtual OIDs to Physical OIDs.

- `search`
  - Usage: `drat search --container <container> [options]`
  - Options:
    - `--start <block addr>` / `--end <block addr>`: scan range (inclusive/exclusive).
    - `--dentry-name <name[,name...]>`: dentry name filters.
    - `--dentry-oid <oid[,oid...]>`: dentry file-id filters.
    - `--dentry-oid-range <start-end>`: dentry file-id ranges.
    - `--scan-omap`: scan omap leaf nodes.
    - `--omap-oid-range <start-end>`: omap OID ranges.
    - `--scan-virtual`: scan virtual objects.
    - `--virtual-oid <oid[,oid...]>`: virtual OID filters.
    - `--no-cksum`: skip checksum validation.
    - `--matches-only`: only print matches (suppress full listing).
    - `--export <path>`: write CSV results (see below).
  - Default behavior scans the whole container and prints dentries.

- `recover`
  - Metadata-based recovery (requires intact trees):
    - `drat recover --container <container> --volume <volume index> --fsoid <filesystem object ID>`
    - `drat recover --container <container> --volume <volume index> --path <file path>`
  - Recovery from search export:
    - `drat recover --container <container> --from-search <export.csv> --file-id <file-id> [--output <path>]`
    - `drat recover --container <container> --from-search <export.csv> --name <file name> [--output <path>]`
  - Raw extent scan (metadata-missing mode):
    - `drat recover --container <container> --scan-extents --file-id <file-id> [--start <block>] [--end <block>] [--output <path>] [--no-cksum]`
  - Options:
    - `--output <path>`: output file path (use `-` for stdout; if a directory, a file is created inside).
    - `--skip-multilinked-inodes`: recover multi-linked files as empty files.

- `version`
  - Usage: `drat version`
  - Prints version, license, and warranty info.

Notes:

- Numerical arguments accept decimal, hex (`0x`), or octal (`0`) formats.
- `modify` exists in the source tree but is currently disabled and not exposed as a command.
- `search --export` writes CSV with columns:
  - `type,block_addr,node_oid,node_xid,file_id,name,logical_addr,phys_block,length_bytes`

### Compiling the software

#### Requirements

- GNU C Compiler (`gcc`) — Required because we use `__attribute__((packed))`. 

- GNU Make (`make`).

- GNU Argp library (`<argp.h>`) — Part of the GNU C Library (glibc):

  - On Ubuntu, ensure that the package `libc6-dev` is installed.
  
  - On macOS, you can install just Argp via the [Homebrew](https://brew.sh)
    package `argp-standalone`. The Makefile will handle this configuration
    automatically. If you acquire Argp any other way, such as by installing
    glibc in its entirety, you may need to configure `CFLAGS` and `LDFLAGS` as
    appropriate.

#### Instructions

- Ensure that `gcc` is in your `$PATH`, or configure `CC` and `LD` as appropriate.
  
- Run `make` from the project root (where this `README.md` file resides). An
  `out` directory will be created in which the object files will be stored. The
  final binary `drat` will be stored in the project root.

- Run `make clean` to remove the compiled binary (`drat`) and other output files
  (`out` directory).

#### Tested platforms

Compilation and execution has been tested on the following platforms:

- macOS Catalina 10.15.7 (19H524) on an Intel x86-64 machine (MacBookPro9,2), using:

  - GCC 11.2.0 (Homebrew GCC 11.2.0)
  - GNU Make 3.81 (as included in Xcode Command Line Tools)
  - Homebrew package `argp-standalone`, version 1.3

- Ubuntu 20.04.3 on an Intel x86-64 machine (Intel Core i5-4288U), using:

  - GCC 9.3.0
  - GNU Make 4.2.1
  - GNU C Library (glibc) 2.31

### Generating the documentation

[Sphinx](https://www.sphinx-doc.org/en/master/) is used to manage the
documentation. This facilitates usage of [Read the Docs](https://readthedocs.org/),
which hosts the documentation online for you to read easily, both for all
versioned releases and as generated from the `main` branch.

We use a variant of Markdown called [MyST](https://myst-parser.readthedocs.io/en/latest/)
that supports all of the features of reStructuredText.

#### Requirements

Sphinx requires Python and its `sphinx` package. We also require the
Read the Docs theme (`sphinx_rtd_theme`) and the MyST parser (`myst-parser`).
If/when you have Python installed, you can install the required packages all at
once with the following: `pip install sphinx sphinx_rtd_theme myst-parser`.

<!-- TODO: Use pip requirements file instead -->

#### Instructions

- From the project root (the directory where this `README.md` file resides):

  - Run `make docs` to generate HTML documentation in `docs/_build/html`.
    Open `docs/_build/html/index.html` in your browser to view the generated
    documentation.

  - Run `make clean-docs` to remove the generated documentation (`docs/_build`
    directory).

- From the `docs` directory:

  - Run `make <format>` to generate the documentation in a format other than
    HTML, where `<format>` is any of the formats listed in the output of
    `make help`. You may need to install other software to generate
    documentation in these other formats.

  - Run `make clean` to remove the generated documentation.
