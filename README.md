# vulnlist

A command line tool to download the [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
and produce a numbered list, sorted by deadline for mitigation along with the
required action for mitigation.

## Install

To install using bun run the command below. This will install the `vulnlist`
binary in your bun path. Only [bun](https://bun.sh/) is required for this
installation method.

```
bun install -g https://code.unnecessary.tech/devries/vulnlist/releases/download/v1.1.1/vulnlist-1.1.1.tgz
```

## Create a cli binary

You can compile a binary using the command `make build` provided you have
already installed [bun](https://bun.sh/), and [gleam](https://gleam.run/).
This will produce a binary called `vulnlist` in the toplevel directory of this
project.

The `make install` command will install the binary, either to your `$HOME/.local/bin`
directory, or if you are root it will install to `/usr/local/bin`.

## Using the tool

The vulnlist tool will query the CISA known exploited vulnerabilities catalog
and return a formatted list of those vulnerabilities along with information
about when they must be fixed (for U.S. civilian agencies and services used
by those agencies) as well as the course of action to remedy the vulnerabilities.

```
Usage: vulnlist [-n | --new] [ -a | --any <search_term>] [ -c | --cve <search_term>] [ -v || --vendor <search_term>]
                  [-d | --added] [-f | --fetch] [-V | --verbose]
       -n | --new                  - Only show not overdue
       -a | --any <search_term>    - Case insensitive search for search term in vendor, product, or description
       -c | --cve <search_term>    - Case insensitive search for search term in CVE ID
       -v | --vendor <search_term> - Case insensitive search for search term in CVE ID
       -d | --added                - Sort by date added
       -f | --fetch                - Force data refresh
       -V | --verbose              - Verbose output
       -h | --help                 - Show this help
```

The `--new` option shows only those vulnerabilities whose deadlines for
mitigation are approaching. `--any` takes a case insensitive term and looks
for that term in the vendor name, product name, or description. The `--cve`
flag searches for a specific portion of the CVE number. The `--vendor` option
does a case insensitive search in the vendor field.
