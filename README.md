# vulnlist

A command line tool to download the [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
and produce a numbered list, sorted by deadline for mitigation along with the
required action for mitigation.

## Development

```sh
gleam run   # Run the project
gleam test  # Run the tests
gleam shell # Run an Erlang shell
```
## Write cli binary

```sh
make build
```

This will produce a binary called `vulnlist` in the toplevel directory of this
project. 

## Using the tool

The vulnlist tool will query the CISA known exploited vulnerabilities catalog
and return a formatted list of those vulnerabilities along with information
about when they must be fixed (for U.S. civilian agencies and services used
by those agencies) as well as the course of action to remedy the vulnerabilities.

```
Usage: ./vulnlist [-n | --new] [ -a | --any <search_term>] [ -c | --cve <search_term>] [ -v || --vendor <search_term>]
       -n | --new                  - Only show not overdue
       -a | --any <search_term>    - Case insensitive search for search term in vendor, product, or description
       -c | --cve <search_term>    - Case insensitive search for search term in CVE ID
       -v | --vendor <search_term> - Case insensitive search for search term in CVE ID
       -h | --help                 - Show this help
```

The `-new` option shows only those vulnerabilities whose deadlines for
mitigation are approaching. `--any` takes a case insensitive term and looks
for that term in the vendor name, product name, or description. The `--cve`
flag searches for a specific portion of the CVE number. The `--vendor` option
does a case insensitive search in the vendor field.
