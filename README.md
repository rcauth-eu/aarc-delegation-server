# aarc-delegation-server

This is a custom
[OA4MP](http://grid.ncsa.illinois.edu/myproxy/oauth/server/index.xhtml)
implementation for AARC
[Pre-Piloting Work](https://wiki.nikhef.nl/grid/AARC_Pilot)
in particular for the
[RCauth.eu online CA](https://wiki.nikhef.nl/grid/AARC_Pilot_-_RCAuth.eu).

## Delegation Server

The Delegation Server is used as a frontend for the
[RCauth.eu](http://rcauth.eu/) Online CA. It takes care of providing user
certificates for authenticated users via a registered and trusted
[Master Portal](https://github.com/rcauth-eu/aarc-master-portal). 

## Building

In case you wish the build the Delegation Service you should first build two of
its dependencies in the following order 

1. [security-lib](https://github.com/rcauth-eu/security-lib)
2. [OA4MP](https://github.com/rcauth-eu/OA4MP)

See [AARC Pilot - Building from Source](https://wiki.nikhef.nl/grid/AARC_Pilot_-_Building_from_Source) for further details.

## Other Resources

If you are looking for a client that talks to the Delegation Server check out
the [Master Portal](https://github.com/rcauth-eu/aarc-master-portal).
