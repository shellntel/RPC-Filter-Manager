# RPC-Filter-Manager
Simple tool to manage RPC filters relevant to coercion attacks.

Currently impliments a filter like the following. 
```
rpc filter
add rule layer=um actiontype=block filterkey=df1941c5-fe89-4e79-bf10-463657acf44d
add condition field=if_uuid matchtype=equal data=df1941c5-fe89-4e79-bf10-463657acf44d
add filter
```
For awareness it is possible to add conditions by auth type and by domain group.


```
 RPC Filter Management Script
---------------------------
This script helps manage RPC interface filters for security hardening.

Commands:
    -b, -block   : Block RPC interfaces (use with -i to block specific interface)
    -a, -allow  : Permit RPC interfaces (must be used with -i)
    -l, -list    : Show currently blocked interfaces
    -r, -remove  : Removes all RPC filters !!!Use with caution!!!
    -i           : Specify interface to block/permit (use with -b or -a)
    -h, -help    : Show this help

Available Interfaces:

    MS-RPRN   : Printer Bug                      [12345678-1234-abcd-ef00-0123456789ab] 
    MS-DFSNM  : DFS Coerce                       [4fc742e0-4a10-11cf-8273-00aa004ae673] 
    MS-FSRVP  : Shadow Coerce                    [a8e0653c-2744-4389-a61d-7373df8b2292] 
    MS-EFSRPC-2: PetitPotam                       [df1941c5-fe89-4e79-bf10-463657acf44d] 
    MS-PAR    : IRemoteWinspool                  [76F03F96-CDFD-44FC-A22C-64950A001209] 
    MS-EVEN   : Cheese Ounce                     [82273fdc-e32a-18c3-3f78-827929dc23ea] 
    MS-EFSRPC-1: PetitPotam                       [c681d488-d850-11d0-8c52-00c04fd90f7e]

Usage:
    ./Coercion-Filters.ps1 -h                 : Show this help
    ./Coercion-Filters.ps1 -b                 : Block all interfaces
    ./Coercion-Filters.ps1 -b -i MS-RPRN     : Block specific interface
    ./Coercion-Filters.ps1 -a -i MS-RPRN     : Set Permit on specific interface and enable auditing.
    ./Coercion-Filters.ps1 -l                 : List blocked interfaces
    ./Coercion-Filters.ps1 -r                 : Remove all filters 

```
