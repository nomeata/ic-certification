
To call a function that returns a Blob, and decode as binary, one can use something like this
```
dfx canister call merkle-tree-demo fetch_whoami_request '()' |cut -c7- |head -c-2|perl -npe '/.*"(.*)".*/; $_=$1; s/\\(..)/pack ("H*",$1)/ge'
```
To then post it to to the local replica, pipe into:
```
curl -i -X POST -H 'content-type: application/cbor' --data-binary @- http://127.0.0.1:4943/api/v2/canister/$(dfx canister id merkle-tree-demo)/query
```
