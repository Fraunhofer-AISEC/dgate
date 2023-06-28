#!/bin/bash

[ -z "$1" ] && echo "Provide target IP!" && exit 1
[ -z "$2" ] && echo "Provide value delimiter for log!" && exit 2

echo "### Benchmarking $1 ###"

for r in 10 100 1000 10000
do
  echo ""
  echo "Logging to file $1_$r.log ($r repetitions) with delimiter \"$2\""
  for i in {1..100}
  do
    printf "\r\033[K%d repetitions, probe %d/100..." "$r" "$i"
    echo -n "$(curl --request GET \
      --url "http://$1:10000/init-attestation" \
      --header 'Content-Type: application/json' \
      --data '{
            "repetitions": '"$r"',
            "targetEndpoint": "localhost:10000",
            "targetPublicKeyPem": "LS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JSUNJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBZzhBTUlJQ0NnS0NBZ0VBdzRvRW9qZ3k0SUxKRGpaZElYamoKU1ZEV3picVllYUxhc2k3N1lYODRFVmh1MVo5TnREWGxTTWhadTQxaUN1a2J2cm1ER0Zubm5od0N0dUlvWVh2OApJTVFOQnFhN0k0bnNTa2VqUWxleXZ0NGJFQ2xUOTVpQ1NyME1sWnpHOCt4aXhHVDlVSHFrTGpMOVVsaE5PR05hCnQ0VHhVZXMrdlZ4VXJOWnFQMW1tem44UjNTYWU3UUF0NVBURlMzYytPSXBXUm55RzNtNC8rYTlmUGpWeTB5SGIKVldsRU8wWWNJSnFaVjdGMGJFdHlmd3duaFlYOFRaRzRSMTdlajBWRDBaME9WU2J1c1dzeGdLRHU3Ykl5TDNHawpKekx4NGFlTWdJdEV5SnFMRzlxUVJYNE9nOUtLa2QzdjRjSFJqV1M3ZklLUjdYQ3VJNWQrYVZJTktVY1R6Z3BpCmR2aytZNFZRUVBUNjZKenRKSGlxV3lVbks5SVdNZnFxYUZJNnNXTWpQd2tRVVFQWFNETFc5WXZpZEEyczZaQncKN09TR2RpazBlSlNha01mV2psbHBYaExCWndpdG9JUUd2MVFSakNGcE12MVhueEhqWTJrcmw2RERRNkpSY2ZDKwp0MVgvNS8zSE9UcllTNjdCTmQ0S2lXRGJQWXRIUzJIOHdZMVF6ZmZOeE5aOTBBeTR0cEY3YXVFOFFOcldxZGR5CmFtZmtIK2daa0xleURHdXhjc01maTNsYlFkR2VwbDBmR3BFNFpBcURnTW41Mzc3Q3hWZGRwckJSUDNjNS9oRWIKQWRpWlN5VEI1UmRTbUJpMjZFcGlKcW1vODE0bURHcUlnV1VSYjhYUzRjQ1Q4RnJ1c28vZVp6K0JrUjhNaDR2Vgp5Q3kzb3BUOEJpRXVVM1dKSWpRSmlYOENBd0VBQVE9PQotLS0tLUVORCBSU0EgUFVCTElDIEtFWS0tLS0t"
    }' 2>/dev/null | jq .MeasuredDelay)$2" >>"$1_$r.log"
  done
done