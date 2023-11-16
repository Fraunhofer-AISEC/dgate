# Information

This is a repository which contains a proof-of-concept implementation for the published paper called "D-GATE: Decentralized Geolocation and Time Enforcement for Usage Control" published 2023 in a IEEE European Symposium on Security and Privacy Workshop (EuroS&PW). For details please refer to our paper. 

# Start instructions

Start a node via:
```bash
cd go-code
go run . 
```
Should show something like "Ready!"

In another terminal, launch the time measurement and signature process using this `curl` command:
```bash
curl --request GET \
  --url http://localhost:10000/init-attestation \
  --header 'Content-Type: application/json' \
  --data '{
	"repetitions": 1000,
	"targetEndpoint": "localhost:10000",
	"targetPublicKeyPem": "LS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JSUNJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBZzhBTUlJQ0NnS0NBZ0VBdzRvRW9qZ3k0SUxKRGpaZElYamoKU1ZEV3picVllYUxhc2k3N1lYODRFVmh1MVo5TnREWGxTTWhadTQxaUN1a2J2cm1ER0Zubm5od0N0dUlvWVh2OApJTVFOQnFhN0k0bnNTa2VqUWxleXZ0NGJFQ2xUOTVpQ1NyME1sWnpHOCt4aXhHVDlVSHFrTGpMOVVsaE5PR05hCnQ0VHhVZXMrdlZ4VXJOWnFQMW1tem44UjNTYWU3UUF0NVBURlMzYytPSXBXUm55RzNtNC8rYTlmUGpWeTB5SGIKVldsRU8wWWNJSnFaVjdGMGJFdHlmd3duaFlYOFRaRzRSMTdlajBWRDBaME9WU2J1c1dzeGdLRHU3Ykl5TDNHawpKekx4NGFlTWdJdEV5SnFMRzlxUVJYNE9nOUtLa2QzdjRjSFJqV1M3ZklLUjdYQ3VJNWQrYVZJTktVY1R6Z3BpCmR2aytZNFZRUVBUNjZKenRKSGlxV3lVbks5SVdNZnFxYUZJNnNXTWpQd2tRVVFQWFNETFc5WXZpZEEyczZaQncKN09TR2RpazBlSlNha01mV2psbHBYaExCWndpdG9JUUd2MVFSakNGcE12MVhueEhqWTJrcmw2RERRNkpSY2ZDKwp0MVgvNS8zSE9UcllTNjdCTmQ0S2lXRGJQWXRIUzJIOHdZMVF6ZmZOeE5aOTBBeTR0cEY3YXVFOFFOcldxZGR5CmFtZmtIK2daa0xleURHdXhjc01maTNsYlFkR2VwbDBmR3BFNFpBcURnTW41Mzc3Q3hWZGRwckJSUDNjNS9oRWIKQWRpWlN5VEI1UmRTbUJpMjZFcGlKcW1vODE0bURHcUlnV1VSYjhYUzRjQ1Q4RnJ1c28vZVp6K0JrUjhNaDR2Vgp5Q3kzb3BUOEJpRXVVM1dKSWpRSmlYOENBd0VBQVE9PQotLS0tLUVORCBSU0EgUFVCTElDIEtFWS0tLS0t"
}'
```

You may control measurement parameters via the passed JSON structure.
