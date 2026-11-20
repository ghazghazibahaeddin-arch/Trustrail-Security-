# Trustrail Security Cloud Python SDK

Standard-library Python 3 client (`urllib.request`) with zero external dependencies.

## Quickstart

```python
from sdk.python.trustrail_client import TrustrailClient

client = TrustrailClient("http://127.0.0.1:3000")
client.login("sarah@acme.cloud", "Trustrail!2026")

posture = client.get_organization()
findings = client.list_findings(severity="CRITICAL")
intel = client.query_intel(cve_ids=["CVE-2021-44228"])
events = client.list_fabric_events(limit=25)
```
