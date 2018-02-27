# AzureSasToken
MS Azure Shared Access Signature Token Generator for MicroPython

Usage :
```python
from AzureSasToken import generateAzureSasToken
token = generateAzureSasToken(uri, key, expiryTimestamp, policy_name=None)
```
