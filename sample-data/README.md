# Sample data (synthetic)

Exported from `demo/aegis_demo/data.py` and `catalog.py` (regenerate rather than edit by hand).
All names are fictional; BSNs pass the 11-proof and IBANs pass mod-97 only so that the PII recognizers
treat them as real-looking values. No client, confidential or personal data is used anywhere.

- `customers.json` – demo customers and the landlord IBAN used in scene S3
- `documents.json` – D-77 (passport scan) and D-99 (rental contract with an embedded prompt injection, scene S4)
- `catalog.json` – tool classifications and agent manifests ("agents and tools as code")
