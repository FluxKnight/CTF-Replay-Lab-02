# `.ctflab.json` Manifest Schema

```json
{
  "schemaVersion": 1,
  "id": "ghost-tail",
  "title": "Ghost Tail",
  "category": "Forensics / Cryptography",
  "difficulty": "Medium-Hard",
  "artifactSha256": "optional 64-character SHA-256",
  "expectedFlagSha256": "required 64-character SHA-256",
  "flagFormat": "^flag\\{[^}]+\\}$",
  "hints": [
    "First hint",
    "Second hint"
  ],
  "author": "@V01d_404"
}
```

## Required fields

- `schemaVersion`: must be `1`
- `id`: stable machine-readable challenge identifier
- `title`: human-readable title
- `expectedFlagSha256`: SHA-256 of the exact plaintext flag

## Recommended fields

- `artifactSha256`: binds verification to the intended root artifact
- `flagFormat`: regular-expression format check
- `hints`: progressive guidance
- `category`, `difficulty`, `author`

## Generate one

Use **Author manifest** in the app. Enter the plaintext flag locally; the exported file stores only its hash.
