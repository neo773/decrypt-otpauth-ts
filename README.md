# decrypt-otpauth-ts

TypeScript version of the OTP Auth file [decryption tool](https://github.com/CooperRS/decrypt-otpauth-files). This tool allows for decrypting the encrypted backups files created by [OTP Auth for iOS](http://cooperrs.de/otpauth.html).

## Requirements

- Node.js 18+ 
- npm or yarn

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd decrypt-otpauth-ts
```

2. Install dependencies:
```bash
npm install
```

3. Build the project:
```bash
npm run build
```

## Usage
### Library
```typescript
import * as fs from "fs/promises";
import { Decryptor } from "decrypt-otpauth-ts/dist/decryptor";

const dbBuffer = await fs.readFile(dbPath);
const dbPassword = "yourpassword";
const tokens = await Decryptor.decryptBackup(dbBuffer, dbPassword);
```

### CLI
To decrypt a backup file:
```bash
node dist/cli.js decrypt-backup --encrypted-otpauth-backup <path-to-your-backup.otpauthdb>
```

The tool will:
1. Prompt for your backup file password
2. Decrypt the backup file
3. Display QR codes for each account in the backup
4. You can scan these QR codes with any authenticator app to import your accounts

## Supported File Versions

Currently supports:
- Backup files version 1.1 (.otpauthdb)

## Security

- Your password is never stored or transmitted
- All decryption happens locally on your machine
- The tool uses standard Node.js crypto libraries for decryption
