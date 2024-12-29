import { Command } from "commander";
import { readFileSync } from "fs";
import { createInterface } from "readline";
import { Decryptor, OTPAccount, Type } from "./decryptor";
import qrcode from "qrcode-terminal";

const program = new Command();

const promptPassword = async (filePath: string): Promise<string> => {
  const rl = createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  return new Promise((resolve) => {
    rl.question(`Password for export file ${filePath}: `, (password) => {
      rl.close();
      resolve(password);
    });
  });
};

const displayQRCode = (account: OTPAccount): Promise<void> => {
  return new Promise((resolve) => {
    const uri = Decryptor.generateOTPUri(account);
    console.log(`${account.type}: ${account.issuer} - ${account.label}`);
    qrcode.generate(uri, { small: true }, (qr) => {
      console.log("\n");
      console.log(qr);
      resolve();
    });
  });
};

const decryptBackup = async (filePath: string, debug: boolean, password: string, json: boolean) => {
  try {
    if (debug) {
      console.log("Reading file:", filePath);
    }
    const encryptedData = readFileSync(filePath);

    if (debug) {
      console.log("File size:", encryptedData.length, "bytes");
    }

    const archivePassword = password ?? await promptPassword(filePath);

    if (debug) {
      console.log("Attempting decryption...");
    }

    const accounts = await Decryptor.decryptBackup(encryptedData, archivePassword);

    if (debug) {
      console.log("Successfully decrypted", accounts.length, "accounts");
    }

    if (json) {
      console.log(JSON.stringify(accounts, null, 2));
      return;
    }

    for (const account of accounts) {
      await displayQRCode(account);
      if (accounts.indexOf(account) < accounts.length - 1) {
        await new Promise((resolve) => {
          const rl = createInterface({
            input: process.stdin,
            output: process.stdout,
          });
          rl.question("Press Enter to continue...", () => {
            rl.close();
            resolve(undefined);
          });
        });
      }
    }
  } catch (error) {
    if (error instanceof Error) {
      console.error("Error:", error.message);
      if (debug && error.stack) {
        console.error("\nStack trace:", error.stack);
      }
    } else {
      console.error("Unknown error occurred");
    }
    process.exit(1);
  }
};

program
  .command("decrypt-backup")
  .description("Decrypt an OTP Auth backup file")
  .requiredOption(
    "--encrypted-otpauth-backup <path>",
    "path to your encrypted OTP Auth backup (.otpauthdb)"
  )
  .option("-p, --password <password>", "password for the backup file")
  .option("-j, --json", "output in JSON format")
  .option("-d, --debug", "enable debug output")
  .action((options) => {
    decryptBackup(options.encryptedOtpauthBackup, options.debug || false, options.password || null, options.json || false);
  });

program.parse();

export { decryptBackup };