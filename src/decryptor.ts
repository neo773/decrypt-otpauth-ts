import bplist from "bplist-parser";
import rncryptor from "rncryptor-node";
import base32Encode from "base32-encode";
import { createHash } from "crypto";
import { createDecipheriv } from "crypto";

export enum Type {
  Unknown = 0,
  HOTP = 1,
  TOTP = 2,
}

export enum Algorithm {
  Unknown = 0,
  SHA1 = 1,
  SHA256 = 2,
  SHA512 = 3,
  MD5 = 4,
}

export interface OTPAccount {
  label: string;
  issuer: string;
  secret: string;
  type: Type;
  algorithm: Algorithm;
  digits: number;
  counter: number;
  period: number;
  refDate: Date;
}

interface NSObject {
  "NS.data"?: Buffer;
  "NS.string"?: string;
  "NS.time"?: number;
  "NS.objects"?: Array<{ UID: string }>;
}

interface ArchiveRoot {
  $objects: Array<NSObject | string | Buffer | { UID: string }>;
  $top: {
    root: {
      UID: string;
    };
  };
}

export class Decryptor {
  private static getTypeUriValue(type: Type): string {
    switch (type) {
      case Type.HOTP:
        return "hotp";
      case Type.TOTP:
        return "totp";
      default:
        return "unknown";
    }
  }

  private static getAlgorithmUriValue(algorithm: Algorithm): string {
    switch (algorithm) {
      case Algorithm.SHA256:
        return "sha256";
      case Algorithm.SHA512:
        return "sha512";
      case Algorithm.MD5:
        return "md5";
      case Algorithm.Unknown:
      case Algorithm.SHA1:
      default:
        return "sha1";
    }
  }

  public static generateOTPUri(account: OTPAccount): string {
    const otpType = this.getTypeUriValue(account.type);
    const otpLabel = encodeURIComponent(`${account.issuer}:${account.label}`);

    const params = new URLSearchParams({
      secret: account.secret,
      algorithm: this.getAlgorithmUriValue(account.algorithm),
      digits: account.digits.toString(),
      period: account.period.toString(),
      issuer: account.issuer,
      counter: account.counter.toString(),
    });

    if (account.issuer) {
      params.append("issuer", account.issuer);
    }

    if (account.type === Type.HOTP) {
      params.append("counter", account.counter.toString());
    } else if (account.period) {
      params.append("period", account.period.toString());
    }
    const uri = decodeURIComponent(
      `otpauth://${otpType}/${otpLabel}?${params.toString()}`
    );
    console.log(uri);
    return uri;
  }

  public static async decryptBackup(
    encryptedData: Buffer,
    password: string
  ): Promise<OTPAccount[]> {
    // First decrypt the outer layer using AES
    const iv = Buffer.alloc(16, 0);
    const key = createHash("sha256").update("Authenticator").digest();

    const decipher = createDecipheriv("aes-256-cbc", key, iv);
    let wrappingArchive = Buffer.concat([
      decipher.update(encryptedData),
      decipher.final(),
    ]);

    const [properties] = bplist.parseBuffer<ArchiveRoot>(wrappingArchive);

    // Access the wrapped data with type safety
    const wrappedObject = properties.$objects[5] as NSObject;
    const wrappedData = wrappedObject["NS.data"]?.toString("base64");
    if (!wrappedData) {
      throw new Error("Could not find wrapped data in archive");
    }

    const decryptedData = rncryptor.Decrypt(wrappedData, password);

    if (!decryptedData) {
      throw new Error("Failed to decrypt data: Invalid password");
    }

    // Parse the inner bplist
    const [innerArchive] = bplist.parseBuffer<ArchiveRoot>(decryptedData);

    // Extract accounts from folders
    const accounts: OTPAccount[] = [];
    const archiveRoot = innerArchive.$objects[
      innerArchive.$top.root.UID as keyof typeof innerArchive.$objects
    ] as NSObject;
    const foldersIndex = archiveRoot["NS.objects"]?.[0]?.UID;
    if (!foldersIndex) {
      throw new Error("No folders index found in archive root");
    }
    const folders = (
      innerArchive.$objects[
        foldersIndex as keyof typeof innerArchive.$objects
      ] as NSObject
    )["NS.objects"];
    if (!folders) {
      throw new Error("No folders found in archive root");
    }

    for (const folderRef of folders) {
      const folder = innerArchive.$objects[
        folderRef.UID as keyof typeof innerArchive.$objects
      ] as { accounts?: { UID: string } };

      if (!folder || typeof folder === "string") {
        console.warn("Skipping invalid folder:", folder);
        continue;
      }

      const accountsArray = (
        innerArchive.$objects[
          folder.accounts?.UID as keyof typeof innerArchive.$objects
        ] as NSObject
      )?.["NS.objects"];

      if (!accountsArray) {
        console.warn("No accounts array found in folder");
        continue;
      }

      for (const accountRef of accountsArray) {
        const account = innerArchive.$objects[
          accountRef.UID as keyof typeof innerArchive.$objects
        ] as {
          secret: { UID: string };
          label: { UID: string };
          issuer: { UID: string };
          lastModified: { UID: string };
          type: number;
          algorithm: number;
          digits: number;
          counter: number;
          period: number;
        };
        if (!account) {
          console.warn("Invalid account reference:", accountRef);
          continue;
        }

        try {
          const secretObj =
            innerArchive.$objects[
              account.secret?.UID as keyof typeof innerArchive.$objects
            ];

          if (!secretObj || !Buffer.isBuffer(secretObj)) {
            console.warn("Invalid secret data format for account");
            continue;
          }

          const labelObj =
            innerArchive.$objects[
              account.label?.UID as keyof typeof innerArchive.$objects
            ];
          const label =
            typeof labelObj === "string"
              ? labelObj
              : (labelObj as NSObject)?.["NS.string"] || "Unknown";

          const issuer =
            typeof innerArchive.$objects[
              account.issuer?.UID as keyof typeof innerArchive.$objects
            ] === "string"
              ? innerArchive.$objects[
                  account.issuer?.UID as keyof typeof innerArchive.$objects
                ]
              : (
                  innerArchive.$objects[
                    account.issuer?.UID as keyof typeof innerArchive.$objects
                  ] as NSObject
                )?.["NS.string"] || "Unknown";

          if (typeof label !== "string" || typeof issuer !== "string") {
            console.warn("Invalid label or issuer for account");
            continue;
          }

          const buffer = Buffer.from(secretObj);
          const secret = base32Encode(buffer, "RFC4648", { padding: false });

          const type = account.type;
          const algorithm = account.algorithm;

          const lastModifiedObj = innerArchive.$objects[
            account.lastModified?.UID as keyof typeof innerArchive.$objects
          ] as NSObject;

          // Convert Cocoa Date to ISO 8601
          const refDate = new Date(
            (new Date("2001-01-01T00:00:00Z").getTime() / 1000 +
              lastModifiedObj["NS.time"]!) *
              1000
          );

          accounts.push({
            label,
            issuer,
            secret,
            type,
            algorithm,
            digits: account.digits,
            counter: account.counter,
            period: account.period,
            refDate,
          });
        } catch (error) {
          console.warn("Failed to parse account:", error);
        }
      }
    }
    return accounts;
  }
}
