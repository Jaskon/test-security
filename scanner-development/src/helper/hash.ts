import crypto from "crypto";
import { HahsType } from "../entitis/applicationsFlowTypes";
import loggerImport from "../logger";
const logger = loggerImport.getDebugLogger();

export const hash = (data: string) => {
  return crypto.createHash("sha256").update(data).digest("hex");
};

export const getRandomString = (): string => {
  return hash(`${new Date()}:${Math.random()}:${Math.random()}:${Math.random()}:${Math.random()}`);
};

const regexExpMD5 = /^[a-f0-9]{32}$/gi;
const regexExpSHA1 = /^[a-f0-9]{40}$/gi;
const regexExpSHA256 = /^[a-f0-9]{64}$/gi;

export function getHashType(str: string) {
  try {
    if (regexExpMD5.test(str)) return HahsType.MD5;
    if (regexExpSHA1.test(str)) return HahsType.SHA1;
    if (regexExpSHA256.test(str)) return HahsType.sha256;
  } catch (err) {
    logger.error(`failed get hash type: ${str} err ${err}`);
  }
  return HahsType.Unknown;
}

export const AES = (key: string, iv: string) => {
  return {
    encrypt: (val: string) => {
      let cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
      let encrypted = cipher.update(val, "utf8", "base64");
      encrypted += cipher.final("base64");
      return encrypted;
    },

    decrypt: (encrypted: string) => {
      let decipher = crypto.createDecipheriv("aes-256-cbc", key, iv);
      let decrypted = decipher.update(encrypted, "base64", "utf8");
      return decrypted + decipher.final("utf8");
    },
  };
};

function isASCII(str) {
  return /^[\x20-\x7E]*$/.test(str);
}

// Presumably
export function isBase64(str) {
  if (str === "" || str.trim() === "") {
    return false;
  }
  try {
    const raw = Buffer.from(str, "base64");
    const base64 = Buffer.from(raw).toString("base64");
    return base64 === str;
  } catch (err) {
    return false;
  }
}

export function EnsureDebased(str) {
  if (isBase64(str)) {
    const tmp = Buffer.from(str, "base64").toString("ascii");

    if (isASCII(tmp)) {
      return tmp;
    }
  }

  return str;
}
