import { AES256GCM } from "../src/AES256GCM";

describe("AES256GCM", () => {
  let aes: AES256GCM;
  let key: Buffer;

  beforeEach(() => {
    aes = new AES256GCM();
    key = aes.generateKey();
  });

  describe("generateKey", () => {
    it("should generate a 32-byte key", () => {
      const generatedKey = aes.generateKey();
      expect(generatedKey).toBeInstanceOf(Buffer);
      expect(generatedKey.length).toBe(32);
    });

    it("should generate different keys on each call", () => {
      const key1 = aes.generateKey();
      const key2 = aes.generateKey();
      expect(key1.toString("hex")).not.toBe(key2.toString("hex"));
    });
  });

  describe("encrypt and decrypt", () => {
    it("should encrypt and decrypt string data correctly", () => {
      const plaintext = "This is a secret message";
      const { encrypted, iv, authTag } = aes.encrypt(plaintext, key);

      expect(encrypted).toBeInstanceOf(Buffer);
      expect(typeof iv).toBe("string");
      expect(iv.length).toBe(6);
      expect(authTag).toBeInstanceOf(Buffer);
      expect(authTag.length).toBe(16);

      const decrypted = aes.decrypt(encrypted, key, iv, authTag);
      expect(decrypted.toString("utf8")).toBe(plaintext);
    });

    it("should encrypt and decrypt Buffer data correctly", () => {
      const plaintext = Buffer.from([1, 2, 3, 4, 5]);
      const { encrypted, iv, authTag } = aes.encrypt(plaintext, key);

      const decrypted = aes.decrypt(encrypted, key, iv, authTag);
      expect(Buffer.compare(decrypted, plaintext)).toBe(0);
    });

    it("should throw an error when key length is invalid", () => {
      const plaintext = "This is a secret message";
      const invalidKey = Buffer.from("tooshort", "utf8");

      expect(() => {
        aes.encrypt(plaintext, invalidKey);
      }).toThrow(/Key must be 32 bytes/);
    });

    it("should throw an error when decryption fails due to tampered data", () => {
      const plaintext = "This is a secret message";
      const { encrypted, iv, authTag } = aes.encrypt(plaintext, key);

      // Tamper with the encrypted data
      encrypted[0] = encrypted[0] ^ 0xff;

      expect(() => {
        aes.decrypt(encrypted, key, iv, authTag);
      }).toThrow(/Decryption failed/);
    });

    it("should throw an error when decryption fails due to tampered auth tag", () => {
      const plaintext = "This is a secret message";
      const { encrypted, iv, authTag } = aes.encrypt(plaintext, key);

      // Tamper with the auth tag
      authTag[0] = authTag[0] ^ 0xff;

      expect(() => {
        aes.decrypt(encrypted, key, iv, authTag);
      }).toThrow(/Decryption failed/);
    });
  });

  describe("encryptToBuffer and decryptFromBuffer", () => {
    it("should encrypt to buffer and decrypt from buffer correctly", () => {
      const plaintext = "This is a secret message";
      const encryptedBuffer = aes.encryptToBuffer(plaintext, key);

      expect(encryptedBuffer).toBeInstanceOf(Buffer);
      expect(encryptedBuffer.length).toBeGreaterThan(32); // IV + authTag + encrypted data

      const decrypted = aes.decryptFromBuffer(encryptedBuffer, key);
      expect(decrypted.toString("utf8")).toBe(plaintext);
    });
  });

  describe("encryptToString and decryptFromString", () => {
    it("should encrypt to string and decrypt from string correctly", () => {
      const plaintext = "This is a secret message";
      const encryptedString = aes.encryptToString(plaintext, key);

      expect(typeof encryptedString).toBe("string");
      expect(encryptedString.length).toBeGreaterThan(0);

      const decrypted = aes.decryptFromString(encryptedString, key);
      expect(decrypted.toString("utf8")).toBe(plaintext);
    });

    it("should handle empty strings", () => {
      const plaintext = "";
      const encryptedString = aes.encryptToString(plaintext, key);

      const decrypted = aes.decryptFromString(encryptedString, key);
      expect(decrypted.toString("utf8")).toBe(plaintext);
    });

    it("should handle special characters", () => {
      const plaintext = "!@#$%^&*()_+{}|:\"<>?~`-=[]\\;',./";
      const encryptedString = aes.encryptToString(plaintext, key);

      const decrypted = aes.decryptFromString(encryptedString, key);
      expect(decrypted.toString("utf8")).toBe(plaintext);
    });
  });
});
