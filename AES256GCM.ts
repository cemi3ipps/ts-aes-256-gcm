import * as crypto from "crypto";

/**
 * AES-256-GCM encryption/decryption utility class
 */
export class AES256GCM {
  private readonly algorithm = "aes-256-gcm";
  private readonly keyLength = 32; // 256 bits
  private readonly ivLength = 6; // 6 characters
  private readonly authTagLength = 16; // 128 bits

  /**
   * Generates a random encryption key
   * @returns Buffer containing the generated key
   */
  public generateKey(): Buffer {
    return crypto.randomBytes(this.keyLength);
  }

  /**
   * Generates a random string for IV
   * @returns Random string for IV generation
   */
  private generateRandomString(): string {
    // Generate random bytes and convert to hex string
    // We need to generate more bytes than needed to ensure we have enough characters after conversion
    return crypto
      .randomBytes(this.ivLength)
      .toString("hex")
      .slice(0, this.ivLength);
  }

  /**
   * Encrypts data using AES-256-GCM
   * @param data - The data to encrypt (string or Buffer)
   * @param key - The encryption key (must be 32 bytes / 256 bits)
   * @param fixedIv - Optional fixed IV string (must be exactly 6 characters)
   * @returns Object containing the encrypted data, IV (as string), and auth tag
   */
  public encrypt(
    data: string | Buffer,
    key: Buffer,
    fixedIv?: string
  ): {
    encrypted: Buffer;
    iv: string;
    authTag: Buffer;
  } {
    // Validate key length
    if (key.length !== this.keyLength) {
      throw new Error(
        `Key must be ${this.keyLength} bytes (${this.keyLength * 8} bits)`
      );
    }

    // Use fixed IV if provided, otherwise generate a random one
    const ivString = fixedIv || this.generateRandomString();

    // Validate IV length if fixed IV is provided
    if (fixedIv && fixedIv.length !== this.ivLength) {
      throw new Error(`IV must be exactly ${this.ivLength} characters`);
    }

    // Convert string to Buffer for encryption
    const iv = Buffer.from(ivString, "utf8");

    // Create cipher
    const cipher = crypto.createCipheriv(this.algorithm, key, iv);

    // Convert data to Buffer if it's a string
    const dataBuffer =
      typeof data === "string" ? Buffer.from(data, "utf8") : data;

    // Encrypt the data
    const encrypted = Buffer.concat([
      cipher.update(dataBuffer),
      cipher.final(),
    ]);

    // Get the authentication tag
    const authTag = cipher.getAuthTag();

    return {
      encrypted,
      iv: ivString,
      authTag,
    };
  }

  /**
   * Decrypts data using AES-256-GCM
   * @param encrypted - The encrypted data
   * @param key - The encryption key (must be 32 bytes / 256 bits)
   * @param iv - The initialization vector used during encryption (string)
   * @param authTag - The authentication tag generated during encryption
   * @returns The decrypted data as a Buffer
   */
  public decrypt(
    encrypted: Buffer,
    key: Buffer,
    iv: string | Buffer,
    authTag: Buffer
  ): Buffer {
    // Validate key length
    if (key.length !== this.keyLength) {
      throw new Error(
        `Key must be ${this.keyLength} bytes (${this.keyLength * 8} bits)`
      );
    }

    // Convert IV to Buffer if it's a string
    const ivBuffer = typeof iv === "string" ? Buffer.from(iv, "utf8") : iv;

    // Create decipher
    const decipher = crypto.createDecipheriv(this.algorithm, key, ivBuffer);

    // Set authentication tag
    decipher.setAuthTag(authTag);

    // Decrypt the data
    try {
      return Buffer.concat([decipher.update(encrypted), decipher.final()]);
    } catch (error) {
      throw new Error(
        "Decryption failed: Authentication failed or data corrupted"
      );
    }
  }

  /**
   * Encrypts data and returns everything needed for decryption in a single buffer
   * Format: [IV (6 bytes)][Auth Tag (16 bytes)][Encrypted Data (variable length)]
   * @param data - The data to encrypt
   * @param key - The encryption key
   * @param fixedIv - Optional fixed IV string (must be exactly 6 characters)
   * @returns Buffer containing IV, auth tag, and encrypted data
   */
  public encryptToBuffer(
    data: string | Buffer,
    key: Buffer,
    fixedIv?: string
  ): Buffer {
    const { encrypted, iv, authTag } = this.encrypt(data, key, fixedIv);
    const ivBuffer = Buffer.from(iv, "utf8");
    return Buffer.concat([ivBuffer, authTag, encrypted]);
  }

  /**
   * Decrypts data from a buffer created with encryptToBuffer
   * @param encryptedBuffer - Buffer containing IV, auth tag, and encrypted data
   * @param key - The encryption key
   * @returns The decrypted data as a Buffer
   */
  public decryptFromBuffer(encryptedBuffer: Buffer, key: Buffer): Buffer {
    // Extract IV, auth tag, and encrypted data from the buffer
    const ivBuffer = encryptedBuffer.subarray(0, this.ivLength);
    const authTag = encryptedBuffer.subarray(
      this.ivLength,
      this.ivLength + this.authTagLength
    );
    const encrypted = encryptedBuffer.subarray(
      this.ivLength + this.authTagLength
    );

    return this.decrypt(encrypted, key, ivBuffer, authTag);
  }

  /**
   * Encrypts data and returns a base64 string containing everything needed for decryption
   * @param data - The data to encrypt
   * @param key - The encryption key
   * @param fixedIv - Optional fixed IV string (must be exactly 6 characters)
   * @returns Base64 string containing IV, auth tag, and encrypted data
   */
  public encryptToString(
    data: string | Buffer,
    key: Buffer,
    fixedIv?: string
  ): string {
    return this.encryptToBuffer(data, key, fixedIv).toString("base64");
  }

  /**
   * Decrypts data from a base64 string created with encryptToString
   * @param encryptedString - Base64 string containing IV, auth tag, and encrypted data
   * @param key - The encryption key
   * @returns The decrypted data as a Buffer
   */
  public decryptFromString(encryptedString: string, key: Buffer): Buffer {
    const encryptedBuffer = Buffer.from(encryptedString, "base64");
    return this.decryptFromBuffer(encryptedBuffer, key);
  }
}
