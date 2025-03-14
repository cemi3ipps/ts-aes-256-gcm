import { AES256GCM } from "./AES256GCM";

// Export the class
export { AES256GCM };

// Example usage
if (require.main === module) {
  // Create an instance of the AES256GCM class
  const aes = new AES256GCM();

  // Generate a random encryption key
  // const key = aes.generateKey();
  const aesHexKey = "d50ec22b016bc0a3fbaaf99816ec397714a7dfb992e847c491d83656324f5cda";
  const key = Buffer.from(aesHexKey, "hex");
  console.log("Generated Key:", aesHexKey);

  const ivString = "1035db";

  // Data to encrypt
  const plaintext =
    '{ url: "/v1/direct_credit/payee/inquiry", base64: "eyJyZXFSZWZObyI6IjE3NDE4MzM0NjUiLCJwYXllZUNvZGUiOiIiLCJ0b0JhbmtCaWNDb2RlIjoiIiwidG9BY2NvdW50Tm8iOiIifQ==", }';
  console.log("\nOriginal Data:", plaintext);

  // Example 1: Basic encryption and decryption
  console.log("\n--- Example 1: Basic Encryption and Decryption ---");
  const { encrypted, iv, authTag } = aes.encrypt(plaintext, key, ivString);
  console.log("Encrypted Data (base64):", encrypted.toString("base64"));
  console.log("Encrypted Data + Auth Tag (base64):", Buffer.concat([encrypted, authTag]).toString("base64"));
  console.log("IV (random string):", iv.toString());
  console.log("IV (hex):", Buffer.from(iv).toString("hex"));
  console.log("Auth Tag:", authTag.toString("hex"));

  const decrypted = aes.decrypt(encrypted, key, iv, authTag);
  console.log("Decrypted Data:", decrypted.toString("utf8"));
}
