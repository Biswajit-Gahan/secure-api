const jwt = require("jsonwebtoken");
const crypto = require("crypto");

const jwtEncode = (data) => {
  const token = jwt.sign(data, process.env.JWT_ENCODE, { expiresIn: 1800 });
  return token;
};

const jwtDecode = (token) => {
  const decodedData = jwt.verify(token, process.env.JWT_ENCODE);
  return decodedData ? decodedData : false;
};

const uuid = () => {
  return crypto.randomUUID();
};

const encryptData = (dataToEncrypt, encryptionKey, initializationVector) => {
  try {
    // Convert strings to buffers
    const dataBuffer = Buffer.from(dataToEncrypt, "utf-8");
    const keyBuffer = Buffer.from(encryptionKey, "utf-8");
    const ivBuffer = Buffer.from(initializationVector, "utf-8");

    // Create Cipher instance
    const cipher = crypto.createCipheriv("aes-256-cbc", keyBuffer, ivBuffer);

    // Encrypt the data
    let encryptedBuffer = cipher.update(dataBuffer, "utf-8", "base64");
    encryptedBuffer += cipher.final("base64");

    // Return the base64-encoded encrypted data
    return encryptedBuffer;
  } catch (error) {
    console.error(error);
    return null;
  }
};

const decryptData = (encryptedData, encryptionKey, initializationVector) => {
  try {
    // Convert base64-encoded string to Buffer
    const encryptedBuffer = Buffer.from(encryptedData, "base64");

    // Convert strings to Buffers with UTF-8 encoding
    const keyBuffer = Buffer.from(encryptionKey, "utf-8");
    const ivBuffer = Buffer.from(initializationVector, "utf-8");

    // Create a decipher object
    const decipher = crypto.createDecipheriv(
      "aes-256-cbc",
      keyBuffer,
      ivBuffer
    );

    // Decrypt the data
    let decrypted = decipher.update(encryptedBuffer, "binary", "utf-8");
    decrypted += decipher.final("utf-8");

    return decrypted;
  } catch (error) {
    console.error(error);
    return null;
  }
};

const getEncryptedData = (data, secret, iv) => {
  const encryptedData = encryptData(JSON.stringify(data), secret, iv);
  const reversedSecret = secret.split("").reverse().join("");
  const reversedIv = iv.split("").reverse().join("");
  const reversedEncryptedData = encryptedData.split("").reverse().join("");
  return `${reversedSecret}${reversedIv}${reversedEncryptedData}`;
  // return `${secret}${iv}${encryptedData}`;
};

const getAutoEncryptedData = (data) => {
  const secret = crypto.randomUUID().substring(0, 32);
  const iv = crypto.randomUUID().substring(0, 16);
  const encryptedData = encryptData(JSON.stringify(data), secret, iv);
  const reversedSecret = secret.split("").reverse().join("");
  const reversedIv = iv.split("").reverse().join("");
  // const reversedEncryptedData = encryptedData.split("").reverse().join("");
  return `${reversedSecret}${reversedIv}${encryptedData}`;
  // return `${secret}${iv}${encryptedData}`;
};

const getDecryptedData = (data) => {
  const iv = data.substring(0, 16);
  const secret = data.substring(16, 48);
  const encryptedData = data.substring(48);
  const reversedSecret = secret.split("").reverse().join("");
  const reversedIv = iv.split("").reverse().join("");
  // const reversedEncryptedData = encryptedData.split("").reverse().join("");
  const decryptedData = decryptData(encryptedData, reversedSecret, reversedIv);
  // const decryptedData = decryptData(encryptedData, secret, iv);
  return decryptedData;
};

module.exports = {
  jwtDecode,
  jwtEncode,
  uuid,
  encryptData,
  decryptData,
  getEncryptedData,
  getDecryptedData,
  getAutoEncryptedData,
};
