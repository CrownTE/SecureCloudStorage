const { ec: EC } = require("elliptic");
const crypto = require("crypto");

const ec = new EC("p256");

const keyPair = ec.genKeyPair();
const aesKey = crypto.randomBytes(32); // 256 bits = 32 bytes

console.log("AES Key (hex):", aesKey.toString("hex"));
console.log("ECC Private Key (hex):", keyPair.getPrivate("hex"));
console.log("ECC Public Key (hex):", keyPair.getPublic().encode("hex"));
