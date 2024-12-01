function base64UrlEncode(data) {
    return Buffer.from(data)
      .toString("base64")
      .replace(/=/g, "")
      .replace(/\+/g, "-")
      .replace(/\//g, "_");
  }
  
  function base64UrlDecode(encodedData) {
    const base64 = encodedData.replace(/-/g, "+").replace(/_/g, "/");
    return Buffer.from(base64, "base64").toString();
  }
  

  console.log("Encoded Data:", base64UrlEncode("hello")); // aGVsbG8
  console.log("Decoded Data:", base64UrlDecode("aGVsbG8")); // hello
  
const crypto = require("crypto");

function hash(payload, secret, header) {
  const encodedHeader = base64UrlEncode(JSON.stringify(header));
  const encodedPayload = base64UrlEncode(JSON.stringify(payload));
  return crypto
    .createHmac("sha256", secret)
    .update(`${encodedHeader}.${encodedPayload}`)
    .digest("hex");
}

function jwtSign(payload, secret, header = { alg: "HS256", typ: "JWT" }) {
    const encodedHeader = base64UrlEncode(JSON.stringify(header));
    const encodedPayload = base64UrlEncode(JSON.stringify(payload));

    const signature = hash(payload, secret, header);
  
    return `${encodedHeader}.${encodedPayload}.${signature}`;
  }

  function jwtVerify(token, secret) {
    const [encodedHeader, encodedPayload, signature] = token.split(".");
  
    if (!encodedHeader || !encodedPayload || !signature) {
      return { valid: false, error: "Malformed token" };
    }
  
    const header = JSON.parse(base64UrlDecode(encodedHeader));
    const payload = JSON.parse(base64UrlDecode(encodedPayload));
    const validSignature = hash(payload, secret, header);

    if (validSignature !== signature) {
      return { valid: false, error: "Invalid signature" };
    }
  
    return { valid: true, payload: payload };
  }

const header = { alg: "HS256", typ: "JWT" };
const payload = {
  userId: 123,
  userName: "Matti",
}; 
const secret = require("crypto").randomBytes(64).toString("hex");

console.log("Generated Secret:", secret);
const token = jwtSign(payload, secret, header);
console.log("JWT:", token);

console.log(jwtVerify(token, secret));