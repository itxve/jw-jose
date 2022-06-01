import * as jose from "jose";
import { readFileSync } from "fs";

// # 1. 生成 ec 算法的私钥，使用 prime256v1 曲线（NIST P-256 标准），密钥长度 256 位。（强度大于 2048 位的 RSA 密钥）
// openssl ecparam -genkey -name prime256v1 -out ecc-private-key.pem
// # 2. 通过密钥生成公钥
// openssl ec -in ecc-private-key.pem -pubout -out ecc-public-key.pem

// # 3. 转换 https://www.openssl.org/docs/man1.1.1/man1/openssl-pkcs8.html

(async () => {
  const algorithm = "ES256";
  const ecPrivateKey = await jose.importPKCS8(
    String(readFileSync("./pkcs8_ec_private.pem")),
    algorithm
  );

  const jwt = await new jose.SignJWT({ name: true, acc: "23" })
    .setProtectedHeader({ alg: algorithm })
    .setIssuer("urn:example:issuer")
    .setAudience("urn:example:audience")
    .setExpirationTime("10s")
    .sign(ecPrivateKey);

  console.log(jwt);

  const rr = jose.decodeJwt(jwt);
  console.log(rr);

  const ecPublicKey = await jose.importSPKI(
    String(readFileSync("./ec_public.pem")),
    algorithm
  );

  const verify = await jose.jwtVerify(
    jwt,
    ecPublicKey,
    //验证项
    {}
  );
  console.log(verify);
})();
