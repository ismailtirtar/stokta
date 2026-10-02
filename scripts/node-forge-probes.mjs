import { createHash, generateKeyPairSync, constants, privateEncrypt } from "node:crypto";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { join, sep } from "node:path";
import { runInNewContext } from "node:vm";

// These keys are generated only for parser regression tests. No application or
// signing credentials are loaded. Malformed encodings are signed with the test
// private key; this is a rejection test, not a no-private-key forgery proof.
export function signatureProbeResults(packageRoot) {
  const require = createRequire(join(packageRoot, "package.json"));
  for (const path of Object.keys(require.cache)) {
    if (path.startsWith(`${packageRoot}${sep}`)) delete require.cache[path];
  }
  const implementations = [["lib/index.js", require(join(packageRoot, "lib/index.js"))]];
  for (const file of ["dist/forge.min.js", "dist/forge.all.min.js"]) {
    // The all-in-one browser build expects jQuery event registration on load.
    // No DOM or randomness from these no-op handlers is used by the RSA probes.
    const handlers = { mousemove() { return this; }, keypress() { return this; } };
    const jQuery = () => handlers;
    const context = {
      window: { jQuery }, jQuery, module: { exports: {} },
      setTimeout, clearTimeout, Uint8Array, ArrayBuffer, Buffer,
    };
    context.exports = context.module.exports;
    runInNewContext(readFileSync(join(packageRoot, file), "utf8"), context, {
      filename: file, timeout: 2000,
    });
    implementations.push([file, context.module.exports]);
  }

  const results = [];
  const message = Buffer.from("Stokdas node-forge DigestInfo regression");
  for (const exponent of [3, 65537]) {
    const pair = generateKeyPairSync("rsa", { modulusLength: 2048, publicExponent: exponent });
    const publicPem = pair.publicKey.export({ type: "spki", format: "pem" });
    for (const [entrypoint, forge] of implementations) {
      const publicKey = forge.pki.publicKeyFromPem(publicPem);
      const a = forge.asn1;
      const node = (type, value, constructed = false) => a.create(a.Class.UNIVERSAL, type, constructed, value);
      for (const [name, algorithm, parameter, extra, outerExtra, wrongDigest, expected] of [
        ["SHA-256 with NULL", "sha256", "null", false, false, false, true],
        ["SHA-256 without parameters", "sha256", "absent", false, false, false, true],
        ["SHA-384 with NULL", "sha384", "null", false, false, false, true],
        ["SHA-512 with NULL", "sha512", "null", false, false, false, true],
        ["legacy MD5 compatibility", "md5", "null", false, false, false, true],
        ["extra nested OCTET STRING", "sha256", "null", true, false, false, false],
        ["unexpected nested parameter", "sha256", "octets", false, false, false, false],
        ["duplicate nested NULL", "sha256", "duplicate", false, false, false, false],
        ["extra outer child", "sha256", "null", false, true, false, false],
        ["wrong digest", "sha256", "null", false, false, true, false],
      ]) {
        const digest = createHash(algorithm).update(message).digest();
        const children = [node(a.Type.OID, a.oidToDer(forge.oids[algorithm]).getBytes())];
        if (parameter === "null" || parameter === "duplicate") children.push(node(a.Type.NULL, ""));
        if (parameter === "duplicate") children.push(node(a.Type.NULL, ""));
        if (parameter === "octets" || extra) children.push(node(a.Type.OCTETSTRING, "unconsumed"));
        const encodedDigest = Buffer.from(digest);
        if (wrongDigest) encodedDigest[0] ^= 1;
        const outer = [node(a.Type.SEQUENCE, children, true), node(a.Type.OCTETSTRING, encodedDigest.toString("binary"))];
        if (outerExtra) outer.push(node(a.Type.NULL, ""));
        const der = Buffer.from(a.toDer(node(a.Type.SEQUENCE, outer, true)).getBytes(), "binary");
        const encoded = Buffer.concat([Buffer.from([0, 1]), Buffer.alloc(256 - der.length - 3, 0xff), Buffer.from([0]), der]);
        const signature = privateEncrypt({ key: pair.privateKey, padding: constants.RSA_NO_PADDING }, encoded);
        let accepted;
        try {
          accepted = publicKey.verify(digest.toString("binary"), signature.toString("binary"));
        } catch (error) {
          // Only the intended DigestInfo validation exception is a valid
          // rejection; unrelated runtime errors must stop verification.
          if (!error.message?.includes("valid RSASSA-PKCS1-v1_5 DigestInfo")) throw error;
          accepted = false;
        }
        results.push({ entrypoint, exponent, name, accepted, expected });
      }
    }
  }
  return results;
}
