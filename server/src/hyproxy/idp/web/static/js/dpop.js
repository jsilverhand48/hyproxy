// Reference DPoP client module (RFC 9449) for browser RPs.
//
// Generates a NON-EXTRACTABLE P-256 ECDSA keypair via WebCrypto, persists the
// CryptoKey objects in IndexedDB (structured clone keeps them non-extractable,
// surviving the OAuth redirect dance), and builds one proof JWT per request.
// The private key never leaves the device, which is the whole point: a stolen
// token is useless without it.
//
// Usage:
//   const dpop = await DpopKit.load();
//   const proof = await dpop.makeProof("POST", tokenEndpointUrl);
//   const proofWithAth = await dpop.makeProof("GET", userinfoUrl, accessToken);
"use strict";

const DpopKit = (() => {
  const DB_NAME = "dpop";
  const STORE = "keys";
  const KEY_ID = "device-key";

  function b64u(bytes) {
    let s = "";
    for (const b of new Uint8Array(bytes)) s += String.fromCharCode(b);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function b64uJson(obj) {
    return b64u(new TextEncoder().encode(JSON.stringify(obj)));
  }

  function idb() {
    return new Promise((resolve, reject) => {
      const req = indexedDB.open(DB_NAME, 1);
      req.onupgradeneeded = () => req.result.createObjectStore(STORE);
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  }

  async function idbGet(db, key) {
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, "readonly").objectStore(STORE).get(key);
      tx.onsuccess = () => resolve(tx.result);
      tx.onerror = () => reject(tx.error);
    });
  }

  async function idbPut(db, key, value) {
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, "readwrite").objectStore(STORE).put(value, key);
      tx.onsuccess = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  }

  class Kit {
    constructor(keyPair, publicJwk) {
      this.keyPair = keyPair;
      this.publicJwk = { kty: publicJwk.kty, crv: publicJwk.crv, x: publicJwk.x, y: publicJwk.y };
    }

    // htu is normalized server-side; send the full request URL without fragment.
    async makeProof(htm, htu, accessToken) {
      const header = { typ: "dpop+jwt", alg: "ES256", jwk: this.publicJwk };
      const claims = {
        jti: b64u(crypto.getRandomValues(new Uint8Array(16))),
        htm: htm,
        htu: htu.split("#")[0],
        iat: Math.floor(Date.now() / 1000),
      };
      if (accessToken) {
        const digest = await crypto.subtle.digest(
          "SHA-256",
          new TextEncoder().encode(accessToken)
        );
        claims.ath = b64u(digest);
      }
      const signingInput = `${b64uJson(header)}.${b64uJson(claims)}`;
      const signature = await crypto.subtle.sign(
        { name: "ECDSA", hash: "SHA-256" },
        this.keyPair.privateKey,
        new TextEncoder().encode(signingInput)
      );
      return `${signingInput}.${b64u(signature)}`;
    }
  }

  async function load() {
    const db = await idb();
    let keyPair = await idbGet(db, KEY_ID);
    if (!keyPair) {
      keyPair = await crypto.subtle.generateKey(
        { name: "ECDSA", namedCurve: "P-256" },
        /* extractable= */ false,
        ["sign"]
      );
      await idbPut(db, KEY_ID, keyPair);
    }
    const publicJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
    return new Kit(keyPair, publicJwk);
  }

  return { load };
})();
