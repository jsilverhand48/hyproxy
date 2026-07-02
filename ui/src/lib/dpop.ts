// DPoP client (RFC 9449) for the admin SPA. Mirrors the IdP reference module
// (idp/web/static/js/dpop.js): a NON-EXTRACTABLE P-256 ECDSA keypair generated
// via WebCrypto and persisted in IndexedDB, so it survives reloads and the
// OAuth redirect dance while the private key never leaves the device.

const DB_NAME = "hyproxy-dpop";
const STORE = "keys";
const KEY_ID = "device-key";

type PublicJwk = { kty: string; crv: string; x: string; y: string };

function b64u(bytes: ArrayBuffer): string {
  let s = "";
  for (const b of new Uint8Array(bytes)) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64uJson(obj: unknown): string {
  return b64u(new TextEncoder().encode(JSON.stringify(obj)).buffer as ArrayBuffer);
}

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(STORE);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

function idbGet<T>(db: IDBDatabase, key: string): Promise<T | undefined> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, "readonly").objectStore(STORE).get(key);
    tx.onsuccess = () => resolve(tx.result as T | undefined);
    tx.onerror = () => reject(tx.error);
  });
}

function idbPut(db: IDBDatabase, key: string, value: unknown): Promise<void> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, "readwrite").objectStore(STORE).put(value, key);
    tx.onsuccess = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

export class DpopKey {
  constructor(
    private readonly keyPair: CryptoKeyPair,
    private readonly publicJwk: PublicJwk,
  ) {}

  async makeProof(htm: string, htu: string, accessToken?: string): Promise<string> {
    const header = { typ: "dpop+jwt", alg: "ES256", jwk: this.publicJwk };
    const claims: Record<string, unknown> = {
      jti: b64u(crypto.getRandomValues(new Uint8Array(16)).buffer),
      htm,
      htu: htu.split("#")[0],
      iat: Math.floor(Date.now() / 1000),
    };
    if (accessToken) {
      const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(accessToken));
      claims.ath = b64u(digest);
    }
    const signingInput = `${b64uJson(header)}.${b64uJson(claims)}`;
    const signature = await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      this.keyPair.privateKey,
      new TextEncoder().encode(signingInput),
    );
    return `${signingInput}.${b64u(signature)}`;
  }
}

let cached: Promise<DpopKey> | null = null;

export function loadDpopKey(): Promise<DpopKey> {
  if (cached) return cached;
  cached = (async () => {
    const db = await openDb();
    let keyPair = await idbGet<CryptoKeyPair>(db, KEY_ID);
    if (!keyPair) {
      keyPair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, [
        "sign",
      ]);
      await idbPut(db, KEY_ID, keyPair);
    }
    const jwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
    return new DpopKey(keyPair, { kty: jwk.kty!, crv: jwk.crv!, x: jwk.x!, y: jwk.y! });
  })();
  return cached;
}
