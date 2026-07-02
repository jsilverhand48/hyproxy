// Step-up glue: run a fresh WebAuthn assertion against the current IdP session,
// then navigate back to the admin UI. No inline scripts (strict CSP); the
// validated return target comes from a data- attribute the server rendered.
"use strict";

function b64uToBuf(s) {
  const pad = "=".repeat((4 - (s.length % 4)) % 4);
  const raw = atob(s.replace(/-/g, "+").replace(/_/g, "/") + pad);
  return Uint8Array.from(raw, (c) => c.charCodeAt(0)).buffer;
}

function bufToB64u(buf) {
  const bytes = new Uint8Array(buf);
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function decodeOptions(options) {
  options.challenge = b64uToBuf(options.challenge);
  if (options.allowCredentials) {
    options.allowCredentials = options.allowCredentials.map((c) => ({
      ...c,
      id: b64uToBuf(c.id),
    }));
  }
  return options;
}

function encodeAssertion(cred) {
  const r = cred.response;
  return {
    id: cred.id,
    rawId: bufToB64u(cred.rawId),
    type: cred.type,
    response: {
      clientDataJSON: bufToB64u(r.clientDataJSON),
      authenticatorData: bufToB64u(r.authenticatorData),
      signature: bufToB64u(r.signature),
      ...(r.userHandle ? { userHandle: bufToB64u(r.userHandle) } : {}),
    },
    clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {},
  };
}

async function postJson(url, body) {
  const resp = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const data = await resp.json().catch(() => ({}));
  if (!resp.ok) throw new Error(data.error || "request failed");
  return data;
}

function showError(message) {
  const el = document.getElementById("webauthn-error");
  el.textContent = message;
  el.hidden = false;
}

document.getElementById("stepup-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const returnTo = event.target.dataset.returnTo;
  try {
    const options = decodeOptions(await postJson("/auth/stepup/options", {}));
    const cred = await navigator.credentials.get({ publicKey: options });
    await postJson("/auth/stepup/verify", { credential: encodeAssertion(cred) });
    window.location.assign(returnTo);
  } catch (err) {
    showError(err.message || String(err));
  }
});
