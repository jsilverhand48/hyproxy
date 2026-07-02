// WebAuthn client glue: base64url <-> ArrayBuffer and the options/verify dance.
// No inline scripts anywhere (strict CSP); state comes from data- attributes.
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
  if (options.user && options.user.id) options.user.id = b64uToBuf(options.user.id);
  for (const key of ["allowCredentials", "excludeCredentials"]) {
    if (options[key]) options[key] = options[key].map((c) => ({ ...c, id: b64uToBuf(c.id) }));
  }
  return options;
}

function encodeCredential(cred) {
  const out = { id: cred.id, rawId: bufToB64u(cred.rawId), type: cred.type, response: {} };
  const r = cred.response;
  out.response.clientDataJSON = bufToB64u(r.clientDataJSON);
  if (r.attestationObject) out.response.attestationObject = bufToB64u(r.attestationObject);
  if (r.authenticatorData) out.response.authenticatorData = bufToB64u(r.authenticatorData);
  if (r.signature) out.response.signature = bufToB64u(r.signature);
  if (r.userHandle) out.response.userHandle = bufToB64u(r.userHandle);
  if (cred.authenticatorAttachment) out.authenticatorAttachment = cred.authenticatorAttachment;
  out.clientExtensionResults = cred.getClientExtensionResults
    ? cred.getClientExtensionResults()
    : {};
  return out;
}

async function postJson(url, body) {
  const resp = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
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

document.getElementById("webauthn-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.target;
  const flow = form.dataset.flow;
  const csrf = form.dataset.csrf;
  try {
    if (form.dataset.mode === "enroll") {
      const options = decodeOptions(
        await postJson("/auth/enroll/webauthn/options", { flow: flow, csrf_token: csrf })
      );
      const cred = await navigator.credentials.create({ publicKey: options });
      const result = await postJson("/auth/enroll/webauthn/verify", {
        flow: flow,
        csrf_token: csrf,
        credential: encodeCredential(cred),
        friendly_name: document.getElementById("friendly_name").value,
        break_glass: document.getElementById("break_glass").checked,
      });
      document.getElementById("enrolled-count").textContent = result.enrolled;
    } else {
      const options = decodeOptions(
        await postJson("/auth/webauthn/options", { flow: flow, csrf_token: csrf })
      );
      const cred = await navigator.credentials.get({ publicKey: options });
      const result = await postJson("/auth/webauthn/verify", {
        flow: flow,
        csrf_token: csrf,
        credential: encodeCredential(cred),
      });
      window.location.assign(result.redirect);
    }
  } catch (err) {
    showError(err.message || String(err));
  }
});
