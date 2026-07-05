# TPM-backed master key: bring-up steps

How to move the master key from the on-disk `file` backend to the TPM-sealed
broker on a host that has a TPM (e.g. `hyproxy-dev`). Nothing in the application
changes: the swap happens behind the `SecretsBackend` seam in
`server/src/hyproxy/core/secrets.py`. See `docs/production.md` section 1 for the
design rationale.

The work is in three parts:

1. one code change: implement `tpm_unseal()` (the only in-repo gap),
2. host preparation: install tpm2-tools and seal a master key to the TPM,
3. a zero-downtime migration off the file key, then destroy it.

## What is already built

- `SecretsBackend` protocol + `TpmSecretsBackend` drop-in (unit-tested with an
  injected `unseal` callable, no hardware needed).
- `get_secrets_backend()` already routes to the TPM backend when
  `HYPROXY_SECRETS_BACKEND=tpm`.
- Config fields `secrets_backend` and `tpm_sealed_blob` exist.
- `rotate-master-key` (`python -m hyproxy.cli rotate-master-key`, Makefile
  `rotate-master-key`) re-wraps every sealed blob to the current key.
  Integration-tested end to end.

All of this is now implemented: `tpm_unseal()` shells out to `tpm2_unseal`
against the persistent handle in `HYPROXY_TPM_SEALED_BLOB` under the PCR
policy in `HYPROXY_TPM_PCRS` (default `sha256:0,2,4,7`), the server image
includes tpm2-tools, and `deploy/docker-compose.tpm.yml` passes the TPM device
into the control-plane services. `install.sh` automates Parts 2-4 end to end
for production installs (seal at install time, one-time plaintext printout for
the FIPS backup device, migration off a pre-existing file key, rotation, and
destruction of the on-disk key). The parts below remain as the manual
procedure and as reference for resealing after PCR-changing updates.

## Part 1: implement `tpm_unseal()`

`TpmSecretsBackend` calls the injected `unseal()` once at process start and
expects the SAME `key_id:base64key` text the file backend parses (last
non-comment line is the current key). Wire `tpm_unseal()` to run `tpm2_unseal`
under the sealing PCR policy and return that text on stdout. Keep the tpm2-tools
call the only hardware-touching code so the adapter stays testable.

Sketch (shell-out form; `tpm2-pytss` is an alternative):

```python
def tpm_unseal() -> str:
    import subprocess
    blob = get_settings().tpm_sealed_blob
    if not blob:
        raise RuntimeError("HYPROXY_TPM_SEALED_BLOB is empty")
    # Re-satisfy the PCR policy in a policy session, then unseal.
    # `blob` is the persistent handle (e.g. 0x81010001) the object was
    # evicted to in Part 2. PCR selection MUST match the sealing policy.
    out = subprocess.run(
        ["tpm2_unseal", "-c", blob, "-p", "pcr:sha256:0,2,4,7"],
        check=True, capture_output=True, text=True,
    )
    return out.stdout
```

Notes:
- The PCR selection here (`0,2,4,7`) MUST match whatever was used at sealing
  time in Part 2. PCR choice is a security-vs-brittleness tradeoff: binding to
  more PCRs (firmware, bootloader, kernel, Secure Boot state) means a firmware
  or kernel update reseals is required; too few weakens the binding.
- Fail closed: any non-zero exit or empty output must raise, so the process
  refuses to start rather than run without keys.

## Part 2: prepare the TPM on the host

Run on `hyproxy-dev`.

```sh
# 1. Confirm the TPM is present and tooling installed (Rocky/RHEL).
sudo dnf install -y tpm2-tools
tpm2_pcrread sha256:0,2,4,7          # sanity: device responds
ls -l /dev/tpmrm0

# 2. Produce the plaintext master-key text to seal. Reuse the current file key
#    so existing ciphertext still decrypts, and append a fresh key that will
#    become current after migration.
cp /etc/hyproxy/master.keys /tmp/master.keys.plain     # existing mk-1 line(s)
python -m hyproxy.cli ... # (or: append a new `mk-N:<base64-32-bytes>` line)
# The last non-comment line is the current key. Ensure the NEW key is last.

# 3. Seal that text to the TPM under a PCR policy.
tpm2_createprimary -C o -g sha256 -G ecc -c /tmp/primary.ctx

tpm2_startauthsession -S /tmp/session.dat
tpm2_policypcr -S /tmp/session.dat -l sha256:0,2,4,7 -L /tmp/pcr.policy
tpm2_flushcontext /tmp/session.dat

tpm2_create -C /tmp/primary.ctx -g sha256 \
    -u /tmp/sealed.pub -r /tmp/sealed.priv \
    -L /tmp/pcr.policy -i /tmp/master.keys.plain

# 4. Persist the sealed object to a stable handle and point config at it.
tpm2_load -C /tmp/primary.ctx -u /tmp/sealed.pub -r /tmp/sealed.priv -c /tmp/sealed.ctx
sudo tpm2_evictcontrol -C o -c /tmp/sealed.ctx 0x81010001

# 5. Scrub the plaintext.
shred -u /tmp/master.keys.plain
```

Then set in the deployment env:

```sh
HYPROXY_TPM_SEALED_BLOB=0x81010001    # the persistent handle from step 4
```

(Alternatively keep `sealed.pub`/`sealed.priv` as files and have `tpm_unseal`
`tpm2_load` them each start; the persistent handle is simpler.)

## Part 3: container passthrough (the deploy gotcha)

The control plane is containerized, so `tpm_unseal` runs INSIDE the server
container. The services that mount the master key today are `migrate`, `cli`,
`idp`, `admin`, and `authz` (`docker-compose.yml`, `secrets: [master_key]`).
For the TPM backend, either:

- Pass the TPM device into those services and add `tpm2-tools` to the server
  image. In `docker-compose.yml` add to each control-plane service:

  ```yaml
      devices:
        - /dev/tpmrm0:/dev/tpmrm0
  ```

  and install `tpm2-tools` in `server/Dockerfile`. The container user needs
  access to the device (group/permissions on `/dev/tpmrm0`).

- Or run the control plane on baremetal where the TPM is directly reachable.

Without this the container cannot reach the TPM even with `tpm_unseal` wired.

## Part 4: zero-downtime migration, then destroy the file key

The sealed blob from Part 2 contains BOTH the old key (`mk-1`, still current
until rotation) and the new key (`mk-N`, now last/current). Because both are
present, rotation can decrypt old ciphertext and re-wrap it to the new key in a
single transaction.

```sh
# 1. Switch the backend to TPM and restart the stack.
#    HYPROXY_SECRETS_BACKEND=tpm  (env / .env)
./start.sh

# 2. Re-wrap all sealed blobs (TOTP secrets, signing keys, connection secrets)
#    to the new current key.
python -m hyproxy.cli rotate-master-key        # or: make rotate-master-key

# 3. (Optional hardening) Re-seal a blob containing ONLY the new key and update
#    HYPROXY_TPM_SEALED_BLOB, so the retired key is gone from the TPM too.

# 4. Destroy the on-disk file master key. Invariant: no unsealed master-key
#    material on disk in production.
shred -u /etc/hyproxy/master.keys
```

## Verification

- On a TPM host, every envelope decrypt succeeds under the TPM backend (login
  with TOTP, existing connections resolve their secrets).
- `HYPROXY_SECRETS_BACKEND=tpm` and no `master.keys` file remains on disk.
- Rebooting into a changed firmware/kernel state (if bound in the PCR policy)
  makes `tpm2_unseal` fail closed; document the reseal procedure for planned
  updates.

## Related

- `docs/production.md` section 1 — design and invariants.
- `docs/production-checklist.md` — the migration line item.
- `docs/TODO.md` — TPM code task and container-passthrough item.
- `server/src/hyproxy/core/secrets.py` — the seam and `tpm_unseal` hook.
