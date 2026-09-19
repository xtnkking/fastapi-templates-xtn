# Graphical CAPTCHA And Authentication Admission

Read [Rate limiting](rate-limiting.md) first for the single Redis fixed-window
policy and default numbers. This reference describes the required graphical
CAPTCHA baseline. It does not create email, SMS, MFA, or account-recovery flows.

All five graphical CAPTCHA scenes below are mandatory for the new-project
baseline. Only email/SMS verification and MFA are optional extensions. There is
no anonymous forgot-password flow in this Skill; temporary-password completion
starts only after an authorized administrator reset.

## Five Fixed Scenes

| Scene | Caller | Protected action |
| --- | --- | --- |
| `login` | Anonymous, trusted IP for issuance limit | Password login |
| `register` | Anonymous, trusted IP for issuance limit | Public registration |
| `admin_create` | Authenticated actor user ID | Administrator creates a user |
| `admin_reset` | Authenticated actor user ID | Administrator resets a lower user's password |
| `self_change` | Authenticated actor user ID | User changes own password |

Require challenge ID and answer in each protected request. A login or
registration attempt lacking valid CAPTCHA must not check the password, create
a user, or issue a JWT. Administrative actions still check Bearer/JTI, RBAC,
strict target hierarchy, and the PostgreSQL transaction; CAPTCHA is only a
minimum defense against automated submissions, not proof of account ownership.
Self password change still requires the old password. Administrator creation
and reset do not ask for the actor's password a second time.

Use `POST /api/v1/auth/captcha` for the first two scenes and authenticated
`POST /api/v1/me/captcha` for the other three. For authenticated scenes,
derive the owner user ID from full server-side authentication; never accept an
owner or target ID in the CAPTCHA issue request. Every issuance/refresh spends
one scene-specific quota (10 per five minutes by default), separate from the
quota for the protected action. Never add a shared all-scene/all-IP/global
bucket or a username-keyed limit. On a rejected refresh, leave the old image
unchanged and usable until expiry or consumption.

A valid scene sent to the wrong issue endpoint, or a parsed CAPTCHA request
with invalid fields, is rejected without issuing or refreshing an image. Count
such requests in one separate
`captcha_rejected_scene` fixed window (10 per five minutes by default), keyed
by trusted IP at the public endpoint or the authenticated actor ID at the
authenticated endpoint. It shares neither a normal scene's issuance quota nor
a global quota; changing the CAPTCHA quota settings also changes this rejection
quota. On excess return `429001`; unavailable Redis or trusted IP returns
`503001`, never an unmetered issue. Unknown/invalid scene values still receive
normal request validation errors when admitted. Invalid JSON syntax is rejected
before authentication dependencies run.

## Challenge Lifecycle

- Generate a cryptographically random, unguessable challenge ID and image
  answer. Issue the image only in the immediate protected response; never put
  the answer in JSON, OpenAPI examples, logs, audit, or a persistent file. Keep
  the answer's verifier, fixed scene, optional authenticated owner, and expiry
  in Redis with a five-minute TTL. Do not store a plaintext answer.
- Submit once. A single atomic Redis Lua operation checks challenge ID,
  expected scene, owner binding, and answer, then deletes its challenge/pointer
  keys even when the answer or binding is wrong. A missing, expired, consumed,
  or mismatched challenge yields one generic invalid-or-expired error. If Redis
  cannot confirm consumption, fail closed (`503001`) and do not run the action.
  Two concurrent submissions cannot both succeed.
- A page may refresh using its old challenge ID. Under one atomic Redis
  operation, replace only a still-active old challenge with a new challenge.
  Concurrent refreshes of the same old ID allow only one winner; a submit that
  consumed first prevents refresh, and a refresh that won first invalidates the
  old answer. An anonymous page must provide its own old ID: without anonymous
  session state, the server cannot claim two unrelated pages share one image.
- After successful CAPTCHA consumption, later password, authorization, or
  registration failure does not restore it. Return the normal business error;
  the next protected attempt needs a fresh challenge.

Issue and refresh routes should expose only the required scene and challenge
ID/image, wrapped in the standard `code`, `message`, `data`, `request_id`
response. Set `Cache-Control: no-store`, avoid cross-origin leaks, and never
echo a raw Redis key or HMAC verifier. For user interfaces, add a refresh action
and clear the previous answer and ID after every submit, successful or not.

## Simple Login/Registration Ordering

`IdentityAbuseFlow` retains a small explicit boundary: fixed-window admission
before product callbacks; a denial/unavailable Redis does not invoke the
callback. The exact order is trusted-IP resolution and the named login/register
fixed-window check, then scene-bound CAPTCHA validation/consumption, then
credential verification or the registration transaction, then Token issuance
for a successful login. Invalid CAPTCHA attempts therefore spend the business
quota, while a rate-limit rejection does not consume the submitted CAPTCHA.
Invalid credentials return one generic
`401001`, including unknown, disabled, deleted, missing-hash, and wrong-password
cases. Perform one real-or-dummy Argon2 verification, with no per-username
failure counter, login lock, or `IP+username` quota. Only after the callback
returns a verified account may the route issue a JWT and register its JTI.
Registration stores only `user`, returns an ID, and does not log in the new
user. Both operations read the current server-side registration policy where
applicable.

The optional email/SMS and MFA variants are out of this base asset. If a later
product explicitly needs one, decide its actual owner, proof semantics,
provider, purpose, and per-business IP/user limit before implementing it.
Do not re-enable unused delivery adapters or silently make an email field
mandatory.

## Verification

Run real-Redis concurrency and TTL tests for issue, refresh, wrong-answer
consumption, wrong-scene/owner consumption, one-winner success, and Redis
outages. Route tests prove each of the five endpoints requires the correct
scene, submission limits are independent of issuance quotas, invalid CAPTCHA
skips the protected work, wrong-endpoint and parsed invalid requests have the separate per-subject
quota and never produce an image or spend a valid scene quota, and the image
answer/credentials/JWT never appear in logs or audits. Test public registration
disabled and re-enabled while an already displayed form is open; the server
wins over the page state.
