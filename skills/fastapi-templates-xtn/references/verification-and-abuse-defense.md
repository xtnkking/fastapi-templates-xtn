# Graphical CAPTCHA And Authentication Request Checks

Read [Rate limiting](rate-limiting.md) first for the single Redis fixed-window
policy and default numbers. This reference describes the required graphical
CAPTCHA baseline. It does not create email, SMS, MFA, or account-recovery flows.

All five graphical CAPTCHA scenes below are mandatory for the new-project
baseline. Only email/SMS verification and MFA are optional extensions. There is
no anonymous forgot-password or temporary-password completion flow in this Skill.
Administrator creation and authorized reset set a directly usable password.

## Five Fixed Scenes

| Scene | Caller | Protected action |
| --- | --- | --- |
| `login` | Anonymous, trusted IP for issuance limit | Password login |
| `register` | Anonymous, trusted IP for issuance limit | Public registration |
| `admin_create_user` | Authenticated user ID | Administrator creates a user |
| `admin_reset_user_password` | Authenticated user ID | Administrator resets a lower user's password |
| `user_change_password` | Authenticated user ID | Current user changes own password |

`app/core/captcha.py` is the sole definition of allowed purposes and their login
requirements. `CaptchaCreateRequest.scene` uses its `CaptchaScene` enum for
Pydantic validation. The public/private string sets are generated from this
enum and its `requires_login` property for rate limits and issue routes.
Services receive `CaptchaScene` members directly and read `scene.requires_login`
to check the user parameter; do not convert to strings and look up another list.
Frontends send the enum's string values: `login`, `register`, `admin_create_user`,
`admin_reset_user_password` or `user_change_password`. The matching enum members
are `LOGIN`, `REGISTER`, `ADMIN_CREATE_USER`, `ADMIN_RESET_USER_PASSWORD` and
`USER_CHANGE_PASSWORD`. Digest serialization uses `scene.value` together with
the authenticated user ID, challenge ID and answer. Renaming a scene changes
its bound digest and issuance counter; fetch a fresh image and use the new
value in both frontend and backend. Do not add old-value aliases or fallback reads.

To add a purpose, add an enum member in that file. New members require login by
default; for a reviewed anonymous purpose, also name that member in the property's
explicit public exceptions. Add the corresponding action's
`require_captcha(CaptchaScene.<PURPOSE>)` dependency and frontend request, then
test its issuance, owner binding and
wrong-purpose rejection. Do not duplicate the list in the Schema, limiter,
Service or issue routes. Removing a purpose requires removing its business and
frontend use too; ordinary API rate limits do not change these definitions.

Require challenge ID and answer in each protected request. A login or
registration attempt lacking valid CAPTCHA must not check the password, create
a user, or issue a JWT. Administrative actions still check Bearer/JTI, RBAC,
strict target hierarchy, and the PostgreSQL transaction; CAPTCHA is only a
minimum defense against automated submissions, not proof of account ownership.
Self password change still requires the old password. Administrator creation
and reset do not ask for the current user's password a second time.

Use `POST /api/v1/auth/captcha` for the first two scenes and authenticated
`POST /api/v1/me/captcha` for the other three. For authenticated scenes,
derive the owner user ID from full server-side authentication; never accept an
owner or target ID in the CAPTCHA issue request. Public `login` and `register`
challenges are deliberately **not** bound to the issuing IP: a legitimate user
whose VPN or mobile-network exit changes can still submit the displayed image.
They remain bound to their fixed scene, five-minute expiry, and one-use atomic
consumption. Possession of both the challenge ID and answer is therefore
transferable; this is an explicit availability tradeoff, and CAPTCHA is not
account-ownership proof. Issuance and the later login/register submission are
still independently limited by the trusted IP observed for that request.
Every issuance spends
one scene-specific quota (10 per five minutes by default), separate from the
quota for the protected action. Never add a shared all-scene/all-IP/global
bucket or a username-keyed limit. A new image does not revoke older images;
each remains usable until expiry or its one allowed submission.

For the authenticated issue route, JWT and active-JTI validation is followed by
one atomic count of the exact private-scene current user window before PostgreSQL account
loading. A count exceeding the scene limit returns `42901` without a database
read. Missing/unknown scenes and public scenes count the separate
`captcha_invalid_scene` window instead. Admission continues to current-account
validation without another count; a later disabled/stale-account denial keeps
that count and attempts to revoke the exact JTI.

A valid scene sent to the wrong issue endpoint, or a missing/unknown scene,
is rejected without issuing an image. Count such requests in one separate
`captcha_invalid_scene` (purpose invalid for this issue endpoint) fixed window
(10 per five minutes by default). This counts invalid image requests, not wrong
CAPTCHA answers submitted to business operations. It is keyed
by trusted IP at the public endpoint or the authenticated current user ID at the
authenticated endpoint. It shares neither a normal scene's issuance quota nor
a global quota; changing the CAPTCHA quota settings also changes this rejection
quota. On excess return `42901`; unavailable Redis or trusted IP returns
`50301`, never an unmetered issue. Unknown/invalid scene values still receive
normal request validation errors when admitted. A valid scene with another
invalid field spends its scene quota before the route returns `422` without an
image. Invalid JSON syntax is rejected before authentication dependencies run.

## Challenge Lifecycle

### Readable Service Flow

`app/services/captcha_service.py` exports one stateless `captcha_service` instance
per process. Pass the current application's Redis client and Settings into
`create_captcha` and `verify_captcha`; keep the scene, owner, ID and answer local
to the call. Do not construct a Service on each image request or store request
data on the shared instance.

`create_captcha` returns `CaptchaResponse` business data: the ID, image and
expiry. Each CAPTCHA route calls the Service directly and wraps that data with
`api_response`. Keep success codes, localized messages and request IDs at the
route boundary. `dependencies/captcha.py` only adapts verification and
single-use consumption; do not add an issuance/response forwarding helper.

`create_captcha` visibly validates the purpose/login requirement, generates the
ID and answer, builds the bound digest and image, then writes only the digest
with NX and a five-minute TTL. `hash_captcha_code` includes the fixed scene,
authenticated `user_id` (empty for public purposes), ID and case-normalized answer
in one HMAC. A fixed JSON list encodes the input fields without ambiguity; it is
only hashing input, not a Redis record to parse later.

`validate_scene_user` is the shared parameter check for issuance and verification.
It receives the enum, requires a nonempty authenticated `user_id` for login-required
purposes, and requires `None` for public purposes. It returns nothing and does not
authenticate, access Redis, or normalize the user ID. The digest method alone
encodes a public purpose's `None` as an empty string.

`verify_captcha` validates its server-side scene/user inputs, performs one Redis
`GETDEL` to atomically retrieve and remove the digest, checks its format, then
compares `expected_code_hash` and `input_code_hash` with `hmac.compare_digest`.
The baseline Redis is dedicated to this service. Store each challenge at
`captcha:<UUID>` without environment/service identifiers, namespace hashes or
hash-tag braces. `build_redis_key` takes only the challenge ID. Scene and user
are bound in the digest, so submitting a challenge at another allowed scene or
user still removes that same challenge.
Bindings differ in the digest and cannot pass comparison. Both correct and
incorrect submissions consume it, and only one concurrent request gets the
stored digest. Keep these stages visible with Chinese comments.

Use meaningful helper names: `build_redis_key`, `hash_captcha_code`,
`validate_scene_user` and `build_png_base64_image`. Do not restore JSON-record
parsing, custom CAPTCHA Lua or a read-then-delete chain; Redis 7 provides the
required atomic `GETDEL`. Redis errors or a malformed digest fail closed with
`50301`; missing, expired or already consumed challenges use the generic CAPTCHA
error. A storage-format change requires fresh images, not an added compatibility
parser or database migration.
A key-format change requires fetching a fresh image; old challenge keys expire
on their existing five-minute TTL. Do not add a fallback reader for old keys.
`dependencies/captcha.py` exposes `require_captcha(CaptchaScene)` for the five
protected actions. Each route declares the fixed purpose explicitly:

```python
captcha_checked: None = Depends(require_captcha(CaptchaScene.LOGIN)),
```

Keep the route's limit or authorization dependency before `captcha_checked` in
the parameter list. Login/register declare their named IP limiter there; own
password change declares its authorization context, and administrator actions
declare their exact permission dependency. FastAPI resolves these dependencies
in declaration order. A limit or authorization denial stops before CAPTCHA.
Do not move these checks into `require_captcha` or build a scene-to-business
model/permission/limit dispatcher there.

The CAPTCHA dependency reads `request.json()`, rejects non-object JSON, and uses
the shared `read_body_field` helper to extract `captcha_id` and `captcha_answer`.
Required values must be non-blank strings; preserve their original text instead
of converting numbers/lists or trimming the answer. Convert the ID with `uuid.UUID`
and enforce the answer's 16-character maximum, then call `captcha_service.verify_captcha`.
Do not manually validate a Pydantic model and translate its error list here.
Private purposes read `request.state.user_id`, which the preceding complete
authentication dependency writes only after confirming the live account and
Token version; a missing user fails closed. This does not authenticate or load
the account again. Public purposes pass `user_id=None`. Service parameters,
local variables and digest inputs all use `user_id`; do not introduce a
separate identity name for CAPTCHA. Client-supplied scene/user fields never
select these server-side bindings. Redis stores only the 64-character digest;
the scene and user ID are included when generating and comparing that digest.

Malformed JSON encountered by the dependency, non-object JSON and CAPTCHA-field
errors use the existing `invalid_request` business exception (HTTP 400 / `40001`),
without consuming a challenge. FastAPI may reject JSON syntax before executing
dependencies, in which case its normal `42201` response remains. Other business
fields are validated by the route's own model;
their errors may be reported after a valid CAPTCHA has already been consumed.
Do not manually repeat complete business-model validation to avoid this timing.
The dependency returns `None`; successful resolution allows the route to continue.
Keep business response composition in routes and do not add verification wrappers.

- Generate a cryptographically random, unguessable challenge ID and image
  answer. Issue the image only in the immediate protected response; never put
  the answer in JSON/schema examples, logs, audit, or a persistent file. Keep
  the bound answer verifier in Redis with a five-minute TTL. Do not store a
  plaintext answer.
- Submit once. Use `GETDEL` before deciding whether the fixed scene,
  authenticated user and answer produce the expected digest. A wrong answer or
  binding still consumes the challenge; malformed stored content is also removed.
  A missing, expired, consumed,
  or mismatched challenge yields one generic invalid-or-expired error. If Redis
  cannot confirm consumption, fail closed (`50301`) and do not run the action.
  Two concurrent submissions cannot both succeed.
- Every request creates a new challenge ID and image without reading or deleting
  an older challenge. Concurrent requests may each receive an image; each image
  has its own five-minute expiry and one-use atomic submission. The client keeps
  only the image and ID it chooses to display.
- After successful CAPTCHA consumption, later password, authorization, or
  registration failure does not restore it. Return the normal business error;
  the next protected attempt needs a fresh challenge.

Issue routes should expose only the required scene and challenge
ID/image, wrapped in the standard `code`, `message`, `data`, `request_id`
response. Set `Cache-Control: no-store`, avoid cross-origin leaks, and never
echo a raw Redis key or HMAC verifier. For user interfaces, requesting a new
image replaces the displayed image, ID and answer; clear them after every
submit, successful or not. An older image is not revoked merely because the
client requested a new one.

## Simple Login/Registration Ordering

The authentication route declares its named rate-limit dependency together
with `Depends(require_captcha(CaptchaScene.LOGIN))` or the register equivalent.
Declare the named limiter before `captcha_checked`; the CAPTCHA dependency does
not call it again. Preserve this parameter order when editing routes. A
denial or unavailable Redis stops before CAPTCHA consumption or product work.
Limit selection and counting remain in `dependencies/rate_limit.py`; the
CAPTCHA Service owns verification and one-time invalidation.
The exact order is trusted-IP resolution and the named login/register
fixed-window check, then scene-bound CAPTCHA validation/consumption, then
credential verification or the registration transaction, then Token issuance
for a successful login. Invalid CAPTCHA attempts therefore spend the business
quota, while a rate-limit rejection does not consume the submitted CAPTCHA.
Invalid credentials return one generic
`40110`, including unknown, disabled, deleted, missing-hash, and wrong-password
cases. Perform one real-or-dummy Argon2 verification, with no per-username
failure counter, login lock, or `IP+username` quota. Only after `AuthService`
returns a verified account may the route issue a JWT and register its JTI.
Registration stores only `user`, returns an ID, and does not log in the new
user. Public registration has no enable/disable switch; it still requires the
database's authorization state and the mandatory `user` role to be available.

The optional email/SMS and MFA variants are out of this base asset. If a later
product explicitly needs one, decide its actual owner, proof semantics,
provider, purpose, and per-business IP/user limit before implementing it.
Do not re-enable unused delivery adapters or silently make an email field
mandatory.

## Verification

Run real-Redis concurrency and TTL tests for independent issues, wrong-answer
consumption, wrong-scene/private-owner consumption, anonymous use after a
client-IP change, one-winner consumption, and Redis
outages. Route tests prove each of the five endpoints requires the correct
scene, submission limits are independent of issuance quotas, invalid CAPTCHA
skips the protected work, wrong-endpoint and missing/unknown scenes have the separate per-subject
quota and never produce an image or spend a valid scene quota. A valid scene
with another invalid field spends only its scene quota and produces no image. The image
answer/credentials/JWT never appear in logs or audits. Verify that public
registration remains available without a registration-switch route or setting.
