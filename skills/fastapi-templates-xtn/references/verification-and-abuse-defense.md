# Verification And Abuse Defense

Read this reference when implementing password-login defense, registration
admission, or an explicitly requested CAPTCHA, email/SMS verification, MFA,
or other proof-of-possession flow. For password persistence, public login,
password change, administrator reset, or account recovery, read
[Local password authentication](local-password-authentication.md) first. Read
[Rate limiting and abuse-control quotas](rate-limiting.md) first. That reference
is the single source for applicable default limits, failure-signal retention,
challenge length/lifetime, attempt maximum, Redis failure rule, and `429001`
response.

The bundled asset provides reusable abuse and optional-verification services and
tests. The local-password asset supplies a concrete username baseline, Argon2id
credential verifier, and public/authenticated password routes, but it still does
not invent a product's identity fields, registration mode, verified recovery
channel, delivery provider, or optional verification purposes.

## Decisions Before Generating Code

First display the complete centralized baseline tables from the rate-limit
reference and ask whether the user accepts all applicable values or wants to
change named settings. Show the optional verification tables only when the user
has explicitly selected such a feature. Do not generate the affected code before
that answer.

Then ask only for product facts that code cannot infer:

- whether login uses `email`, `user_name`, phone, or an explicit combination;
- whether the product wants any optional CAPTCHA, email/SMS code, MFA, or other
  step-up feature at all;
- only when selected, which purposes and channels the product exposes and which
  delivery or verification provider it owns; and
- whether an existing project already has normalization, enumeration, and error
  contracts that must be preserved.

Do not ask again for numeric values the user already accepted. A username and
password are a complete default login scheme. Use the one-batch business gate in
the local-password reference before adding its signup/password model; do not
silently add an email or phone field, CAPTCHA, SMS/email provider, MFA, or
verification purpose. An existing email or phone field is not consent to use it
as a verification channel. The complete asset retains the tested email/SMS
modules in a dormant state; keep them disabled by default instead of making a
username/password-only adopter decide whether to delete files. Dormant modules
must not register routes or require their settings.

## Included Components

| Component | Responsibility |
| --- | --- |
| `SecurityPolicies` | Builds every named Token Bucket from validated settings |
| `AbuseDefenseService` | Composes login and registration bucket checks, optional verification-send/submit checks, and a non-blocking login-failure risk signal |
| `IdentityAbuseFlow` | Enforces admission, product real-or-dummy credential work, failure/success state, and registration callback ordering |
| `VerificationService` | Issues, validates, consumes, expires, replaces, and cancels purpose-bound challenges in Redis |
| `VerificationFlowService` | Orders send limits, challenge issuance, provider delivery, cleanup, submission limits, and challenge consumption |
| `VerificationDeliveryAdapter` | Optional product-supplied email/SMS delivery only |

Keep these boundaries. A delivery adapter never decides authorization, owns
Redis state, generates codes, or applies rate limits. A verification service
never verifies passwords or creates users.

## Abuse-Defense Composition

All account and target values passed to `AbuseDefenseService` must already use
the product's canonical identity normalization. The service rejects blank,
untrimmed, control-bearing, or oversized identities. It canonicalizes only a
trusted IPv4/IPv6 address; deriving that address from a proxy chain remains a
deployment boundary described in the rate-limit reference.

### Login attempt

Product login routes use `IdentityAbuseFlow.authenticate(...)`; do not manually
rebuild its ordering in each route. It performs this sequence:

1. `AbuseDefenseService.check_login_attempt` atomically checks the trusted-IP,
   IP-plus-account, and global login Token Buckets as one all-or-nothing batch.
   These are the only hard login-admission limits.
2. Only after admission, call the product's
   `verify_real_or_dummy_credentials` callback. The callback performs the real
   credential check or equivalent dummy work and returns a verified value or
   `None`; it must not issue a Token.
3. `None` records one login-failure risk signal, then raises the single
   public-safe `InvalidLoginCredentialsError`.
4. A verified value clears the stale failure signal and is returned. A previous
   failure count never prevents the credential callback from checking a correct
   password.
5. Only the caller, after a successful `authenticate` return, may begin Access
   Token issuance.

On a failed credential decision, the flow calls
`record_login_failure(normalized_identifier)`. One Redis Lua call atomically
increments the private consecutive-failure signal and applies its configured
finite retention. On a successful credential decision, call
`record_login_success(...)`; it deletes the failure state and fails closed if
Redis cannot confirm the operation. Invalid credentials must return `None` from
the callback; an infrastructure exception propagates and must not be mislabeled
or counted as a bad password.

The counter is only a risk signal for monitoring or a separately selected
step-up feature. `check_login_attempt` does not read it, the counter never raises
a quota denial, and its value alone never prevents a correct-password attempt.
Do not reintroduce an account-only bucket, account lock, or pre-password denial;
an attacker who knows a username must not be able to lock out that account.

The failure key contains only an HMAC digest:

```text
abuse:v1:<static_namespace>:login_failure:<hmac_sha256>
```

The asset supplies this state machine, not a login route or password verifier.
When adapting it, use one generic `401001` response for an unknown user, wrong
password, deleted/disabled/suspended identity, or other invalid credential state.
Run the same configured password-hash work for an unknown local-password user to
reduce account enumeration. Do not expose whether an account exists, which
risk threshold a product may use internally, or how many failures were recorded.

### Registration attempt

Product registration routes use `IdentityAbuseFlow.register(...)`. It first calls
`check_registration_attempt(...)` to atomically check four Token Buckets:

- trusted client IP;
- normalized target/account;
- trusted IP plus normalized target; and
- global registration traffic.

Only after all four admit does the flow call the product's
`registration_action`. A denial or Redis failure must leave that callback
uninvoked. Passing admission neither reserves an identifier nor proves ownership.
PostgreSQL uniqueness remains the race authority. Proof of email/phone ownership
uses a separate purpose-bound challenge only when the user explicitly selected
that product requirement; username-and-password registration does not imply it.
Normal registration must still assign only the baseline `user` role.

### Verification send

This section and the remaining challenge contract apply only when the user chose
the optional email/SMS code module and enabled at least one purpose and channel.
The module is off by default. CAPTCHA and MFA need their own selected integration
and must not be represented as capabilities of this code-delivery service.

`check_verification_send(...)` normalizes the email/SMS target and atomically
checks six buckets: target cooldown, target average bucket, trusted IP,
IP-plus-target, channel, and global sends. The average policy has the exact
continuous Token Bucket behavior documented in the central table: it starts with
the configured credits and replenishes the configured daily average gradually
while below capacity. Do not present it as a hard per-calendar-day or
arbitrary-24-hour counter.

### Verification submission

`check_verification_attempt(...)` atomically checks four independent submission
buckets: trusted IP, normalized target, IP-plus-target, and global submissions.
These limits run before `VerificationService.verify_challenge`. They complement,
not replace, the per-challenge wrong-attempt maximum.

Any batch denial raises `RateLimitExceeded` using the denied bucket with the
longest wait. If any required Redis operation fails or returns malformed state,
raise an unavailable error and do not continue to credential verification,
registration, delivery, Token issuance, or the protected action.

## Verification Challenge Contract

The asset defines closed channel enums `email` and `sms`, and these purpose
enums:

```text
registration
login
password_reset
email_change
phone_change
sensitive_action
```

`email_change` accepts email only; `phone_change` accepts SMS only. Other
included purposes permit either channel at the service layer. Expose only the
subset the product actually implements.

Email targets are trimmed and case-folded and must satisfy the asset's bounded
basic email shape. SMS targets must use a plus-prefixed international number
shape. Replace or extend normalization only as one product-wide identity change;
rate-limit and challenge lookup must use exactly the same result.

A challenge is bound to the complete tuple:

```text
(challenge_id, purpose, channel, normalized_target, code)
```

The challenge ID is UUIDv4. The numeric code is generated with `secrets`, keeps
leading zeroes, and uses the centralized server-owned length. The HMAC includes
the challenge ID, purpose, channel, target digest, and candidate code. The
verification HMAC secret is distinct from JWT signing and rate-limit HMAC keys.

Plaintext target and code exist only in the internal
`VerificationDeliveryPayload` private attributes long enough for the delivery
adapter. Pydantic serialization and representation omit them. The public issue
result contains only `challenge_id` and `expires_in_seconds` before the common
API envelope is applied.

## Redis Challenge State

For one normalized target, purpose, and channel, all three keys share the target
HMAC as a Redis Cluster hash tag:

```text
<namespace>:{<target_hmac>}:<purpose>:<channel>:active
<namespace>:{<target_hmac>}:<purpose>:<channel>:challenge:<challenge_hmac>
<namespace>:{<target_hmac>}:<purpose>:<channel>:state
```

Redis stores only HMAC fingerprints and bounded state: challenge fingerprint,
code digest, target fingerprint, purpose, channel, attempts used, and recent
`issued`, `expired`, `consumed`, or `cancelled` status. It never stores the raw
target, raw challenge ID, or plaintext code. Challenge and active-pointer TTLs
use the configured challenge lifetime; the small state marker remains only for
the configured additional status-retention interval. No verification key is
permanent.

The asset uses three reviewed Lua operations through direct Redis `EVAL`:

- issue atomically invalidates the prior active challenge for the same scope,
  writes the new challenge/pointer/state, and applies all TTLs;
- verify atomically checks every binding field, increments a wrong code against
  the matching active challenge, consumes it at the configured maximum, and
  allows only one concurrent success;
- cancel removes only the still-matching active challenge and marks it cancelled,
  so a failed older delivery cannot delete a newer resend.

Malformed or contradictory Redis state is an unavailable dependency, not an
incorrect code. Internally the service can distinguish recently expired from
unknown/consumed state for tests and control flow; the public API intentionally
uses one generic invalid-or-expired response.

## Send And Verify Flow

`VerificationFlowService.issue_and_send(...)` runs:

1. all six verification-send limits;
2. atomic challenge issue/replacement;
3. the product delivery adapter; and
4. public-result conversion only after delivery succeeds.

If delivery raises or the task is cancelled, the flow attempts shielded,
compare-and-cancel cleanup. It never refunds the independent send quota. Cleanup
failure does not leak provider/Redis details and is bounded by the short
challenge TTL. A delivery failure becomes
`VerificationDeliveryUnavailableError`, never the provider's raw exception.

`VerificationFlowService.verify(...)` runs all four submission limits and then
atomically consumes the bound challenge. A returned `VerifiedChallenge` proves
only the named target possession for its exact purpose and channel. The product
must still perform current authentication, authorization, hierarchy, and
PostgreSQL transaction checks for the protected action.

Redis challenge consumption and a PostgreSQL business commit are not one ACID
transaction. The bundled baseline uses the simple contract: consume the code,
then require a new code if the later business transaction fails. Do not claim a
cross-system all-or-nothing guarantee that the implementation does not provide.

## Delivery Adapter

Implement this product-owned port without putting provider details into the
security services:

```python
class VerificationDeliveryAdapter(Protocol):
    async def send(
        self,
        *,
        channel: VerificationChannel,
        normalized_target: str,
        purpose: VerificationPurpose,
        code: str,
    ) -> None: ...
```

The adapter may format and send a provider request. It must not generate the
challenge, change TTL/attempt state, refund quota, decide user existence, or log
the destination, code, provider request/response, credentials, or raw exception.
Use a capture adapter only in isolated tests; never return a code through a
production HTTP response or stdout adapter.

## Public Errors And Logs

Use the common response envelope and these public mappings:

| Condition | Result |
| --- | --- |
| Valid Token Bucket denial | HTTP `429`, `429001`, `Retry-After`, `Cache-Control: no-store` |
| Required Redis state unavailable/malformed | HTTP `503`, `503001`, no `Retry-After`, `Cache-Control: no-store` |
| Delivery unavailable | HTTP `503`, `503001`, no provider detail and no `Retry-After` |
| Invalid, expired, consumed, mismatched, or exhausted challenge | HTTP `400`, `400001`, one generic message |
| Invalid login credential/state | Product login adapter returns HTTP `401`, `401001`, one generic message |

Every response carries the same server UUIDv4 in the body and `X-Request-ID`.
Never reveal the denying dimension, target existence, wrong-attempt count,
internal failure-risk signal, expiry distinction, or provider result.

The asset uses `rate_limit.denied` at `WARNING` for Token Bucket denial,
`dependency.rate_limit.unavailable` at `ERROR` for admission Redis failure, and
`dependency.verification.unavailable` at `ERROR` for challenge or delivery
failure. Never log raw IP, normalized account/target, email, phone, code, HMAC,
complete Redis key, Token/JTI, provider credential or body, Redis URL, exception
message, or request body. Follow [Operational logging](operational-logging.md).

## Required Verification

Use a real supported Redis for Lua, TTL, and concurrency checks. Prove:

- each delivered login and registration method selects every documented bucket
  and a denial consumes none of the batch;
- `IdentityAbuseFlow` calls no product callback after admission denial or Redis
  failure; invalid login `None` records one failure, verified login clears state
  before returning, the application Token issuer is never invoked inside the
  credential callback and runs only after return, and registration action starts
  only after admission;
- account failure signals increment atomically under concurrency, use finite
  retention, clear on success, are not read by login admission, and cannot block
  a correct-password callback by themselves;
- the default disabled-verification configuration requires no verification
  secret, purpose, channel, provider, or route;
- when code verification is explicitly enabled, each send and submit method
  selects every documented bucket and target normalization is shared by rate
  limiting, issue, verify, and cancel;
- issue stores no plaintext target/code/raw challenge ID, all keys share one
  target hash slot, and a resend invalidates only the previous challenge;
- every candidate reaches one atomic verification script; a wrong code for the
  matching active challenge increments its attempt count, the configured final
  wrong-code attempt consumes it, and exactly one concurrent correct submit
  succeeds;
- expiry, consumption, cancellation, malformed state, and Redis failure map to
  the documented safe outcomes;
- provider failure/cancellation cleans up only the matching challenge, does not
  refund quota, and exposes no provider data;
- public issuance never serializes delivery target or plaintext code; and
- `429` contains a rounded-up `Retry-After`, while every dependency `503` omits
  it and never runs the protected action.

Unit tests with a mocked `eval` prove argument and result validation. They do not
replace the real-Redis integration suite for scripts, server time, expiry,
replacement races, and single-use concurrency.
