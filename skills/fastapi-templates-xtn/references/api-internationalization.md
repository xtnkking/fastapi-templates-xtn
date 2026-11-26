# API Internationalization

Use this reference when adding or changing client-visible API text. The baseline
supports Simplified Chinese (`zh-CN`) and English (`en`) without a database
locale column, Cookie, query parameter, or third-party translation framework.
Additional languages are an explicit project extension.

## Bundled Files And Call Flow

The feature is implemented in the bundled asset, not only described here:

- [`app/core/i18n/messages.py`](../assets/postgresql-rbac/app/core/i18n/messages.py) defines `MessageKey`,
  validates both catalogs at import time, and translates message keys.
  `translate_for_locale(locale, key)` resolves a message without a Request.
- [`app/core/i18n/language.py`](../assets/postgresql-rbac/app/core/i18n/language.py) selects a
  bounded request locale from `Accept-Language`, keeps it on this request only,
  and applies `Content-Language` and `Vary` response headers.
- [`app/core/i18n/validation_messages.py`](../assets/postgresql-rbac/app/core/i18n/validation_messages.py)
  maps Pydantic error types to safe translated messages and bounded field names.
- [`app/assets/locales/zh-CN.json`](../assets/postgresql-rbac/app/assets/locales/zh-CN.json)
  contains the Simplified Chinese runtime messages.
- [`app/assets/locales/en.json`](../assets/postgresql-rbac/app/assets/locales/en.json) contains
  the English runtime messages. Both JSON files must have exactly the same keys
  as `MessageKey`.
- [`app/core/response.py`](../assets/postgresql-rbac/app/core/response.py) translates
  stable keys while building success and error envelopes.
- [`app/core/access/permissions.py`](../assets/postgresql-rbac/app/core/access/permissions.py) maps
  each built-in `PermissionKey` to a description `MessageKey` in `PERMISSION_CATALOG`.
  `get_permission_description(key, stored_description=..., locale=...)` translates
  built-in descriptions and preserves stored custom descriptions; its locale
  defaults to `zh-CN` for initial data preparation.
- [`app/core/middleware/request_logging.py`](../assets/postgresql-rbac/app/core/middleware/request_logging.py)
  resolves the request locale and attaches `Content-Language` plus `Vary` to
  every HTTP response. [`app/core/exception_handlers.py`](../assets/postgresql-rbac/app/core/exception_handlers.py)
  localizes framework and unexpected errors; `app/main.py` registers both owners.
- [`tests/test_i18n.py`](../assets/postgresql-rbac/tests/test_i18n.py) covers
  catalog parity, negotiation, success/error/validation messages, headers,
  unsafe input, and concurrent Chinese/English requests.

The runtime call flow is:

```text
Accept-Language
-> RequestLoggingMiddleware calls language.locale_for_request()
-> canonical locale is stored on request.state
-> route/service or exception selects a stable MessageKey
-> api_response(), error_content(), or validation_messages.validation_message()
   calls i18n.translate()
-> response contains localized message plus Content-Language and
   Vary: Accept-Language
```

When adding client-visible text, add a `MessageKey`, add the same key to both
catalogs, use that key at the response boundary, and extend `test_i18n.py`.
Rendered Chinese or English literals in routes and services bypass this flow and
are not allowed.

New-password policy length messages use `{min_length}` and `{max_length}` in both catalogs.
`translate_for_locale` fills these from the password module's shared bounds;
changing the bounds does not require editing translated numbers. Only trusted
code constants supply these values; never format a password or raw request into
the message.

Username format messages use `{min_length}`, `{max_length}` and `{characters}`.
`translate_for_locale` fills them from `core/security/user_name.py`, including
the character label for the selected language. The request/query descriptions
and ORM constraints use that same owner; do not hard-code another length in
either language catalog. The two character labels are rule-owned bilingual
fragments kept beside the allowed character range; complete error sentences
remain in the language catalogs. This does not permit rendered error messages
elsewhere in that rule file or in routes and Services.

Password request-validation errors use `validation.password_too_short` or
`validation.password_too_long` with `{length}` taken only from Pydantic's positive
integer `ctx.min_length` or `ctx.max_length`. This reports the actual field
constraint: login/current-password input has an independent transport boundary,
while `NewPassword` uses the current setting policy. Do not guess the range from
the field name `password`, which appears in both login and registration.
Missing or invalid length context falls back to the generic localized text-length
message; no input value or other exception context is returned.

Permission list/detail endpoints pass `locale_for_request(request)` to
`PermissionService`; its response construction calls `get_permission_description()`.
The catalog stores message keys, so user-owned initialization obtains stored text
with `get_permission_description(key)`. Adding a business permission requires a
description `MessageKey` and real text in both Chinese and English catalogs.

## Runtime Contract

The client may send the standard `Accept-Language` request header. Missing,
unsupported, malformed, or oversized values fall back to `zh-CN`; they never
produce `406` and are never reflected in a response. Recognize `zh`, `zh-CN`,
`zh-Hans`, `zh-SG`, `en`, and English regional tags such as `en-US`. Among
recognized candidates, choose the highest positive `q` weight; ties keep the
first candidate. `q=0` skips that candidate, and `*` does not choose a language.
If no candidate remains, use `zh-CN` even when the request rejected it; this
small bilingual default does not implement full HTTP language negotiation.
Bound both header length and the number of parsed ranges.

Every HTTP response carries the canonical selected value in
`Content-Language` and merges `Accept-Language` into `Vary` exactly once. This
prevents a cache from serving an English representation to a Chinese request or
the reverse. The ordinary JSON envelope remains exactly `code`, `message`,
`data`, and `request_id`; never add a `locale` field.

Only human-facing runtime text is localized:

- successful command and query `message` values;
- domain, authentication, authorization, CAPTCHA, rate-limit, dependency, and
  unexpected-error `message` values;
- the outer validation message and safe `data.errors[].message` values; and
- built-in permission `data.description` values in catalog list/detail results; and
- liveness and readiness messages, only when the adopter explicitly requests
  those probes. The default project has none; requested probes must be limited
  to an internal network or trusted probes.

HTTP status, numeric business code, response shape, field names, machine values
inside `data`, request ID, permission keys, role keys, stable log events, audit
actions, audit outcomes, and internal `reason_code` values remain
language-independent. Database-authored product content and static schema
descriptions are separate product concerns; do not claim they are translated by
the runtime message module.
The default public `Field` and `Query` descriptions use Chinese to explain input
and output meaning in source and validation metadata. They remain static when
`Accept-Language: en` is sent; this does not mean runtime API translation is missing. Preserve field
names, constraints and machine values while adding those descriptions. See
[Python comments](python-comments.md) when changing documentation or layout.
Default projects do not expose `/docs`, `/redoc`, or `/openapi.json`.

## Stable Message Keys

Routes and services must not contain rendered Chinese or English response text.
They select a closed `MessageKey`; the response or exception boundary translates
that key with the request locale. A domain exception stores its public
`message_key` separately from its private `reason_code`. Never translate or
return the reason code because several sensitive causes intentionally share one
public result.

```python
return api_response(
    request,
    code=BusinessCode.OK,
    message_key=MessageKey.AUTH_LOGIN_SUCCEEDED,
    data=result,
)
```

Determine locale once per request and keep it in request-local state. Never use
a process-global mutable current language: concurrent Chinese and English
requests would leak into one another. Translation is pure in-memory lookup and
must not add PostgreSQL or Redis work to a request.

The bundled asset keeps `app/assets/locales/zh-CN.json` and `app/assets/locales/en.json` as
package data. Startup fails if a catalog is unreadable, has blank values, or its
key set differs from `MessageKey`; silently returning a key name is forbidden.

## Validation Errors

Do not return Pydantic's raw `msg`. It is framework-version-dependent, normally
English, and custom contexts can contain details that should not be public.
Map stable `error["type"]` values to message keys. Use
`PydanticCustomError` with a stable type for project validators. An unknown type
falls back to a localized generic invalid-value message without echoing the raw
message, input, context, exception, password, or CAPTCHA answer.

The `field` hint remains stable and untranslated so clients can associate an
error with an input. Expose at most the request location and first schema field;
mask an extra field and omit deeper list or mapping keys so attacker-controlled
names are never reflected. Clients branch on HTTP status, numeric `code`, and
the bounded field hint, never on localized text.

## Adding Another Language

When the project owner explicitly needs another language:

1. Add its canonical code and only required safe aliases in `core/i18n/language.py`.
   Never turn a request value into a file path or dynamic import.
2. Add one UTF-8 JSON catalog under `app/assets/locales/` with exactly the same keys as
   `MessageKey`, and include it as package data.
3. Translate every value; do not copy English as a silent placeholder.
4. Add parser, fallback, response-header, catalog-parity, validation, error, and
   concurrent-request tests for the new locale.
5. Update the public language contract and verify any CDN or reverse-proxy cache
   respects `Vary: Accept-Language`.

Do not add pluralization, user locale persistence, browser language UI, or a
translation management service until the actual product needs them.

## Verification

Test missing/default Chinese, explicit Chinese, English and regional English,
common browser headers, quality ordering, zero-weight skipping, unsupported values, malformed values, control
characters, path-like input, excessive length, and excessive language ranges.
The resolver must always return one registered locale and never reflect input.

For both languages cover successful reads and writes, built-in permission
list/detail descriptions, custom-description fallback, `400`, `401`, `403`,
password-change-required, `404`, `405`, both `409` codes, `422`, `429`, `500`,
and `503`. Confirm only human text changes: HTTP status, numeric code, machine values inside `data`,
request ID, `WWW-Authenticate`, `Cache-Control`, `Retry-After`, and rate-limit
headers retain their existing semantics. Run concurrent mixed-language requests
to prove request isolation, and scan public response call sites for rendered
string literals.
