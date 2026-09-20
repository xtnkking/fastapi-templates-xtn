# API Internationalization

Use this reference when adding or changing client-visible API text. The baseline
supports Simplified Chinese (`zh-CN`) and English (`en`) without a database
locale column, Cookie, query parameter, or third-party translation framework.
Additional languages are an explicit project extension.

## Runtime Contract

The client may send the standard `Accept-Language` request header. Missing,
unsupported, malformed, or oversized values fall back to `zh-CN`; they never
produce `406` and are never reflected in a response. Support exact `zh-CN` and
`en`, the common `zh` aliases, English regional tags such as `en-US`, quality
weights, and `*`. A more specific language range, including `q=0`, overrides a
parent range or wildcard for that language. If every supported language is
explicitly rejected, keep the documented no-`406` fallback to `zh-CN`. Bound
both header length and the number of parsed ranges.

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
- liveness and readiness messages.

HTTP status, numeric business code, response shape, field names, machine values
inside `data`, request ID, permission keys, role keys, stable log events, audit
actions, audit outcomes, and internal `reason_code` values remain
language-independent. Database-authored product content and OpenAPI developer
metadata are separate product concerns; do not claim they are translated by the
runtime message module.

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

The bundled asset keeps `app/locales/zh-CN.json` and `app/locales/en.json` as
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

1. Add its canonical code and only required safe aliases to the static locale
   registry. Never turn a request value into a file path or dynamic import.
2. Add one UTF-8 JSON catalog under `app/locales/` with exactly the same keys as
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
quality ordering, `q=0`, unsupported values, malformed values, control
characters, path-like input, excessive length, and excessive language ranges.
The resolver must always return one registered locale and never reflect input.

For both languages cover successful reads and writes, `400`, `401`, `403`,
password-change-required, `404`, `405`, both `409` codes, `422`, `429`, `500`,
and `503`. Confirm only human text changes: HTTP status, numeric code, `data`,
request ID, `WWW-Authenticate`, `Cache-Control`, `Retry-After`, and rate-limit
headers retain their existing semantics. Run concurrent mixed-language requests
to prove request isolation, and scan public response call sites for rendered
string literals.
