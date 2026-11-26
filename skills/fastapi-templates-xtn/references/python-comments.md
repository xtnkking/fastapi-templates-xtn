# Python Comments And Function Contracts

Read before writing or changing Python code. The default is Chinese explanatory
text with reStructuredText field names, as shown below. An existing project's
explicit documentation-language rule takes precedence. Python identifiers,
types, business codes and protocol values remain unchanged.

## Every Delivered File Has A Responsibility And Version Record

Every generated Python file, including `__init__.py`, tests, models, endpoints,
Services and Repositories, starts with the following layout. Use the real file's
business and boundaries, not a copied description from another project:

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    用户角色数据访问文件
#    查询用户的有效角色绑定并执行关系软删除
#    使用调用方提供的 PostgreSQL 会话，不自行提交事务或判断管理员权限
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# YYYY/MM/DD    项目作者  V1.000        新建
# --------------------------------------------------------------------------------------------------
```

Replace `YYYY/MM/DD` with the actual generation date. A newly generated project
file has exactly one entry: that date, the author provided by the user/project,
`V1.000` and `新建`. Do not copy the Skill template's maintenance dates, versions
or modifications into it. Preserve the file's existing history on later edits;
append one entry per completed logical change with
the next file revision (`V1.001`, `V1.002`, etc.). Do not add an entry for every
formatting invocation, reset an existing project's history, copy another file's author/date, or invent
past changes. A file version is independent of the Skill/package release version.
For an existing file with no history, record today's actual documentation update,
not “新建”. Use this repository owner's `XTN` for maintained Skill assets. In a
generated user's project use their supplied author or the explicit role label
`项目维护者` when no personal name is known; never assume that user is XTN.
Copied-code attribution remains in the existing README appendix, separate from
the new project's file maintenance records.

File responsibility belongs in the `# 说明:` header. Do not repeat it in a
module docstring; preserve function and class docstrings. Keep a module docstring
only when an existing project actually uses `__doc__` at runtime. Put the header
before `from __future__` imports. Shell/TOML/YAML/env files use their native `#` comments,
JS/TS use their native comment syntax, and Markdown uses an HTML comment before
the document. JSON, images and legal/license text cannot safely take
this header: keep their original format, with no extra comment keys, history
manifest or source-tracking file. Python keeps its History in the source file;
formats without comments use the project's normal version-control history.
Do not inject extra keys into a message catalog just to fake comments.
Existing project headers and author policies are preserved;
update only files in the authorized coding scope.

## Every Function Explains Its Contract

Add a multi-line triple-double-quoted docstring as the first statement of every
delivered function: synchronous/asynchronous functions, methods, private and
nested helpers, constructors, properties, dependencies, validators and callbacks.
A short body is not a reason to omit its contract. Do not create extra functions
solely to make room for comments. Classes also receive a
short responsibility description, especially models, repositories, services and
endpoints.

The docstring contains:

- A concrete sentence explaining the operation and its business purpose.
- Additional sentences only for meaningful behavior: soft-deletion scope,
  visibility, locking order, transaction ownership, external I/O, idempotency,
  side effects, or important failure behavior actually implemented here.
- For every endpoint, write one independent `访问条件：...` line followed by one
  independent `所需权限：...` line. Never combine access state and permission on
  the same line. The permission line names the exact permission key and its
  plain-language meaning, including `account:read` and `account:change_password`
  for the corresponding own-account operations. Use `所需权限：无管理权限要求。`
  only when no named permission is checked, such as CAPTCHA issuance or logout.
  Derive both lines from the actual dependency and
  Service checks, not the endpoint name. Put object visibility or hierarchy on a
  separate `目标限制：...` line, and CAPTCHA purpose or exceptional credentials
  on `其他要求：...` when applicable. A permission alias or
  `:param context: 已校验权限` alone is not sufficient documentation.
- One `:param name: explanation` for every declared parameter except implicit
  `self`/`cls`. Include keyword-only parameters, positional-only parameters and
  variadic parameters when present, in their signature order. Explain units,
  optional values and defaults
  where their meaning matters; do not merely repeat the type or variable name.
  For a boolean that selects behavior, explain the plain-language question it
  answers and what each value actually changes. Use a small before/after example
  when the state change is otherwise unclear. Explain meaningful call timing
  and why each behavior exists; labels alone do not explain their effects.
- A nonempty `:return:` explaining the result, including `None`, empty results,
  booleans and whether the caller receives ORM state or an immutable snapshot.
  A generator/context manager uses `:yield:` for its yielded resource and states
  who closes it. An always-raising function states that no normal return occurs.
- `:raises ExceptionType:` for deliberate failures a caller needs to handle.
  Do not list every possible runtime or driver exception mechanically.

For example, a repository with a real query has this shape:

```python
class RoleRepository:
    """
        负责 PostgreSQL 角色查询，复用调用方的事务。
    """

    async def get_live_role(self, session: AsyncSession,
                            role_id: uuid.UUID
                            ) -> Role | None:
        """
            根据角色 ID 查询未软删除的角色。
            此查询不判断操作者权限；调用方必须先执行权限和目标可见性校验。
            复用调用方的会话，不提交或回滚事务。

        :param session: 调用方管理事务的 PostgreSQL 异步会话。
        :param role_id: 待查询角色的非顺序业务 ID。
        :return: 未软删除的角色；不存在或已软删除时返回 None。
        """
        # 按业务 ID 精确查询并排除软删除记录，避免把已删除角色重新用于授权。
        role_query = select(Role).where(Role.id == role_id, Role.deleted_at.is_(None))
        # 仅读取结果；提交、回滚和上层权限判断仍由调用方负责。
        return await session.scalar(role_query)


role_repository = RoleRepository()
```

## Aligned Method Signatures And Indentation

Use the same direct business word across the active operation's model, method
and message member: `RegisterRequest`, `AuthService.register` and
`MessageKey.AUTH_REGISTER_SUCCEEDED`. A naming cleanup changes Python identifiers
and all their consumers, without keeping forwarding aliases. Preserve existing
message-key values, Redis purposes, audit actions and reason-code strings; those
are contracts, not alternative Python spellings of the operation.

Name local variables for their actual contents, not the library's vocabulary.
For authentication, `token_header` holds the parsed request header, `token` the
Token string, `token_fields` the JWT field dictionary, and `token_info` its typed
user/time information. A reader should see the difference without translating
`credentials` or `payload`. Keep FastAPI's real `HTTPAuthorizationCredentials`
type and `.credentials` attribute; explain that attribute where it is read
instead of adding a wrapper or alias solely to rename a library API.

In repositories, distinguish the unexecuted query from its result: use
`user_query` / `user`, `user_count_query` / `total_users`, and
`role_permissions_query` / `role_permission_rows` rather than bare
`statement`, `result` or `rows`. Use `user_permissions_by_id` for complete
`UserPermissions` results indexed by user ID, and `user_details_by_id`
for page-display results, with `user_details` for one `UserDetails` value.
Each `UserDetails.user_info` contains only what
the caller may view and must not authorize operations. Authentication reads
the current user's complete information from `context.user_info`; a local
holding that information uses `user_info`. Preserve SQLAlchemy APIs, SQL labels
and public object fields when renaming locals.

The shared read-only type is `core/access/authorization.py::UserInfo`: account
state, roles, role level and permissions. ORM `User` is a database entity, HTTP
`*Response` schemas define returned fields, and AuthService's private `_UserInfo`
copies password-check state, including the password hash; do not substitute that
private object for the shared permission information.

Use four spaces per Python block. Inside the docstring, indent explanatory
prose four more spaces than its triple quotes; align `:param:`, `:return:`,
`:yield:` and `:raises:` fields with the triple quotes. Field continuations
receive one additional indentation level. The example above is the default
layout, not the formatter's usual flush-left docstring layout.

For class methods with two or more inputs besides `self`/`cls`, use the aligned
layout demonstrated below even when the complete signature could fit on one
line. Keep `self`/`cls` and the first input on the definition line; put every
remaining input on its own line, aligned with `self`/`cls`. Put the closing `)`
on a separate line in that same column, followed by the return annotation.
Constructors follow this rule too. Static methods align subsequent inputs and
the closing `)` with their first input. A method with only `self`/`cls` or one
additional input may stay on one line when short.
For a static method with only keyword inputs, keep `*` on the definition line
and list all business inputs below, aligned with `*`, so each input has its own
line and the existing formatter preserves the layout.

Preserve keyword-only `*`, positional-only `/`, annotations, defaults and argument
order. For example, `self, session: AsyncSession, *,` can remain on the first
line; if all inputs are keyword-only, use `self, *, context: Context,` there.
Continuation inputs still align with `self`, not with `context`. Aim for 120
columns without sacrificing readability: if the name or a long annotation makes
that alignment excessive, start all inputs on the next line, one block indented,
with one input per line. Only in this hanging-indent fallback, bring the closing
`)` back to the definition's indentation. Do not shorten meaningful names or
alter the callable contract just to satisfy layout.

Here is a real permission-catalog Service shape; imports, the file header and
other methods are omitted from this excerpt:

```python
class PermissionService:
    """
        组织权限目录分页；接口依赖负责检查目录查询权限。
    """

    async def list_permissions(self, session: AsyncSession, *,
                               page: int,
                               page_size: int,
                               locale: str = DEFAULT_LOCALE
                               ) -> PageResponse[PermissionResponse]:
        """
            计算分页位置，读取权限及匹配总数，并仅返回公开的目录字段。
            入口必须已检查 permissions:read（查看权限目录）。

        :param session: 调用方管理生命周期的 PostgreSQL 异步会话。
        :param page: 从 1 开始且已通过范围校验的页码。
        :param page_size: 已通过接口上限校验的每页条数。
        :param locale: 接口通过 locale_for_request(request) 协商的展示语言，直接调用时默认中文。
        :return: 当前页权限列表、页码、每页条数和未删除权限总数。
        """
        # 页码换算为跳过的记录数；列表和计数采用同一未删除范围。
        offset = (page - 1) * page_size
        total = await permission_repository.count_live_permissions(session)
        permissions = await permission_repository.list_live_permissions(
            session,
            offset=offset,
            limit=page_size,
        )
        # 只公开接口承诺的字段，新增数据库内部字段不会自动进入响应。
        items = [
            PermissionResponse(
                id=item.id,
                key=item.key,
                description=get_permission_description(
                    item.key,
                    stored_description=item.description,
                    locale=locale,
                ),
            )
            for item in permissions
        ]
        return PageResponse(
            items=items,
            page=page,
            page_size=page_size,
            total=total,
        )
```

For calls passing several business inputs, especially Service-to-Repository or
Service-to-Service calls, put arguments on separate lines inside the call's
parentheses as above. Keep explicit keywords and the visible execution order;
do not squash a clear multi-line call merely because it could fit in 120 columns.
A genuinely short/simple call or non-route decorator can remain on one line. Ordinary
route functions do not need the class-method layout forced onto every signature;
when a route has several dependencies, filters or long annotated inputs, place
each input on its own continuation line. Use ordinary hanging indentation when
alignment would leave too little room; do not pack unrelated inputs into groups
just to save lines. Never compress a multi-stage
query or business flow into a dense expression. Put the business prefix on its
`APIRouter`; default projects do not add documentation-only tags. Repeated long
permission dependencies can use a typed alias beside that business's
routes, with the exact permission visible at its definition. Keep distinct
write permissions distinct; an alias must not replace target-level checks.
Do not add a helper function or a class merely to make the route visually shorter.

Put a short shared explanation beside each business `APIRouter` instead of
repeating a paragraph above every operation. Explain that `prefix` supplies the
module path. An `@router.get(...)` or `@router.post(...)` selects the HTTP method
and its first string is the path appended to that prefix. Keep only arguments
with runtime meaning: `status_code` changes the successful HTTP status,
`response_model` validates and filters the successful body, and `dependencies`
executes pre-handler dependencies whose return value is not injected. Default
projects do not add `tags`, `responses`, `route_class`, explicit `operation_id`,
or other documentation-only arguments. Put a short decorator on one line and
wrap only when the configured line length requires it.

Authenticated routes do not use an extra rate-limit decorator. A current-account
authentication dependency automatically selects `rate_limit_user_read` for GET or
`rate_limit_user_write` for POST. A permission dependency uses those same ordinary
user settings by default. Only a route that explicitly calls
`require_permission(key, management=True)` selects `rate_limit_admin_read` for
GET or `rate_limit_admin_write` for POST. Explain that this selects the business
quota, not the caller's role: needing a permission does not mean being an
administrator. The authenticated CAPTCHA dependency keeps its separate scene
limits. The route handler's stable, unique function name becomes the internal
business counter name. This keeps mandatory protection in one dependency chain
instead of asking a beginner to remember a second decorator.

For example, once the shared `RoleReadContext` has been defined, a detail
endpoint imports the ordinary shared Service directly and shows its real
PostgreSQL dependency in the signature. Other imports and the mandatory file
header are omitted from this short excerpt:

```python
from app.services.role_service import role_service


# response_model 会实际校验和过滤成功响应；它不是只给文档看的参数。
@router.get("/detail", response_model=ApiResponse[RoleResponse])
async def get_role_detail(request: Request,
                          role_id: Annotated[uuid.UUID, Query(description="要查询的角色业务 ID")],
                          context: RoleReadContext,
                          db: Annotated[AsyncSession, Depends(get_postgres_session)]
                          ) -> ApiResponse[RoleResponse]:
    """
        读取操作者可见的角色详情，不存在与不可见使用同一种错误。
        访问条件：已登录且账号可用。
        所需权限：roles:read（查看角色及其权限）。
        目标限制：普通管理员只能查看比自己等级低且未受保护的角色；超级管理员可查看全部未删除角色。

    :param request: 当前请求，用于生成统一响应及关联请求 ID。
    :param role_id: 查询参数中的目标角色 ID。
    :param context: 已通过角色查询权限检查的操作者上下文。
    :param db: FastAPI 为本次查询注入的 PostgreSQL 会话；请求结束自动关闭，不在接口提交事务。
    :return: 当前操作者可见的角色详情。
    """
    # 由业务层落实目标可见性，URL 中的 ID 不能代替权限判断。
    data = await role_service.get_role_detail(
        db,
        current_user=context.user_info,
        role_id=role_id,
    )
    return api_response(
        request,
        code=BusinessCode.OK,
        message_key=MessageKey.COMMON_QUERY_SUCCESS,
        data=data,
    )
```

The corresponding public URL is `/api/v1/roles/detail?role_id=...` when the
business router declares `prefix="/roles"` and the v1 assembly supplies
`prefix="/api/v1"` once. Static paths and validated input
placement follow the API contract; comments must not claim this placement
prevents injection or unauthorized access by itself.

The asset uses `autopep8` for conservative layout and Ruff for lint/import
checks. Its `pyproject.toml` owns the settings. Run
`python -B -m autopep8 --in-place --recursive app tests` when formatting;
use `--diff --exit-code` instead of `--in-place` to check. Do not run a second
formatter that undoes the aligned method signatures or docstring indentation. An
existing project's explicit style/toolchain stays in place unless the owner
authorizes changing it.
The existing asset settings preserve both layouts; this convention requires no
additional lint ignores or replacement formatter.
The asset deliberately ignores Ruff `UP009` so automatic lint fixes preserve
the required UTF-8 header; do not disable unrelated checks.

For a command returning no value, document the actual mutation and say
`:return: 无返回值；成功时已完成……。` Do not claim a transaction was committed
when the function only flushed, or claim authorization when only a lookup ran.
For a session dependency, use `:yield: 当前请求使用的数据库会话；退出时关闭。`
and document commit ownership separately.

The supplied asset's callable contracts are examples, not a requirement that a
new domain copy its names or adopt its unrelated security components. Explain
business-specific behavior in that domain's own words.

## Module, Model And API Documentation

Start every file with the responsibility/history header above. Write the module's
responsibility in that header only, without a second prose string. Repository/model modules identify the database;
Service modules identify the orchestration they own; endpoint modules identify
the API business and version. Checkmark markers such as `[√]` are optional;
they do not replace a real explanation or accurate maintenance record.

Model classes describe the entity, soft-deletion or append-only behavior and
important relationships. Document business fields where they are declared,
including dataclasses, response schemas, settings and class-level constants.
State whose identifier a field contains, the unit of time/size/amount, the
meaning of `None`/empty/false, who supplies it, and whether clients may change it
when relevant. Explain version counters by what changing them actually does.
SQLAlchemy `comment=` is database metadata; it does not replace readable source
comments beside long field declarations. Prefer source `#` explanations for a
comment-only change instead of changing ORM/Pydantic runtime metadata.
API function descriptions explain the public business contract: never include
credentials, internal denial details or internal table names. Public
access-management descriptions use user/role/permission wording and retain the
existing neutral API contract.

Source comments and API field documentation serve different readers. Public
Pydantic request/response fields need meaningful Chinese `Field(description=...)`
text, and GET inputs need corresponding `Query(description=...)` text. Explain
whose ID it is, units, allowed choices and optional/default meanings where useful.
Preserve aliases, requiredness, defaults, constraints, validators and input
placement when adding descriptions; a documentation fix must not silently change
the accepted request. Do not expose password hashes, internal denial reasons or
private security state. These descriptions are static; `Accept-Language` still
selects only the separate runtime response messages. Preserve an established
project's explicit documentation-language choice.

Distinguish offline JSON Schema metadata, runtime validation and disabled public
documentation routes. A schema description can explain an input without making
`/docs` or `/openapi.json` public. When a route returns the configured Token TTL
as `expires_in`, describe the issue-time lifetime, not a live remaining-time
countdown.

## Constants, Variables And The Function Body

Document module/class constants and non-obvious fixed values at their definition:
what the value controls, its unit, what its allowed range or sentinel means, and
where a user should change it. Distinguish configurable defaults from mandatory
invariants (for example maximum 10 roles), protocol values and internal lookup
maps. Explain the purpose of allowlists and each non-obvious entry; group clear
members under one useful comment rather than repeating their name as prose.
Do not add a configurable switch solely to justify a comment.

Every permission Enum member has its own short Chinese explanation of the
operation it grants. Explain system-role grant sets and immutable limits beside
their definitions. Distinguish “possesses this permission” from “may act on this
target”: a role name alone does not grant access, and a permission check does not
remove hierarchy or object visibility checks. Give each non-obvious class field
or constant an adjacent explanation; a generic class docstring does not cover it.

Write for someone learning backend development. Expand terms at first use in
the relevant module: for example JTI is the identifier of one login token,
an authority snapshot is the permissions read for this operation, a row lock
makes conflicting writes wait, and flush sends changes without committing them.
Explain why the order matters with a concrete effect, such as rechecking a
permission after waiting for a lock because another administrator may revoke it.
Do not replace accurate names/types with vague wording, repeat library manuals,
or claim that a lock makes unrelated reads or other systems atomic.

Apply the same beginner-facing coverage to every non-test function throughout
the Skill's executable assets and tools, including private helpers, constructors,
properties, nested callbacks and generators. The docstring states the concrete
purpose and real parameter/return meanings; body comments explain each actual
stage in plain language. Use numbered steps for multi-stage flows and one
specific explanation for a tiny operation. Keep already clear comments, and do
not invent steps, repeat each assignment or add functions just to hold comments.

Within Services and Repositories, readers should be able to follow the whole
business operation from the docstring and phase comments. Before meaningful
steps, explain what this stage accomplishes and why its ordering matters:

- Repository: filters and soft-deletion scope, visibility predicates, join or
  subquery purpose, deterministic ordering/pagination, batch reads, row locks,
  refresh behavior, and the meaning of no result. State that the caller owns
  commit/rollback where applicable; do not claim a query itself checks access.
- Service: prerequisite checks, authority reload after locking, validation of
  the intended change, mutation, version invalidation, audit in the same
  transaction, response snapshot and rollback/error handling. Explain why an
  external call is outside the lock when that is the actual guarantee.
- Local variables: explain opaque collections, units, temporary snapshots or
  sentinel values close to their first assignment. Clear trivial assignments
  can be covered by the surrounding phase comment.

For each non-obvious exception handler, explain why that error is caught and
whether it is retried, translated or re-raised unchanged. For constraint retries,
name the recoverable constraint, explain why a new ID can fix it, the attempt
limit and why other constraints must propagate. Explain savepoint rollback
separately from outer transaction rollback and commit; a generic “handle errors”
comment does not tell a learner which writes survive a failed attempt.

Keep response constructors, audit dictionaries and nontrivial field mappings
readable one field per line when several business facts are assembled. Group
related fields under a short comment only when that explains their purpose;
do not squeeze many key/value pairs onto one line or create a helper solely to
hide the mapping. A tiny obvious literal may stay inline.

Embedded Lua scripts are also delivered code. Explain `KEYS`, `ARGV`, success,
denial and damaged-state return values in Chinese beside each script. For a
nontrivial script, add a few Chinese phase comments inside the Lua source at
atomic checks, mutation order and cleanup that a beginner could otherwise
misread. Do not comment every Redis command, translate protocol/error literals,
or change executable statements merely to satisfy the documentation rule.

Explain callback timing accurately. A nested `def` only declares work; it does
not validate a password, acquire a lock or write a user yet. Name the actual
invocation stage and describe the rate-limit/check/transaction sequence where it
happens. Do not say a request already passed CAPTCHA, permissions or rate limits
merely because a callback is defined or passed to another function. Preserve a
callback that owns a real security/framework boundary; do not add generic
callback dispatch to a straightforward business flow.

Use short Chinese business explanations. A short function may need only one
body comment; longer flows need comments at the actual stages and unusual
branches. Do not mechanically comment every `return`, loop or assignment, or
use “查询数据/执行操作/返回结果” without explaining the business meaning. Comments
must not claim stronger locking, atomicity, authorization or failure guarantees
than the code provides. Keep code readable with meaningful names as well.
Use plain words and one purpose per comment: for example, “加锁后重查权限，防止刚被撤权”。
Do not repeat the same explanation in the summary, parameter description and
body. Explain the operation in the summary, inputs in parameters, and reasons
or important ordering beside the code; avoid stacking technical terms.

Prefer short business language to a long collection of technical nouns. Explain
what a missing result means and who owns the transaction; readers should not
need to inspect three other files to understand the return value. Add a short
comment before a non-obvious stage such as reloading authority after a lock.
Do not paste the same long paragraph into every function or describe a class
as only generating IDs after it has grown into a complete business service.
Checkmarks, empty `:return:` fields and copied maintenance histories from a
reference project are not substitutes for accurate contracts.

## Review Accuracy Along With Code

When changing a signature, return shape, transaction or error, update its
docstring in the same change. Check parameter names against the real signature,
including nested functions and decorated callbacks. An automated AST check can
find missing descriptions or stale fields, but human review must confirm meaning.
When a validator calls a shared normalizer, describe the checks that normalizer
actually performs and their execution order. Do not attribute those checks to
later `Query` metadata.
When comments name another module as the next place to read, check that the
named file exists in the generated project, not only in the maintenance source.
Do not use placeholder phrases such as “处理数据”, “参数”, “返回结果” or empty
`:return:` fields to satisfy that check.

Before delivery, read one complete endpoint → Service → Repository chain as a
beginner. Verify that the endpoint states the real login/permission/target
conditions, fields and constants explain their business meaning and units,
and the body explains consequential steps. Follow the actual checks: a read
visibility filter and a write-management permission-subset check may differ.
Check the generated files as well as the maintained asset; rules alone are not
evidence that readers receive the promised explanations.
Compare public field descriptions with the actual Pydantic and FastAPI metadata,
and trace any callback through its real caller before asserting execution order. Comments
that sound helpful but contradict the code must be corrected, not multiplied.

Examples supplied for naming or comment style are not permission to copy their
unrelated design decisions. In particular, querying before inserting does not
guarantee a unique ID under concurrency; a database unique constraint remains
the final guard. Preserve the project's existing ID generation, authorization,
transaction and error-handling rules unless their change is explicitly requested.
