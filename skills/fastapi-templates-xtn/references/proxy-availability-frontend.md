# Proxy Availability Frontend

Read [the shared contract](proxy-availability-detection.md) first. Inspect the
existing frontend framework, API client, table, selection/query state,
notification, request-cancellation, and testing patterns before adapting these
examples. The browser sends only a proxy ID; it never receives or constructs a
proxy URL or credentials.

## Data And Display

Use one discriminated snapshot for the direct response and cached list field.
Replace it completely after a check so a failure cannot retain an older success's
IP or latency.

```typescript
export type ProxyAvailabilityCheck =
  | {
      success: true;
      latency_ms: number;
      ip_address: string;
      country: string | null;
      country_code: string | null;
      region: string | null;
      city: string | null;
      message: string;
      updated_at: string;
    }
  | {
      success: false;
      message: string;
      updated_at: string;
    };

export interface ProxyListItem {
  id: string;
  // Existing public fields remain unchanged.
  availability_check: ProxyAvailabilityCheck | null;
}

export interface ApiResponse<T> {
  code: number;
  message: string;
  data: T | null;
  request_id: string;
}

export interface PageData<T> {
  items: T[];
  page: number;
  page_size: number;
  total: number;
}
```

Under the XTN response standard, the API client validates the numeric `code` and
required `request_id`, then returns `data` to feature code. Preserve the request
ID with a thrown application error so support can correlate it, but never branch
on localized `message` text. A completed check is `200000` even when its
`data.success` is false.

A successful list response with `availability_check=null` renders as `未检测`.
When the list request fails with cache-specific HTTP `503` / business code
`503002`, render `检测结果暂不可用` for the list instead of treating rows as cache
misses. A success shows exit IP, country, region, city, latency, and server check
time; use `--` for optional null location values. A cached failure shows its safe
backend message. Never reinterpret `检测服务请求频率受限` as a proxy connection or
authentication failure.

Mount, refresh, pagination, sort, search, filter, and ordinary query refetch call
only the list API. Do not trigger active detection from a mount effect, row
renderer, cache-miss callback, or automatic retry.

## Shared Scheduler And Single Check

Row and batch operations share one scheduler guard, or five batch workers plus a
row click can exceed the required limit. Track activity by proxy ID, not table
index. Claim locks synchronously rather than relying on delayed disabled-button
rendering.

```typescript
const inFlightById = new Map<string, Promise<ProxyAvailabilityCheck>>();
const runningIds = new Set<string>();
let batchOwnsScheduler = false;

function checkOnce(
  proxyId: string,
  origin: "row" | "batch" = "row",
): Promise<ProxyAvailabilityCheck> {
  if (origin === "row" && batchOwnsScheduler) {
    return Promise.reject(new Error("batch_check_in_progress"));
  }

  const existing = inFlightById.get(proxyId);
  if (existing) return existing;

  runningIds.add(proxyId);
  const task = Promise.resolve().then(async () => {
    try {
      publishRunningIds(new Set(runningIds));
      const result = await api.checkProxy(proxyId);
      replaceCompleteRowResult(proxyId, result);
      clearTransportError(proxyId);
      return result;
    } catch (error) {
      setTransportError(proxyId, toSafeUiMessage(error));
      if (
        origin === "row" &&
        hasBusinessCode(error, 503002)
      ) {
        try {
          await reloadVisibleProxyList();
        } catch (reloadError) {
          showSafeListReloadError(toSafeUiMessage(reloadError));
        }
      }
      throw error;
    } finally {
      runningIds.delete(proxyId);
      inFlightById.delete(proxyId);
      publishRunningIds(new Set(runningIds));
    }
  })();

  inFlightById.set(proxyId, task);
  return task;
}
```

The in-flight map suppresses only simultaneous double clicks. It deletes its
entry in `finally`, so a later explicit click always sends a fresh request. A
browser-to-backend transport or application error is temporary UI state and must
not replace the last Redis-backed snapshot or expose raw response content.
Business code `503002` is special: reload cache-only list data
without retrying detection, because Redis may already contain the observation.
Batch processing relies on its one final reload instead of reloading per item.

## Batch Target Snapshot

At batch start, synchronously require both `!batchOwnsScheduler` and
`runningIds.size === 0`, then set `batchOwnsScheduler=true` before the first
`await`. Snapshot selection and normalized filters. A non-empty selection uses
exactly its deduplicated IDs and skips page enumeration. Otherwise remove
page-specific parameters, freeze search/filter/sort values, and fetch every page
with a requested maximum of 200 rows:

```typescript
const PAGE_SIZE = 200;
const WORKER_COUNT = 5;

async function collectTargetIds(
  selectedIds: readonly string[],
  normalizedFilters: Readonly<Record<string, unknown>>,
): Promise<string[]> {
  const selected = [...new Set(selectedIds)];
  if (selected.length > 0) return selected;

  const filters = structuredClone(normalizedFilters);
  const ids = new Set<string>();
  let page = 1;
  let expectedPages: number | undefined;

  for (;;) {
    const result = await api.listProxies({
      ...filters,
      page,
      page_size: PAGE_SIZE,
    });
    if (result.page !== page || result.page_size !== PAGE_SIZE) {
      throw new Error("invalid page response");
    }
    for (const proxy of result.items) ids.add(proxy.id);

    expectedPages ??= Math.ceil(result.total / PAGE_SIZE);
    if (page >= expectedPages) break;
    if (result.items.length === 0) {
      throw new Error("page ended before the initial total");
    }
    page += 1;
  }

  return [...ids];
}
```

The XTN baseline returns only `items`, `page`, `page_size`, and `total`. Calculate
the page count from the first response and do not add `total_pages`, `has_next`,
or cursor metadata. Require deterministic ordering and deduplicate IDs. Proxies
created or deleted during offset-page collection belong to the next run; products
that require a strict snapshot need a separately versioned pagination contract.

## Five-Worker Pool

Start up to five consumers over one queue index. Do not use an unbounded
`Promise.all(ids.map(...))`. Each item catches its own failure and increments
exactly one outcome counter in `finally`.

```typescript
interface BatchState {
  phase: "idle" | "collecting" | "running" | "completed" | "failed";
  total: number;
  completed: number;
  succeeded: number;
  failed: number;
}

async function runFiveWorkers(
  ids: readonly string[],
  onSettled: (succeeded: boolean) => void,
): Promise<void> {
  let nextIndex = 0;
  let progressUpdateFailed = false;
  let progressError: unknown;

  async function worker(): Promise<void> {
    for (;;) {
      const index = nextIndex++;
      if (index >= ids.length) return;

      let succeeded = false;
      try {
        const result = await checkOnce(ids[index], "batch");
        succeeded = result.success;
      } catch {
        succeeded = false;
      } finally {
        try {
          onSettled(succeeded);
        } catch (error) {
          if (!progressUpdateFailed) progressError = error;
          progressUpdateFailed = true;
        }
      }
    }
  }

  const workerOutcomes = await Promise.allSettled(
    Array.from(
      { length: Math.min(WORKER_COUNT, ids.length) },
      () => worker(),
    ),
  );
  const rejectedWorker = workerOutcomes.find(
    (outcome): outcome is PromiseRejectedResult => outcome.status === "rejected",
  );
  if (rejectedWorker) throw rejectedWorker.reason;
  if (progressUpdateFailed) throw progressError;
}
```

The batch orchestrator owns the synchronous lock through target collection,
worker settlement, final summary, and one visible-list reload:

```typescript
async function startBatch(
  selectedIds: readonly string[],
  normalizedFilters: Readonly<Record<string, unknown>>,
): Promise<void> {
  if (batchOwnsScheduler || runningIds.size > 0) return;
  batchOwnsScheduler = true;

  try {
    publishBatchState({
      phase: "collecting",
      total: 0,
      completed: 0,
      succeeded: 0,
      failed: 0,
    });
    const ids = await collectTargetIds(selectedIds, normalizedFilters);
    publishBatchProgress({ phase: "running", total: ids.length });

    await runFiveWorkers(ids, (succeeded) => {
      updateBatchProgress((current) => ({
        ...current,
        completed: current.completed + 1,
        succeeded: current.succeeded + (succeeded ? 1 : 0),
        failed: current.failed + (succeeded ? 0 : 1),
      }));
    });

    publishBatchPhase("completed");
    showBatchSummary();
    try {
      await reloadVisibleProxyList();
    } catch (error) {
      showSafeListReloadError(toSafeUiMessage(error));
    }
  } catch (error) {
    publishBatchFailure(toSafeUiMessage(error));
  } finally {
    batchOwnsScheduler = false;
  }
}
```

Adapt state mutation to the framework's functional/transactional update API.
Set `total` only after collection. A domain `success=false` and a frontend
transport failure both count as failed, but neither stops another worker. Every
item clears its running ID in `finally`. A structural collection/worker error
sets a retryable `failed` phase; a final list-reload error preserves the completed
counts and reports refresh failure separately. `Promise.allSettled` is a worker
barrier: even a progress-update exception cannot release the scheduler while
other checks still run. Disable duplicate batch starts for the entire lock
lifetime and disable each row action while its ID is running.

Patch rows by ID and publish a new `Set`; mutating an observed `Set` in place may
not render. Protect list responses and row patches with a request generation or
server `updated_at`, so a stale in-flight list response cannot overwrite a newer
check. Reload the visible list once after all workers settle, not after each item.

Cancellation is optional. If exposed, stop taking new IDs, allow the at-most-five
active requests to settle, classify unstarted items as cancelled rather than
failed, then reload. Aborting a browser request does not prove the backend stopped
its outbound request or Redis update. Keep the scheduler locked until active work
settles, or isolate runs with a monotonically increasing run generation.
