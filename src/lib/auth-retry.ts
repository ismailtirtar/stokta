type SupabaseErrorLike = {
  code?: string;
  message?: string;
  name?: string;
  status?: number;
};

type SupabaseResultLike = {
  error: unknown | null;
  status?: number;
};

export class OperationTimeoutError extends Error {
  readonly status = 408;

  constructor(message = "İşlem zaman aşımına uğradı") {
    super(message);
    this.name = "OperationTimeoutError";
  }
}

const transientStatuses = new Set([401, 408, 425, 500, 502, 503, 504, 520, 522, 524]);
const transientNames = new Set([
  "AuthRetryableFetchError",
  "AuthUnknownError",
  "FunctionsFetchError",
  "FunctionsRelayError",
  "OperationTimeoutError",
]);

export async function withOperationTimeout<T>(
  operation: PromiseLike<T>,
  timeoutMs = 12_000,
  message = "Bağlantı zaman aşımına uğradı",
): Promise<T> {
  let timeout: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      Promise.resolve(operation),
      new Promise<never>((_resolve, reject) => {
        timeout = setTimeout(() => reject(new OperationTimeoutError(message)), timeoutMs);
      }),
    ]);
  } finally {
    if (timeout !== undefined) clearTimeout(timeout);
  }
}

export function isTransientSupabaseError(error: unknown, responseStatus?: number) {
  if (!error) return false;

  const candidate = error as SupabaseErrorLike;
  const status = responseStatus ?? candidate.status;
  if (typeof status === "number" && transientStatuses.has(status)) return true;
  if (candidate.name && transientNames.has(candidate.name)) return true;

  const diagnostic = `${candidate.code ?? ""} ${candidate.message ?? ""}`.toLowerCase();
  return /\b(jwt|network|fetch|timeout|timed out|connection|gateway)\b/.test(diagnostic);
}

export async function retryTransientSupabaseOperation<T extends SupabaseResultLike>(
  operation: () => PromiseLike<T>,
  delayMs = 450,
  timeoutMs = 12_000,
) {
  const runAttempt = async () => {
    try {
      return await withOperationTimeout(operation(), timeoutMs);
    } catch (error) {
      return { data: null, error, status: (error as { status?: number })?.status ?? 0 } as unknown as T;
    }
  };

  const firstResult = await runAttempt();
  if (!isTransientSupabaseError(firstResult.error, firstResult.status)) return firstResult;

  await new Promise((resolve) => setTimeout(resolve, delayMs));
  return runAttempt();
}
