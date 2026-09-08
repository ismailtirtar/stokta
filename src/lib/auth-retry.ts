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

const transientStatuses = new Set([401, 408, 425, 500, 502, 503, 504, 520, 522, 524]);
const transientNames = new Set([
  "AuthRetryableFetchError",
  "AuthUnknownError",
  "FunctionsFetchError",
  "FunctionsRelayError",
]);

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
  operation: () => Promise<T>,
  delayMs = 450,
) {
  const firstResult = await operation();
  if (!isTransientSupabaseError(firstResult.error, firstResult.status)) return firstResult;

  await new Promise((resolve) => setTimeout(resolve, delayMs));
  return operation();
}
