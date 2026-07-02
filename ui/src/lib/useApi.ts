// Small data-fetching hooks over the api client. Deliberately dependency-free
// (no React Query) to keep the bundle small and the CSP tight.

import { useCallback, useEffect, useState } from "react";
import { api, ApiError, StepUpRequired } from "./api";
import { beginStepUp } from "./auth";
import type { Page } from "./types";

export interface AsyncState<T> {
  data: T | null;
  error: string | null;
  loading: boolean;
  reload: () => void;
}

export function useResource<T>(path: string): AsyncState<T> {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [tick, setTick] = useState(0);

  useEffect(() => {
    let live = true;
    setLoading(true);
    api
      .get<T>(path)
      .then((d) => {
        if (live) {
          setData(d);
          setError(null);
        }
      })
      .catch((e: unknown) => {
        if (live) setError(e instanceof Error ? e.message : String(e));
      })
      .finally(() => {
        if (live) setLoading(false);
      });
    return () => {
      live = false;
    };
  }, [path, tick]);

  const reload = useCallback(() => setTick((t) => t + 1), []);
  return { data, error, loading, reload };
}

// Keyset-paginated list with a "load more" cursor. `query` is a pre-encoded
// query string (without a leading '?') built from the viewer's filter inputs.
export function usePaged<T>(basePath: string, query: string) {
  const [items, setItems] = useState<T[]>([]);
  const [cursor, setCursor] = useState<number | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchPage = useCallback(
    async (reset: boolean, cur: number | null) => {
      setLoading(true);
      try {
        const parts = [query, cur != null ? `cursor=${cur}` : ""].filter(Boolean);
        const path = parts.length ? `${basePath}?${parts.join("&")}` : basePath;
        const page = await api.get<Page<T>>(path);
        setItems((prev) => (reset ? page.items : [...prev, ...page.items]));
        setCursor(page.next_cursor);
        setError(null);
      } catch (e: unknown) {
        setError(e instanceof Error ? e.message : String(e));
      } finally {
        setLoading(false);
      }
    },
    [basePath, query],
  );

  useEffect(() => {
    setItems([]);
    setCursor(null);
    void fetchPage(true, null);
  }, [fetchPage]);

  const loadMore = useCallback(() => void fetchPage(false, cursor), [fetchPage, cursor]);
  return { items, cursor, loading, error, loadMore };
}

// Runs a mutation, turning a step-up requirement into the IdP redirect and
// returning a human-readable error otherwise.
export async function runMutation(fn: () => Promise<unknown>): Promise<string | null> {
  try {
    await fn();
    return null;
  } catch (e: unknown) {
    if (e instanceof StepUpRequired) {
      beginStepUp();
      return "Confirming your identity...";
    }
    if (e instanceof ApiError) return e.detail;
    return e instanceof Error ? e.message : String(e);
  }
}
