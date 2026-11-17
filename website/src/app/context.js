import { createContext } from "preact";
import { useCallback, useContext, useEffect, useState } from "preact/hooks";

export const AppContext = createContext(null);
export const useApp = () => useContext(AppContext);

/**
 * Load async data and reload whenever the workspace revision changes.
 * Returns { data, error, loading }.
 */
export function useData(load, deps = []) {
  const { rev } = useApp();
  const [state, setState] = useState({ data: undefined, error: null, loading: true });
  useEffect(() => {
    let live = true;
    setState((s) => ({ ...s, loading: true }));
    Promise.resolve()
      .then(load)
      .then((data) => live && setState({ data, error: null, loading: false }))
      .catch((error) => live && setState({ data: undefined, error, loading: false }));
    return () => {
      live = false;
    };
  }, [rev, ...deps]);
  // A failed load goes to the page's error boundary instead of leaving a
  // blank page. Loaders that expect "not found" catch it themselves.
  if (state.error) throw state.error;
  return state;
}

/** Wrap a workspace mutation: run it, bump the revision, report errors as toasts. */
export function useAction() {
  const { bump, toast } = useApp();
  return useCallback(async (fn, success) => {
    try {
      const result = await fn();
      bump();
      if (success) toast(success);
      return result;
    } catch (err) {
      toast(err?.message ? capitalise(err.message) : "That action failed.", "error");
      return undefined;
    }
  }, [bump, toast]);
}

const capitalise = (s) => s.charAt(0).toUpperCase() + s.slice(1) + (/[.!?]$/.test(s) ? "" : ".");
