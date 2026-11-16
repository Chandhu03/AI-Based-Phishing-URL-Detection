// Storage adapters with one small async interface:
//   get(store, id) · put(store, record) · delete(store, id) · list(store) · clear()
//   commit(ops): several puts and deletes across stores, all or nothing.
// IndexedDB keeps the workspace in this browser profile only. Nothing here
// talks to a server.

export const STORES = Object.freeze(["analyses", "investigations", "indicators", "activity"]);
const DB_NAME = "securemind-workspace";
const DB_VERSION = 1;

const clone = (value) => (value === undefined ? undefined : structuredClone(value));

/** In-memory adapter, used by tests and as a fallback when IndexedDB is blocked. */
export function createMemoryStore() {
  const data = new Map(STORES.map((s) => [s, new Map()]));
  const table = (s) => {
    if (!data.has(s)) throw new Error(`unknown store ${s}`);
    return data.get(s);
  };
  return {
    kind: "memory",
    async get(s, id) { return clone(table(s).get(id)); },
    async put(s, record) { table(s).set(record.id, clone(record)); return record; },
    async delete(s, id) { table(s).delete(id); },
    async list(s) { return [...table(s).values()].map(clone); },
    async clear() { for (const t of data.values()) t.clear(); },
    async commit(ops) {
      // Apply to copies, then swap: a failure part-way leaves the data untouched.
      const next = new Map([...data].map(([s, t]) => [s, new Map(t)]));
      for (const op of ops) {
        const t = next.get(op.store);
        if (!t) throw new Error(`unknown store ${op.store}`);
        if (op.type === "put") t.set(op.record.id, clone(op.record));
        else if (op.type === "delete") t.delete(op.id);
        else throw new Error(`unknown operation ${op.type}`);
      }
      for (const [s, t] of next) data.set(s, t);
    },
  };
}

function promisify(request) {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

/** IndexedDB adapter. Rejects if IndexedDB is unavailable (e.g. some private modes). */
export async function createIdbStore(idb = globalThis.indexedDB) {
  if (!idb) throw new Error("IndexedDB is not available");
  const open = idb.open(DB_NAME, DB_VERSION);
  open.onupgradeneeded = () => {
    const db = open.result;
    for (const s of STORES) if (!db.objectStoreNames.contains(s)) db.createObjectStore(s, { keyPath: "id" });
  };
  const db = await promisify(open);
  const run = (s, mode, fn) => {
    const tx = db.transaction(s, mode);
    const result = promisify(fn(tx.objectStore(s)));
    return new Promise((resolve, reject) => {
      tx.oncomplete = () => resolve(result);
      tx.onerror = () => reject(tx.error);
      tx.onabort = () => reject(tx.error || new Error("transaction aborted"));
    });
  };
  return {
    kind: "indexeddb",
    get: (s, id) => run(s, "readonly", (st) => st.get(id)),
    put: async (s, record) => { await run(s, "readwrite", (st) => st.put(record)); return record; },
    delete: (s, id) => run(s, "readwrite", (st) => st.delete(id)),
    list: (s) => run(s, "readonly", (st) => st.getAll()),
    async clear() { for (const s of STORES) await run(s, "readwrite", (st) => st.clear()); },
    /** One readwrite transaction over every store touched: IndexedDB aborts all of it on any failure. */
    commit(ops) {
      if (!ops.length) return Promise.resolve();
      const names = [...new Set(ops.map((o) => o.store))];
      return new Promise((resolve, reject) => {
        let tx;
        try {
          tx = db.transaction(names, "readwrite");
          for (const op of ops) {
            const st = tx.objectStore(op.store);
            if (op.type === "put") st.put(op.record);
            else if (op.type === "delete") st.delete(op.id);
            else throw new Error(`unknown operation ${op.type}`);
          }
        } catch (err) {
          tx?.abort();
          reject(err);
          return;
        }
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error);
        tx.onabort = () => reject(tx.error || new Error("transaction aborted"));
      });
    },
  };
}
