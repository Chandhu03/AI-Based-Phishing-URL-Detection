/** Milliseconds as a short duration: "under 1 min", "12 min", "5 h", "3 days"; "—" when unknown. */
export function duration(ms) {
  if (ms == null) return "—";
  const min = Math.round(ms / 60000);
  if (min < 1) return "under 1 min";
  if (min < 60) return `${min} min`;
  const h = Math.round(min / 60);
  return h < 48 ? `${h} h` : `${Math.round(h / 24)} days`;
}
