// Small, dependency-free charts. Each chart also renders its numbers as text
// (a table or list), so nothing is conveyed by shape alone.

const LEVELS = [
  ["high-risk", "High risk"],
  ["suspicious", "Suspicious"],
  ["inconclusive", "Inconclusive"],
  ["no-strong-indicators", "No strong indicators"],
];

export function VerdictBars({ byVerdict }) {
  const total = Object.values(byVerdict).reduce((a, b) => a + b, 0);
  return (
    <div class="vbars">
      <div class="vbar-track" aria-hidden="true">
        {total > 0 && LEVELS.map(([k]) => byVerdict[k] > 0 && (
          <span key={k} class="vbar-seg" data-level={k} style={{ flexGrow: byVerdict[k] }} />
        ))}
      </div>
      <table class="vbar-table">
        <caption class="visually-hidden">Analyses by verdict</caption>
        <tbody>
          {LEVELS.map(([k, label]) => (
            <tr key={k}>
              <th scope="row"><span class="verdict-dot" data-level={k} aria-hidden="true" />{label}</th>
              <td>{byVerdict[k]}</td>
              <td class="muted">{total ? `${Math.round((byVerdict[k] / total) * 100)}%` : "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function DayColumns({ perDay }) {
  const max = Math.max(1, ...perDay.map((d) => d.count));
  return (
    <figure class="days">
      <div class="days-plot" aria-hidden="true">
        {perDay.map((d) => (
          <span key={d.day} class="days-col" title={`${d.day}: ${d.count}`}>
            <span class="days-bar" style={{ height: `${(d.count / max) * 100}%` }} />
          </span>
        ))}
      </div>
      <figcaption class="days-axis">
        <span>{perDay[0]?.day}</span>
        <span>{perDay.at(-1)?.day}</span>
      </figcaption>
      <table class="visually-hidden">
        <caption>Analyses per day</caption>
        <tbody>{perDay.map((d) => <tr key={d.day}><th scope="row">{d.day}</th><td>{d.count}</td></tr>)}</tbody>
      </table>
    </figure>
  );
}
