export function DistributionPanel({
  title,
  data,
  emptyLabel,
}: {
  title: string;
  data: { name: string; count: number }[];
  emptyLabel: string;
}) {
  const maximum = Math.max(...data.map((item) => item.count), 1);
  return (
    <article className="panel distribution-panel">
      <div className="panel-heading">
        <h2>{title}</h2>
        <span>Recent snapshot</span>
      </div>
      {data.length === 0 ? (
        <p className="panel-empty">{emptyLabel}</p>
      ) : (
        <ol className="distribution-list">
          {data.map((item) => (
            <li key={item.name}>
              <div>
                <span>{item.name}</span>
                <strong>{item.count}</strong>
              </div>
              <progress max={maximum} value={item.count} aria-label={`${item.name}: ${item.count}`} />
            </li>
          ))}
        </ol>
      )}
    </article>
  );
}
