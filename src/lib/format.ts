const relativeFormatter = new Intl.RelativeTimeFormat("en", { numeric: "auto" });

export function formatDateTime(value: string): string {
  return new Intl.DateTimeFormat("en-GB", {
    dateStyle: "medium",
    timeStyle: "short",
    timeZone: "UTC",
  }).format(new Date(value));
}

export function formatRelativeTime(value: string, now = Date.now()): string {
  const difference = new Date(value).getTime() - now;
  const absolute = Math.abs(difference);
  if (absolute < 60_000) return "just now";
  if (absolute < 3_600_000) return relativeFormatter.format(Math.round(difference / 60_000), "minute");
  if (absolute < 86_400_000) return relativeFormatter.format(Math.round(difference / 3_600_000), "hour");
  return relativeFormatter.format(Math.round(difference / 86_400_000), "day");
}

export function formatNumber(value: number): string {
  return new Intl.NumberFormat("en-GB", { notation: "compact" }).format(value);
}

export function sentenceCase(value: string): string {
  return value.length > 0 ? value[0].toUpperCase() + value.slice(1) : value;
}
