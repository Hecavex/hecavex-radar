const relativeFormatter = new Intl.RelativeTimeFormat("lt", { numeric: "auto" });

export function formatDateTimeLt(value: string): string {
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp)) return "Laikas nežinomas";
  return new Intl.DateTimeFormat("lt-LT", {
    dateStyle: "medium",
    timeStyle: "short",
    timeZone: "Europe/Vilnius",
  }).format(timestamp);
}

export function formatRelativeTimeLt(value: string, now = Date.now()): string {
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp)) return "laikas nežinomas";
  const difference = timestamp - now;
  const absolute = Math.abs(difference);
  if (absolute < 60_000) return "ką tik";
  if (absolute < 3_600_000) return relativeFormatter.format(Math.round(difference / 60_000), "minute");
  if (absolute < 86_400_000) return relativeFormatter.format(Math.round(difference / 3_600_000), "hour");
  return relativeFormatter.format(Math.round(difference / 86_400_000), "day");
}

export function formatNumberLt(value: number): string {
  return new Intl.NumberFormat("lt-LT").format(value);
}

export const statusLt = {
  active: "aktyvus",
  suspected: "įtariamas",
  offline: "nepasiekiamas",
  mitigated: "suvaldytas",
  unknown: "nežinomas",
} as const;

export const categoryLt: Record<string, string> = {
  banking: "bankininkystė",
  delivery: "siuntų pristatymas",
  government: "valstybės paslaugos",
  insurance: "draudimas",
  marketplace: "prekyvietė",
  payments: "mokėjimai",
  telecommunications: "telekomunikacijos",
  transport: "transportas",
  utilities: "komunalinės paslaugos",
};
