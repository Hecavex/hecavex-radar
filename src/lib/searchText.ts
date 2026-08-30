/** Fold user-facing text for local, accent-insensitive filtering. */
export function foldSearchText(value: string, locale?: string): string {
  return value
    .normalize("NFKD")
    .replace(/\p{M}/gu, "")
    .toLocaleLowerCase(locale);
}
