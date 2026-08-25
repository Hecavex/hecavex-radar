import brandRegistry from "../../data/brands-lt.json" with { type: "json" };

export type BrandEntry = {
  brand: string;
  lastReviewedAt: string;
  aliases: string[];
  fuzzyAliases?: string[];
  excludedTerms?: string[];
  excludedDomains?: string[];
  category: string;
  officialDomains: string[];
  sources: string[];
};

export const brandEntries = brandRegistry.entries as BrandEntry[];
export const brandRegistryReviewedAt = brandRegistry.reviewedAt;
export const brandRegistryScope = brandRegistry.scope;

export function brandSlug(value: string): string {
  return value
    .normalize("NFKD")
    .replace(/[\u0300-\u036f]/gu, "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/gu, "-")
    .replace(/^-+|-+$/gu, "");
}

export function brandPath(brand: string, language: "en" | "lt" = "en"): string {
  const slug = brandSlug(brand);
  return language === "lt" ? `/lt/prekes-zenklai/${slug}/` : `/brands/${slug}/`;
}

export function findBrand(value: string): BrandEntry | undefined {
  const slug = brandSlug(value);
  return brandEntries.find((entry) => brandSlug(entry.brand) === slug);
}

export function defangDomain(domain: string): string {
  return domain.replaceAll(".", "[.]");
}
