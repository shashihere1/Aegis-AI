// Class-name helper used by shadcn/ui components (imported as `cn` from "@/lib/utils").
// Merges conditional classes and resolves conflicting Tailwind utilities (later wins). Taught the project's
// custom text sizes and shadows so `text-caption text-muted` isn't treated as two colours.
import { clsx, type ClassValue } from "clsx";
import { extendTailwindMerge } from "tailwind-merge";

export type { ClassValue };

const twMerge = extendTailwindMerge({
  extend: { theme: { text: ["2xs", "caption"], shadow: ["card", "pop", "overlay", "soft"] } },
});

export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs));
}
