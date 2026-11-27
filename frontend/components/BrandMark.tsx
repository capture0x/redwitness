/** The RedWitness mark (an eye: the witness) as inline SVG, so it renders crisply at any size and needs no extra request. */
export default function BrandMark({ size = 32, className = "" }: { size?: number; className?: string }) {
  return (
    <svg viewBox="0 0 96 96" width={size} height={size} className={className} aria-hidden="true">
      <defs><linearGradient id="rw-mark" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stopColor="#f43f5e" /><stop offset="0.55" stopColor="#be185d" /><stop offset="1" stopColor="#6d28d9" /></linearGradient></defs>
      <rect width="96" height="96" rx="22" fill="url(#rw-mark)" />
      <path d="M14 48 C26 29 38 23 48 23 C58 23 70 29 82 48 C70 67 58 73 48 73 C38 73 26 67 14 48 Z" fill="none" stroke="#fff" strokeWidth="6" strokeLinejoin="round" />
      <circle cx="48" cy="48" r="13" fill="#fff" /><circle cx="48" cy="48" r="5.5" fill="#be185d" /><circle cx="52.5" cy="43.5" r="2.4" fill="#fff" />
    </svg>
  );
}
