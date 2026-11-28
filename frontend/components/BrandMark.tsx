import mark from "@/app/brand-mark.png";

/** The RedWitness mark (the X from the logo). Imported as a static asset, so the build bundles it and no public/ folder is needed. */
export default function BrandMark({ size = 32, className = "" }: { size?: number; className?: string }) {
  return <img src={mark.src} width={size} height={size} alt="" aria-hidden="true" className={className} style={{ objectFit: "contain" }} />;
}
