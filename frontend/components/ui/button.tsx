import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

const button = cva(
  "inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-lg text-[13px] font-medium transition-all duration-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-400/60 disabled:pointer-events-none disabled:opacity-40 active:scale-[.98]",
  {
    variants: {
      variant: {
        default: "bg-gradient-to-b from-indigo-500 to-indigo-600 text-snow shadow-pill ring-1 ring-inset ring-white/10 hover:from-indigo-400 hover:to-indigo-500",
        secondary: "glass text-slate-100 hover:border-white/[0.16]",
        ghost: "text-slate-300 hover:bg-white/[0.07] hover:text-white",
        danger: "bg-rose-600/90 text-snow ring-1 ring-inset ring-white/10 hover:bg-rose-500",
        outline: "border border-white/[0.12] text-slate-200 hover:border-indigo-400/50 hover:bg-indigo-500/10",
      },
      size: { default: "h-9 px-4", sm: "h-8 px-3 text-xs", lg: "h-11 px-6 text-sm", icon: "h-9 w-9" },
    },
    defaultVariants: { variant: "default", size: "default" },
  },
);
export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement>, VariantProps<typeof button> {}
export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(({ className, variant, size, ...p }, ref) => (
  <button ref={ref} className={cn(button({ variant, size }), className)} {...p} />
));
Button.displayName = "Button";
