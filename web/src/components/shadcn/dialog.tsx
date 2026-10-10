import * as React from "react";
import * as DialogPrimitive from "@radix-ui/react-dialog";
import { X } from "lucide-react";
import { cn } from "@/lib/utils";

// shadcn/ui Dialog, adapted to the Aegis tokens. Radix supplies focus trapping, Esc, scroll lock,
// aria-labelledby/-describedby wiring and focus return to the trigger.

const Dialog = DialogPrimitive.Root;
const DialogTrigger = DialogPrimitive.Trigger;
const DialogClose = DialogPrimitive.Close;
const DialogPortal = DialogPrimitive.Portal;
const DialogTitle = DialogPrimitive.Title;
const DialogDescription = DialogPrimitive.Description;

const DialogOverlay = React.forwardRef<
  React.ComponentRef<typeof DialogPrimitive.Overlay>,
  React.ComponentPropsWithoutRef<typeof DialogPrimitive.Overlay>
>(({ className, ...props }, ref) => (
  <DialogPrimitive.Overlay ref={ref} className={cn("data-[state=open]:animate-overlay fixed inset-0 z-40 bg-overlay backdrop-blur-[2px]", className)} {...props} />
));
DialogOverlay.displayName = "DialogOverlay";

type Side = "center" | "right" | "left";

const sideStyles: Record<Side, string> = {
  center:
    "data-[state=open]:animate-content top-1/2 left-1/2 max-h-[90vh] w-[calc(100%-2rem)] -translate-x-1/2 -translate-y-1/2 rounded-2xl border border-line",
  right: "data-[state=open]:animate-sheet-right inset-y-0 right-0 h-full w-full max-w-xl border-l border-line",
  left: "data-[state=open]:animate-sheet-left inset-y-0 left-0 h-full w-72 max-w-[85vw] border-r border-line",
};

const DialogContent = React.forwardRef<
  React.ComponentRef<typeof DialogPrimitive.Content>,
  React.ComponentPropsWithoutRef<typeof DialogPrimitive.Content> & { side?: Side }
>(({ className, side = "center", children, onInteractOutside, ...props }, ref) => (
  <DialogPortal>
    <DialogOverlay />
    <DialogPrimitive.Content
      ref={ref}
      onInteractOutside={(e) => {
        // Clicking a toast must not close the dialog underneath it.
        if ((e.target as HTMLElement | null)?.closest?.("[data-toast]")) e.preventDefault();
        onInteractOutside?.(e);
      }}
      className={cn("fixed z-40 flex flex-col overflow-hidden bg-card text-fg shadow-overlay outline-none", sideStyles[side], className)}
      {...props}
    >
      {children}
    </DialogPrimitive.Content>
  </DialogPortal>
));
DialogContent.displayName = "DialogContent";

function DialogCloseButton({ className }: { className?: string }) {
  return (
    <DialogPrimitive.Close
      className={cn(
        "grid size-8 shrink-0 place-items-center rounded-lg text-muted transition hover:bg-hover hover:text-fg focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent",
        className,
      )}
      aria-label="Close"
    >
      <X className="size-4" />
    </DialogPrimitive.Close>
  );
}

export { Dialog, DialogTrigger, DialogClose, DialogPortal, DialogOverlay, DialogContent, DialogTitle, DialogDescription, DialogCloseButton };
