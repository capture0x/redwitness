"use client";
import { createContext, useContext } from "react";

export type Role = "viewer" | "operator" | "admin";
export const RANK: Record<Role, number> = { viewer: 0, operator: 1, admin: 2 };
export const ROLE_LABEL: Record<Role, string> = { viewer: "Viewer", operator: "Operator", admin: "Admin" };
export type Me = { username: string; role: Role } | null;

export const MeContext = createContext<{ me: Me; can: (need: Role) => boolean }>({ me: null, can: () => false });
export const useMe = () => useContext(MeContext);

/** Page → minimum role. The server already enforces these rules; the UI only hides things so as not to mislead the user. */
export const ROUTE_ROLE: [string, Role][] = [["/users", "admin"], ["/settings", "admin"], ["/audit", "operator"], ["/new", "operator"]];
export const routeRole = (path: string): Role => ROUTE_ROLE.find(([p]) => path.startsWith(p))?.[1] ?? "viewer";
