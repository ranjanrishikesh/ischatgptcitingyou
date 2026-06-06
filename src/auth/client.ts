"use client";
import { createAuthClient } from "better-auth/react";

// Same-origin; baseURL defaults to the current origin.
export const authClient = createAuthClient();
