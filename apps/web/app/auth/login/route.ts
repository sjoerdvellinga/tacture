// apps/web/app/auth/login/route.ts
import { NextResponse } from "next/server";

export const runtime = "nodejs";

function getEnv(name: string) {
  return process.env[name];
}

export async function GET(req: Request) {
  return NextResponse.json({
    MARKER: "debug-login-2026-02-18-2145",
    keys: Object.keys(process.env).filter(
      (k) => k.includes("COGNITO") || k.includes("AUTH")
    ),
    COGNITO_DOMAIN: process.env.COGNITO_DOMAIN ?? null,
    COGNITO_CLIENT_ID: process.env.COGNITO_CLIENT_ID ?? null,
    COGNITO_REDIRECT_URI: process.env.COGNITO_REDIRECT_URI ?? null,
  });
}