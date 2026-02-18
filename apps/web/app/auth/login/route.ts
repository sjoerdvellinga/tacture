// apps/web/app/auth/login/route.ts
import { NextResponse } from "next/server";

export const runtime = "nodejs";

function requireEnv(name: string) {
  const v = process.env[name];
  if (!v) throw new Error(`Missing env var: ${name}`);
  return v;
}

export async function GET(req: Request) {
  const url = new URL(req.url);
  const returnTo = url.searchParams.get("returnTo") || "/";

  let domain = requireEnv("COGNITO_DOMAIN").trim().replace(/\/$/, "");
  if (!domain.startsWith("http://") && !domain.startsWith("https://")) {
    domain = `https://${domain}`;
  }

  const clientId = requireEnv("COGNITO_CLIENT_ID");
  const redirectUri = requireEnv("COGNITO_REDIRECT_URI");

  const state = Buffer.from(
    JSON.stringify({ returnTo, t: Date.now() })
  ).toString("base64url");

  const authorize = new URL(`${domain}/oauth2/authorize`);
  authorize.searchParams.set("client_id", clientId);
  authorize.searchParams.set("response_type", "code");
  authorize.searchParams.set("scope", "openid email profile");
  authorize.searchParams.set("redirect_uri", redirectUri);
  authorize.searchParams.set("state", state);

  return NextResponse.redirect(authorize.toString());
}