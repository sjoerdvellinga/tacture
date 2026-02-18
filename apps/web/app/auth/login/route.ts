import { NextResponse } from "next/server";

function requireEnv(name: string) {
  const v = process.env[name];
  if (!v) throw new Error(`Missing env var: ${name}`);
  return v;
}

export const runtime = "nodejs";

export async function GET(req: Request) {
  const url = new URL(req.url);

  let domain = requireEnv("COGNITO_DOMAIN").trim().replace(/\/$/, "");
  if (!domain.startsWith("http://") && !domain.startsWith("https://")) {
    domain = `https://${domain}`;
  }

  const clientId = requireEnv("COGNITO_CLIENT_ID");
  const redirectUri = requireEnv("COGNITO_REDIRECT_URI");

  // optioneel: returnTo (waar je heen wil na login)
  const returnTo = url.searchParams.get("returnTo") || "/";
  const state = encodeURIComponent(returnTo);

  const authorizeUrl = new URL(`${domain}/oauth2/authorize`);
  authorizeUrl.searchParams.set("client_id", clientId);
  authorizeUrl.searchParams.set("response_type", "code");
  authorizeUrl.searchParams.set("scope", "openid email profile");
  authorizeUrl.searchParams.set("redirect_uri", redirectUri);
  authorizeUrl.searchParams.set("state", state);

  return NextResponse.redirect(authorizeUrl.toString());
}