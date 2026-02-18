// apps/web/app/auth/login/route.ts
import { NextResponse } from "next/server";

export const runtime = "nodejs";

function getEnv(name: string) {
  return process.env[name];
}

export async function GET(req: Request) {
  const url = new URL(req.url);

  let returnTo = url.searchParams.get("returnTo") ?? "/";
  if (!returnTo.startsWith("/")) returnTo = "/";
  if (returnTo.startsWith("//")) returnTo = "/";

  let domain =
    getEnv("COGNITO_DOMAIN") ??
    getEnv("NEXT_PUBLIC_COGNITO_DOMAIN") ??
    "";

  if (!domain) {
    return NextResponse.json(
      { error: "missing_env", details: "COGNITO_DOMAIN is not set" },
      { status: 500 }
    );
  }

  domain = domain.trim().replace(/\/$/, "");
  if (!domain.startsWith("http://") && !domain.startsWith("https://")) {
    domain = `https://${domain}`;
  }

  const clientId =
    getEnv("COGNITO_CLIENT_ID") ??
    getEnv("NEXT_PUBLIC_COGNITO_CLIENT_ID") ??
    "";

  const redirectUri =
    getEnv("COGNITO_REDIRECT_URI") ??
    getEnv("NEXT_PUBLIC_COGNITO_REDIRECT_URI") ??
    "";

  if (!clientId || !redirectUri) {
    return NextResponse.json(
      {
        error: "missing_env",
        details: {
          COGNITO_CLIENT_ID: !!getEnv("COGNITO_CLIENT_ID"),
          COGNITO_REDIRECT_URI: !!getEnv("COGNITO_REDIRECT_URI"),
        },
      },
      { status: 500 }
    );
  }

  const authorizeUrl = new URL(`${domain}/oauth2/authorize`);
  authorizeUrl.searchParams.set("response_type", "code");
  authorizeUrl.searchParams.set("client_id", clientId);
  authorizeUrl.searchParams.set("redirect_uri", redirectUri);
  authorizeUrl.searchParams.set("scope", "openid email profile");
  authorizeUrl.searchParams.set("prompt", "login");

  authorizeUrl.searchParams.set(
    "state",
    Buffer.from(JSON.stringify({ returnTo })).toString("base64url")
  );

  return NextResponse.redirect(authorizeUrl.toString());
}