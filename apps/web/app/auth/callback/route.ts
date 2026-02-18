// apps/web/app/auth/callback/route.ts
import { NextResponse } from "next/server";
import { SignJWT } from "jose";

export const runtime = "nodejs"; // nodig voor Buffer/jose

function requireEnv(name: string) {
  const v = process.env[name];
  if (!v) throw new Error(`Missing env var: ${name}`);
  return v;
}

export async function GET(req: Request) {
  const url = new URL(req.url);

  const code = url.searchParams.get("code");
  const error = url.searchParams.get("error");
  const errorDescription = url.searchParams.get("error_description");

  if (error) {
    return NextResponse.json(
      { error, error_description: errorDescription },
      { status: 400 }
    );
  }

  if (!code) {
    return NextResponse.json({ error: "missing_code" }, { status: 400 });
  }

  // env vars
  let domain = requireEnv("COGNITO_DOMAIN").trim().replace(/\/$/, "");
  if (!domain.startsWith("http://") && !domain.startsWith("https://")) {
    domain = `https://${domain}`;
  }

  const clientId = requireEnv("COGNITO_CLIENT_ID");
  const clientSecret = requireEnv("COGNITO_CLIENT_SECRET");
  const redirectUri = requireEnv("COGNITO_REDIRECT_URI");
  const cookieSecret = requireEnv("AUTH_COOKIE_SECRET");

  const tokenUrl = `${domain}/oauth2/token`;

  const body = new URLSearchParams();
  body.set("grant_type", "authorization_code");
  body.set("client_id", clientId);
  body.set("code", code);
  body.set("redirect_uri", redirectUri);

  const basic = Buffer.from(`${clientId}:${clientSecret}`).toString("base64");

  const tokenRes = await fetch(tokenUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: `Basic ${basic}`,
    },
    body: body.toString(),
    cache: "no-store",
  });

  const tokenJson = await tokenRes.json();

  if (!tokenRes.ok) {
    return NextResponse.json(
      { error: "token_exchange_failed", details: tokenJson },
      { status: 400 }
    );
  }

  const accessToken = tokenJson.access_token as string | undefined;
  const idToken = tokenJson.id_token as string | undefined;
  const refreshToken = tokenJson.refresh_token as string | undefined;
  const expiresIn = Number(tokenJson.expires_in ?? 3600);

  if (!accessToken || !idToken) {
    return NextResponse.json(
      { error: "missing_tokens", details: tokenJson },
      { status: 400 }
    );
  }

  // session cookie jwt
  const secretKey = new TextEncoder().encode(cookieSecret);
  const expiresAt = Math.floor(Date.now() / 1000) + expiresIn;

  const sessionJwt = await new SignJWT({
    accessToken,
    idToken,
    refreshToken,
    expiresAt,
  })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt()
    .setExpirationTime(expiresAt)
    .sign(secretKey);

  // returnTo via state (base64url JSON)
  const state = url.searchParams.get("state");
  let returnTo = "/";

  if (state) {
    try {
      const parsed = JSON.parse(
        Buffer.from(state, "base64url").toString("utf8")
      );
      if (parsed?.returnTo && typeof parsed.returnTo === "string") {
        returnTo = parsed.returnTo;
      }
    } catch {
      // ignore invalid state
    }
  }

  const res = NextResponse.redirect(new URL(returnTo, req.url));

  res.cookies.set({
    name: "tacture_session",
    value: sessionJwt,
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    path: "/",
    maxAge: expiresIn,
  });

  return res;
}