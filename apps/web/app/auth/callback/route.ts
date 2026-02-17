// app/auth/callback/route.ts
import { NextResponse } from "next/server";
import { SignJWT } from "jose";

export const runtime = "nodejs"; // belangrijk: node runtime (niet edge) voor jose/Buffer

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

  // ✅ Vul dit in via .env.local
  // Bijvoorbeeld:
  // COGNITO_DOMAIN=https://eu-west-1kklggohln.auth.eu-west-1.amazoncognito.com
  // COGNITO_CLIENT_ID=...
  // COGNITO_CLIENT_SECRET=...
  // COGNITO_REDIRECT_URI=http://localhost:3000/auth/callback
  // SESSION_SECRET=een-lange-random-string (min 32 chars)
  let domain = requireEnv("COGNITO_DOMAIN").trim().replace(/\/$/, "");
  if (!domain.startsWith("http://") && !domain.startsWith("https://")) {
    domain = `https://${domain}`;
  }
  const clientId = requireEnv("COGNITO_CLIENT_ID");
  const clientSecret = requireEnv("COGNITO_CLIENT_SECRET");
  const redirectUri = requireEnv("COGNITO_REDIRECT_URI");
  const sessionSecret = requireEnv("AUTH_COOKIE_SECRET");

  const tokenUrl = `${domain}/oauth2/token`;

  const body = new URLSearchParams();
  body.set("grant_type", "authorization_code");
  body.set("client_id", clientId);
  body.set("code", code);
  body.set("redirect_uri", redirectUri);

  // Basic auth: base64(client_id:client_secret)
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
    // Cognito geeft vaak: error, error_description
    return NextResponse.json(
      { error: "token_exchange_failed", details: tokenJson },
      { status: 400 }
    );
  }

  // tokenJson bevat meestal: access_token, id_token, refresh_token?, expires_in, token_type
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

  // ✅ Maak een eigen sessie-cookie (httpOnly) door een “session JWT” te signen
  // Let op: dit is een pragmatische aanpak; later kun je refresh tokens server-side opslaan.
  const secretKey = new TextEncoder().encode(sessionSecret);
  const expiresAt = Math.floor(Date.now() / 1000) + expiresIn;

  const sessionJwt = await new SignJWT({
    accessToken,
    idToken,
    refreshToken, // kan undefined zijn; ok
    expiresAt,
  })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt()
    .setExpirationTime(expiresAt)
    .sign(secretKey);

  const res = NextResponse.redirect(new URL("/", req.url));

  res.cookies.set({
    name: "tacture_session",
    value: sessionJwt,
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    path: "/",
    maxAge: expiresIn, // seconds
  });

  return res;
}