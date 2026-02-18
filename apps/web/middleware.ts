import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

export function middleware(req: NextRequest) {
  const { pathname, search } = req.nextUrl;

  // Laat auth routes en static assets door
  if (
    pathname.startsWith("/auth") ||
    pathname.startsWith("/_next") ||
    pathname === "/favicon.ico"
  ) {
    return NextResponse.next();
  }

  // Check sessie-cookie
  const session = req.cookies.get("tacture_session")?.value;

  if (!session) {
    const loginUrl = req.nextUrl.clone();
    loginUrl.pathname = "/auth/login";
    loginUrl.searchParams.set("returnTo", `${pathname}${search}`);
    return NextResponse.redirect(loginUrl);
  }

  return NextResponse.next();
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
};