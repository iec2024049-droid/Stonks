import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { jwtVerify } from 'jose';

const encoder = new TextEncoder();

const ACCESS_COOKIE = 'stonks_access';
const REFRESH_COOKIE = 'stonks_refresh';

const ISSUER = 'stonks';
const AUDIENCE = 'stonks-web';

function getAccessSecret() {
  const secret = process.env.JWT_ACCESS_SECRET;
  return secret ? encoder.encode(secret) : null;
}

function getRefreshSecret() {
  const secret = process.env.JWT_REFRESH_SECRET;
  return secret ? encoder.encode(secret) : null;
}

export async function proxy(req: NextRequest) {
  // If secrets aren't set, don't block dev unexpectedly.
  const accessSecret = getAccessSecret();
  const refreshSecret = getRefreshSecret();
  if (!accessSecret || !refreshSecret) {
    return NextResponse.next();
  }

  const accessToken = req.cookies.get(ACCESS_COOKIE)?.value;
  if (accessToken) {
    try {
      await jwtVerify(accessToken, accessSecret, { issuer: ISSUER, audience: AUDIENCE });
      return NextResponse.next();
    } catch {
      // fall through to refresh attempt
    }
  }

  const refreshToken = req.cookies.get(REFRESH_COOKIE)?.value;
  if (!refreshToken) {
    const url = req.nextUrl.clone();
    url.pathname = '/login';
    return NextResponse.redirect(url);
  }

  try {
    const { payload } = await jwtVerify(refreshToken, refreshSecret, { issuer: ISSUER, audience: AUDIENCE });
    if (payload.type !== 'refresh' || !payload.sub || !payload.jti) {
      throw new Error('Invalid refresh token');
    }

    return NextResponse.next();
  } catch {
    const url = req.nextUrl.clone();
    url.pathname = '/login';
    const res = NextResponse.redirect(url);
    res.cookies.set({ name: ACCESS_COOKIE, value: '', maxAge: 0, path: '/' });
    res.cookies.set({ name: REFRESH_COOKIE, value: '', maxAge: 0, path: '/' });
    return res;
  }
}

export const config = {
  matcher: ['/dashboard/:path*'],
};
