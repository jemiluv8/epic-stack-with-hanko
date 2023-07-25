import { createCookieSessionStorage } from '@remix-run/node'

export const sessionStorage = createCookieSessionStorage({
	cookie: {
		name: '_session',
		sameSite: 'lax',
		path: '/',
		httpOnly: true,
		secrets: [process.env.SESSION_SECRET],
		secure: process.env.NODE_ENV === 'production',
	},
})

export const { getSession, commitSession, destroySession } = sessionStorage


export const hankoSessionStorage = createCookieSessionStorage({
	cookie: {
		name: 'hanko',
		sameSite: 'none',
		path: '/',
		httpOnly: false,
		secure: true
	},
})
