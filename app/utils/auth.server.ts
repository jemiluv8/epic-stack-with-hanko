import { type Password, type User } from '@prisma/client'
import { redirect } from '@remix-run/node'
import bcrypt from 'bcryptjs'
import { Authenticator } from 'remix-auth'
import { FormStrategy } from 'remix-auth-form'
import { prisma } from '~/utils/db.server.ts'
import { invariant } from './misc.ts'
import { sessionStorage } from './session.server.ts'
import * as jose from "jose"

export type { User }

const JWKS_ENDPOINT = `${process.env.HANKO_API_URL}/.well-known/jwks.json`;

export const authenticator = new Authenticator<string>(sessionStorage, {
	sessionKey: 'sessionId',
})

const SESSION_EXPIRATION_TIME = 1000 * 60 * 60 * 24 * 30

authenticator.use(
	new FormStrategy(async ({ form }) => {
		const username = form.get('username')
		const password = form.get('password')

		invariant(typeof username === 'string', 'username must be a string')
		invariant(username.length > 0, 'username must not be empty')

		invariant(typeof password === 'string', 'password must be a string')
		invariant(password.length > 0, 'password must not be empty')

		const user = await verifyLogin(username, password)
		if (!user) {
			throw new Error('Invalid username or password')
		}
		const session = await prisma.session.create({
			data: {
				expirationDate: new Date(Date.now() + SESSION_EXPIRATION_TIME),
				userId: user.id,
			},
			select: { id: true },
		})

		return session.id
	}),
	FormStrategy.name,
)

function parseCookies (request: Request) {
    const list: Record<string, any> = {};
    const cookieHeader = request.headers.get("Cookie");
    if (!cookieHeader) return list;

    cookieHeader.split(`;`).forEach(function(cookie) {
        let [ name, ...rest] = cookie.split(`=`);
        name = name?.trim();
        if (!name) return;
        const value = rest.join(`=`).trim();
        if (!value) return;
        list[name] = decodeURIComponent(value);
    });

    return list;
}

export function getHankoToken(request: Request): string | undefined {
	const cookies = parseCookies(request)
	if (cookies.hanko) {
		return cookies.hanko
	}

	const authorization = request.headers.get("authorization");

	if (authorization && authorization.split(" ")[0] === "Bearer") {
		return authorization.split(" ")[1]
	}
}

async function getHankoSessionUser(request: Request) {
	// console.log(request.headers, request.cookies)
	const token = getHankoToken(request)
	if (token) {
		const JWKS_CONFIG = jose.createRemoteJWKSet(new URL(JWKS_ENDPOINT))

		const { payload } = await jose.jwtVerify(token, JWKS_CONFIG);
		console.log("payload", payload)
		return payload

		// const res = await fetch(JWKS_ENDPOINT)
		// const json = await res.json()
		// console.log("hanko jw", json)
		// const key = jose.JWK.createKeyStore(json)
		// key.add(jose.JWK.createKey(json, ))
		// const hankoVerifyResult = await jose.JWS.createVerify(json as any).verify(token)
		// console.log("hankoVerifyResult", hankoVerifyResult)
	}
  }

export async function requireUserId(
	request: Request,
	{ redirectTo }: { redirectTo?: string | null } = {},
) {
	const requestUrl = new URL(request.url)
	redirectTo =
		redirectTo === null
			? null
			: redirectTo ?? `${requestUrl.pathname}${requestUrl.search}`
	const loginParams = redirectTo
		? new URLSearchParams([['redirectTo', redirectTo]])
		: null
	const failureRedirect = ['/login', loginParams?.toString()]
		.filter(Boolean)
		.join('?')
	try {
		const hankoSessionUser = await getHankoSessionUser(request)
	
		if (hankoSessionUser) {
			return hankoSessionUser.sub
		}
		return redirect("/auth/signup")
	} catch (error) {
		console.log("ERROR VERIFYING STYFF", error)
		return null
	}
}

export async function getUserId(request: Request) {
	const userId = requireUserId(request)
	if (!userId) {
		// Perhaps their session was deleted?
		await authenticator.logout(request, { redirectTo: '/' })
		return null
	}
	return userId
}

export async function requireAnonymous(request: Request) {
	await authenticator.isAuthenticated(request, {
		successRedirect: '/',
	})
}

export async function resetUserPassword({
	username,
	password,
}: {
	username: User['username']
	password: string
}) {
	const hashedPassword = await bcrypt.hash(password, 10)
	return prisma.user.update({
		where: { username },
		data: {
			password: {
				update: {
					hash: hashedPassword,
				},
			},
		},
	})
}

export async function signup({
	email,
	username,
	password,
	name,
}: {
	email: User['email']
	username: User['username']
	name: User['name']
	password: string
}) {
	const hashedPassword = await getPasswordHash(password)

	const session = await prisma.session.create({
		data: {
			expirationDate: new Date(Date.now() + SESSION_EXPIRATION_TIME),
			user: {
				create: {
					email: email.toLowerCase(),
					username: username.toLowerCase(),
					name,
					password: {
						create: {
							hash: hashedPassword,
						},
					},
				},
			},
		},
		select: { id: true, expirationDate: true },
	})
	return session
}

export async function getPasswordHash(password: string) {
	const hash = await bcrypt.hash(password, 10)
	return hash
}

export async function verifyLogin(
	username: User['username'],
	password: Password['hash'],
) {
	const userWithPassword = await prisma.user.findUnique({
		where: { username },
		select: { id: true, password: { select: { hash: true } } },
	})

	if (!userWithPassword || !userWithPassword.password) {
		return null
	}

	const isValid = await bcrypt.compare(password, userWithPassword.password.hash)

	if (!isValid) {
		return null
	}

	return { id: userWithPassword.id }
}
