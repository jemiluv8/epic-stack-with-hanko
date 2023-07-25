import { redirect, type DataFunctionArgs } from '@remix-run/node'
import { authenticator, getHankoSessionUser, getHankoToken } from '~/utils/auth.server.ts'
import { hankoSessionStorage } from '~/utils/session.server.ts'

export async function action({ request }: DataFunctionArgs) {

	const hankoSession = await getHankoSessionUser(request)
	if (hankoSession) {
		const token = getHankoToken(request)
		if (token) {
			try {
				await fetch(process.env.HANKO_API_URL + "/logout", {
					method: 'POST',
					headers: {
						authorization: `Bearer ${token}`
					}
				})
			} catch {}
		}
	}

	await authenticator.logout(request, { redirectTo: '/logout' })
}

export async function loader() {
	const hankoSession = await hankoSessionStorage.getSession()
	const unsetHankoHeaders = await hankoSessionStorage.destroySession(hankoSession)
	return redirect('/', {
		headers: {
			'Set-Cookie': unsetHankoHeaders
		}
	})
}
