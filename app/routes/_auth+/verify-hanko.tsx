import { redirect, type DataFunctionArgs } from '@remix-run/node'
import { prisma } from '~/utils/db.server.ts'
import { commitSession, getSession } from '~/utils/session.server.ts'
import { authenticator, createSessionForUserId, getHankoSessionUser } from '~/utils/auth.server.ts'


export async function loader({ request }: DataFunctionArgs) {
    // validate hanko session
    const hankoSession = await getHankoSessionUser(request)
    console.log("HANKO SESSION", hankoSession)
    if (!hankoSession) {
        // verifying session here doesn't quite verify that the email is really
        // related to the session
        // so any auth user could manually use this endpoint to login as another user!
        return redirect("/login")
    }

    const params: URLSearchParams = new URL(request.url).searchParams
    const email = params.get('email');
    
    if (!email) {
        return redirect("/login")
    }

    // TODO: validate that user with email does not already exist.
    const existingUser = await prisma.user.findFirst({
        where: {
            email,
        },
    })

    console.log("existingUser", existingUser)

    if (existingUser) {
        // log user in how?
        const session = await createSessionForUserId(existingUser.id)
        const cookieSession = await getSession(request.headers.get('cookie'))
        cookieSession.set(authenticator.sessionKey, session.id)

        const remember = false //TODO: fix this
        
        const responseInit = {
            headers: {
                'Set-Cookie': await commitSession(cookieSession, {
                    // Cookies with no expiration are cleared when the tab/window closes
                    expires: remember ? session.expirationDate : undefined,
                }),
            },
        }

        return redirect(`/users/${existingUser.username}`, responseInit)
    }

	const session = await getSession(request.headers.get('Cookie'))
	session.set('onboardingEmail', email)
	return redirect('/onboarding', {
		headers: { 'Set-Cookie': await commitSession(session) },
	})
}
