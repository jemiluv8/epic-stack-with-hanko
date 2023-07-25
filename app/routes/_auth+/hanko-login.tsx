import {
	json,
	type DataFunctionArgs,
	type V2_MetaFunction,
    ActionArgs,
    redirect,
} from '@remix-run/node'
import { z } from 'zod'
import { useLoaderData, useSearchParams  } from '@remix-run/react'
import { GeneralErrorBoundary } from '~/components/error-boundary.tsx'
import { Spacer } from '~/components/spacer.tsx'
import { authenticator, createSessionForUserId, requireAnonymous } from '~/utils/auth.server.ts'
import { commitSession, getSession } from '~/utils/session.server.ts'
import { Verifier, unverifiedSessionKey } from '../resources+/verify.tsx'
import HankoAuth from '~/components/hanko-auth.tsx'
import { ClientOnly } from 'remix-utils'
import { parse } from '@conform-to/zod'

export async function loader({ request }: DataFunctionArgs) {
	await requireAnonymous(request)
	const session = await getSession(request.headers.get('cookie'))
	const error = session.get(authenticator.sessionErrorKey)
	let errorMessage: string | null = null
	if (typeof error?.message === 'string') {
		errorMessage = error.message
	}
	return json(
		{ formError: errorMessage, unverified: session.has(unverifiedSessionKey) },
		{
			headers: {
				'Set-Cookie': await commitSession(session),
			},
		},
	)
}

export const meta: V2_MetaFunction = () => {
	return [{ title: 'Login to Epic Notes' }]
}

const VerifyHankoSignUpSchema = z.object({
	email: z.string().email(),
})

export async function action({ request }: ActionArgs) {
    const formData = await request.formData()
	const submission = parse(formData, {
		schema: VerifyHankoSignUpSchema,
		acceptMultipleErrors: () => true,
	})
	if (!submission.value) {
		return json(
			{
				status: 'error',
				submission,
			} as const,
			{ status: 400 },
		)
	}

    // TODO: validate that user with email does not already exist.
    const existingUser = await prisma.user.findFirst({
        where: {
            email: submission.value.email,
        },
    })

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

        return json({ status: 'success', submission } as const, responseInit)
    }

	if (submission.intent !== 'submit') {
		return json({ status: 'success', submission } as const)
	}

	const session = await getSession(request.headers.get('Cookie'))
	session.set('onboardingEmail', submission.value.email)
	return redirect('/onboarding', {
		headers: { 'Set-Cookie': await commitSession(session) },
	})
}

export default function LoginPage() {
	const [searchParams] = useSearchParams()
	const data = useLoaderData<typeof loader>()

	const redirectTo = searchParams.get('redirectTo') || '/'

	return (
		<div className="flex min-h-full flex-col justify-center pb-32 pt-20">
			<div className="mx-auto w-full max-w-md">
				<div className="flex flex-col gap-3 text-center">
					<h1 className="text-h1">Welcome back!</h1>
				</div>
				
				<Spacer size="xs" />
				{data.unverified ? (
					<Verifier redirectTo={redirectTo} />
				) : (
					<ClientOnly>
						{ () => <HankoAuth redirectTo={redirectTo} /> }
					</ClientOnly>
				)}
			</div>
		</div>
	)
}

export function ErrorBoundary() {
	return <GeneralErrorBoundary />
}
