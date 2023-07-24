import { parse } from '@conform-to/zod'
import { json, type DataFunctionArgs } from '@remix-run/node'
import { z } from 'zod'
import { requireUserId } from '~/utils/auth.server.ts'
import { prisma } from '~/utils/db.server.ts'

export const ROUTE_PATH = '/resources/login-up/hanko'

const SignUpForm = z.object({
	email: z.string(),
})

// this is used by our hanko client to login/signup

export async function action({ request }: DataFunctionArgs) {
	const userId = await requireUserId(request, { redirectTo: null })
	const formData = await request.formData()
	const submission = parse(formData, {
		schema: SignUpForm,
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
	if (submission.intent !== 'submit') {
		return json({ status: 'success', submission } as const)
	}
	const { email } = submission.value
	const user = await prisma.user.findFirst({
		select: { id: true },
		where: {
			email
		},
	})
	if (!user) {
    // is sign up
		submission.error.imageId = ['Image not found']
		return json(
			{
				status: 'error',
				submission,
			} as const,
			{ status: 404 },
		)
	}

  // else sign the user in

	

	return json({ status: 'success' } as const)
}
