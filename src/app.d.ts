// See https://svelte.dev/docs/kit/types#app.d.ts
import type { Session } from '#lib/types.js';

declare global {
	namespace App {
		interface Locals {
			/** Session token from the HttpOnly cookie, once the API has confirmed it. */
			token: string | null;
			session: Session | null;
			/** Set when the session could not be checked because the API failed (not a 401). */
			sessionError: string | null;
		}
		// interface Error {}
		// interface PageData {}
		// interface PageState {}
		// interface Platform {}
	}
}

export {};
