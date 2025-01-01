/**
 * Welcome to Cloudflare Workers!
 *
 * This is a template for a Scheduled Worker: a Worker that can run on a
 * configurable interval:
 * https://developers.cloudflare.com/workers/platform/triggers/cron-triggers/
 *
 * - Run `npm run dev` in your terminal to start a development server
 * - Run `curl "http://localhost:8787/__scheduled?cron=*+*+*+*+*"` to see your worker in action
 * - Run `npm run deploy` to publish your worker
 *
 * Bind resources to your worker in `wrangler.toml`. After adding bindings, a type definition for the
 * `Env` object can be regenerated with `npm run cf-typegen`.
 *
 * Learn more at https://developers.cloudflare.com/workers/
 */

import { Resend } from 'resend';

interface ApiResponse {
	message: string;
	result: Array<{ '?column?': number }> | null;
}

export default {
	fetch(req, env, ctx) {
		return new Response('https://qmp.ezegatica.com', { status: 200 });
	},
	// The scheduled handler is invoked at the interval set in our wrangler.toml's
	// [[triggers]] configuration.
	async scheduled(event, env, ctx): Promise<void> {
		// A Cron Trigger can make requests to other endpoints on the Internet,
		// publish to a Queue, query a D1 Database, and much more.
		const prod = await fetch('https://qmp.ezegatica.com/api/health/db');
		if (!prod.ok) {
			return handleError(env, 
				`${prod.status} - ${prod.statusText} > ${await prod.text()}`
			);
		}

		const body = (await prod.json()) as ApiResponse;

		if (body.result == null) {
			return handleError(env, JSON.stringify(body));
		}

		// You could store this result in KV, write to a D1 Database, or publish to a Queue.
		// In this template, we'll just log the result:
		console.log(`${new Date().toLocaleString('es-AR')} > trigger fired at ${event.cron}: ${body.message}`);
	},
} satisfies ExportedHandler<Env>;

async function handleError(env: Env, message: string): Promise<void> {
	console.error(`${new Date().toLocaleString('es-AR')} > cron failed at: ${message}`);
	const resend = new Resend(env.RESEND_KEY);
	const { error } = await resend.emails.send({
		from: 'Alertas Sistemas: qmp <alerts@robot.ezegatica.com>',
		to: 'Eze <qmp@ezegatica.com>',
		subject: 'Base de datos de QMP caída',
		html: `
		<p>La pegada de hank (healthy) tiró error</p>
		<p><pre>${message}</pre></p>
		<hr>
		<a href="https://dash.cloudflare.com/c0d489e9d849b2347d806c2556279c9c/ezegatica.com">Link a Cloudflare</a> |
		<a href="https://supabase.com/dashboard/project/harbmctzkgwzpxyhsdiq">Link a Supabase</a> |
		<a href="https://vercel.com/gati/qmp">Link a Vercel</a> |
		<a href="https://qmp.ezegatica.com/app">Link a Que me Pongo</a>
		`,
	});
	if (error) {
		console.error(`${new Date().toLocaleString('es-AR')} > Error al enviar el mail: ${error}`);
	}
}
