import "@std/dotenv/load" // Otomatis membaca file .env di root folder

import { Hono } from 'hono'
import { cors } from "hono/cors"
import routers from './src/routes.ts'

const BASE_PATH = Deno.env.get("BASE_PATH") || ""
const HOST = Deno.env.get("HOST") || "0.0.0.0"
const PORT = Deno.env.get("PORT") || 3000

const app = BASE_PATH ? new Hono().basePath(BASE_PATH) : new Hono()

app.use('*', cors())
app.get('/.well-known/paseto-keys', async (c) => {
  const publicKey = Deno.env.get("PASETO_PUBLIC_KEY")
  const secretKey = Deno.env.get("PASETO_SECRET_KEY")

  return c.json({ public_key: publicKey || '', secret_key: secretKey || '' })
})

app.route('/', routers)

Deno.serve({
  hostname: HOST,
  port: PORT,
  onListen: () => console.log(`[START] Listening on http://${HOST}:${PORT}` + (BASE_PATH ? `/${BASE_PATH}` : '')),
}, app.fetch)
