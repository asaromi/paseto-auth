import { Hono } from "hono";
import { login, refresh, verify } from "./controllers.ts";

export const routers = new Hono();

routers.get("/", (c) => c.text("Hello Hono!"));
routers.post("/login", login);
routers.get("/verify", verify);
routers.get("/refresh", refresh);
routers.get("/me", verify, (c) => c.json({ message: "Hello, me!" }))

export default routers;
