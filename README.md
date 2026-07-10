## Run

```bash
deno task start
```

## Supabase auth integration

Set these environment variables:

```bash
SUPABASE_URL=https://<project-ref>.supabase.co
SUPABASE_PUBLISHABLE_KEY=<supabase-anon-key>
```

### Phase 1 (required auth fields only)

- `POST /register` with `email` and `password`
- `POST /login` with `email` and `password`

### Phase 2 (metadata + profile sync)

Send `metadata` in register payload. When `metadata` exists, the API upserts it into `profile` table using the newly created user's Supabase access token.

Example payload:

```json
{
  "email": "user@example.com",
  "password": "strong-password",
  "metadata": {
    "full_name": "Example User"
  }
}
```

### Supabase configuration steps

1. In Supabase dashboard, enable **Email** provider in Auth.
2. Create `profile` table (if not exists) with `id uuid primary key references auth.users (id) on delete cascade` and metadata columns you need (e.g. `full_name varchar(64)`). Run `supabase/migrations/0001_create_profile_table.sql` for a ready-made version, including an `updated_at` trigger.
3. Enable RLS on `profile`.
4. Add policy so authenticated users can upsert/select only their own row (`id = auth.uid()`).
5. Use the project URL + anon key in this service environment.

> The `id` column references `auth.users(id)` instead of using a standalone `gen_random_uuid()` default, since `saveProfileMetadata` (`src/services.ts`) always sets `id` explicitly to the authenticated user's UUID. Any column you add here must match a key you send in the `metadata` payload, otherwise PostgREST will reject the upsert with a "column not found" error.
