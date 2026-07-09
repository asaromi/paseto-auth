## Run

```bash
deno task start
```

## Supabase auth integration

Set these environment variables:

```bash
SUPABASE_URL=https://<project-ref>.supabase.co
SUPABASE_ANON_KEY=<supabase-anon-key>
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
2. Create `profile` table (if not exists) with `id uuid primary key` and metadata columns you need.
3. Enable RLS on `profile`.
4. Add policy so authenticated users can upsert/select only their own row (`id = auth.uid()`).
5. Use the project URL + anon key in this service environment.
