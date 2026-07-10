CREATE OR REPLACE FUNCTION public.sync_profile_from_auth_user()
RETURNS trigger AS $$
BEGIN
  INSERT INTO public.profile (user_id, full_name)
  VALUES (NEW.id, NEW.raw_user_meta_data->>'full_name')
  ON CONFLICT (user_id)
  DO UPDATE SET
    full_name = EXCLUDED.full_name;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

DROP TRIGGER IF EXISTS on_auth_user_changed ON auth.users;

CREATE TRIGGER on_auth_user_changed
  AFTER INSERT OR UPDATE OF raw_user_meta_data ON auth.users
  FOR EACH ROW
  EXECUTE FUNCTION public.sync_profile_from_auth_user();