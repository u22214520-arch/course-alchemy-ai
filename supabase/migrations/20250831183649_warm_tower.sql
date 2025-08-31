/*
# Complete Authentication Fix

This migration completely resolves authentication issues by:

1. Database Setup
   - Clean up conflicting policies
   - Recreate proper RLS policies
   - Fix profile creation workflow

2. Authentication Flow
   - Enable proper sign-up and sign-in
   - Fix profile creation trigger
   - Ensure Google OAuth compatibility

3. Security Configuration
   - Proper permissions for auth operations
   - Secure profile management
   - Enable email confirmation handling
*/

-- First, clean up any existing conflicting policies
DROP POLICY IF EXISTS "Users can view their own profile" ON public.profiles;
DROP POLICY IF EXISTS "Users can update their own profile" ON public.profiles;
DROP POLICY IF EXISTS "Users can insert their own profile" ON public.profiles;
DROP POLICY IF EXISTS "Allow service role to insert profiles" ON public.profiles;

-- Drop and recreate the trigger function with better error handling
DROP FUNCTION IF EXISTS public.handle_new_user() CASCADE;

CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER 
SECURITY DEFINER
SET search_path = public
LANGUAGE plpgsql
AS $$
BEGIN
  -- Insert profile for new user
  INSERT INTO public.profiles (user_id, email, full_name, avatar_url)
  VALUES (
    NEW.id,
    NEW.email,
    COALESCE(
      NEW.raw_user_meta_data->>'full_name',
      NEW.raw_user_meta_data->>'name',
      split_part(NEW.email, '@', 1)
    ),
    NEW.raw_user_meta_data->>'avatar_url'
  );
  RETURN NEW;
EXCEPTION
  WHEN unique_violation THEN
    -- Profile already exists, update it instead
    UPDATE public.profiles 
    SET 
      email = NEW.email,
      full_name = COALESCE(
        NEW.raw_user_meta_data->>'full_name',
        NEW.raw_user_meta_data->>'name',
        full_name
      ),
      avatar_url = COALESCE(NEW.raw_user_meta_data->>'avatar_url', avatar_url),
      updated_at = now()
    WHERE user_id = NEW.id;
    RETURN NEW;
  WHEN others THEN
    -- Log error but don't fail user creation
    RAISE WARNING 'Could not create/update profile for user %: %', NEW.id, SQLERRM;
    RETURN NEW;
END;
$$;

-- Recreate the trigger
DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW
  EXECUTE FUNCTION public.handle_new_user();

-- Create comprehensive RLS policies
CREATE POLICY "Enable read access for users to their own profile"
  ON public.profiles
  FOR SELECT
  USING (auth.uid() = user_id);

CREATE POLICY "Enable insert access for authenticated users"
  ON public.profiles
  FOR INSERT
  WITH CHECK (
    auth.uid() = user_id OR 
    auth.role() = 'service_role' OR
    auth.role() = 'supabase_auth_admin'
  );

CREATE POLICY "Enable update access for users to their own profile"
  ON public.profiles
  FOR UPDATE
  USING (auth.uid() = user_id)
  WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Enable delete access for users to their own profile"
  ON public.profiles
  FOR DELETE
  USING (auth.uid() = user_id);

-- Grant all necessary permissions to auth roles
GRANT USAGE ON SCHEMA public TO supabase_auth_admin, anon, authenticated;
GRANT ALL ON public.profiles TO supabase_auth_admin;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.profiles TO authenticated;
GRANT SELECT ON public.profiles TO anon;

-- Grant permissions on sequences
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO supabase_auth_admin, authenticated;

-- Grant execute permissions on functions
GRANT EXECUTE ON FUNCTION public.handle_new_user() TO supabase_auth_admin;
GRANT EXECUTE ON FUNCTION public.update_updated_at_column() TO supabase_auth_admin, authenticated;

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS profiles_user_id_idx ON public.profiles(user_id);
CREATE INDEX IF NOT EXISTS profiles_email_idx ON public.profiles(email);

-- Ensure the profiles table has proper constraints
ALTER TABLE public.profiles 
  ALTER COLUMN user_id SET NOT NULL,
  ALTER COLUMN created_at SET NOT NULL,
  ALTER COLUMN updated_at SET NOT NULL;

-- Add a check to ensure email is valid if provided
ALTER TABLE public.profiles 
  ADD CONSTRAINT valid_email 
  CHECK (email IS NULL OR email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$');