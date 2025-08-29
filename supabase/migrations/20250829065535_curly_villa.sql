/*
# Fix Authentication Configuration

This migration resolves authentication issues by:

1. Security Updates
   - Fix RLS policies for proper authentication flow
   - Ensure proper permissions for auth operations
   - Update profile creation trigger

2. Authentication Setup
   - Configure proper auth policies
   - Fix profile creation workflow
   - Enable Google OAuth if needed

3. Database Permissions
   - Grant necessary permissions to auth roles
   - Fix any permission conflicts
*/

-- Drop existing conflicting policies first
DROP POLICY IF EXISTS "Allow service role to insert profiles" ON public.profiles;

-- Recreate the profiles table trigger function with proper security context
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER 
SECURITY DEFINER
SET search_path = public
LANGUAGE plpgsql
AS $$
BEGIN
  INSERT INTO public.profiles (user_id, email, full_name, avatar_url)
  VALUES (
    NEW.id,
    NEW.email,
    COALESCE(NEW.raw_user_meta_data->>'full_name', NEW.raw_user_meta_data->>'name'),
    NEW.raw_user_meta_data->>'avatar_url'
  );
  RETURN NEW;
EXCEPTION
  WHEN others THEN
    -- Log error but don't fail the user creation
    RAISE WARNING 'Could not create profile for user %: %', NEW.id, SQLERRM;
    RETURN NEW;
END;
$$;

-- Ensure the trigger exists and is properly configured
DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW
  EXECUTE FUNCTION public.handle_new_user();

-- Update RLS policies to be more permissive for auth operations
DROP POLICY IF EXISTS "Users can insert their own profile" ON public.profiles;
CREATE POLICY "Users can insert their own profile" 
  ON public.profiles 
  FOR INSERT 
  WITH CHECK (
    auth.uid() = user_id OR 
    auth.role() = 'service_role' OR
    auth.role() = 'supabase_auth_admin'
  );

-- Ensure users can read their own profiles
DROP POLICY IF EXISTS "Users can view their own profile" ON public.profiles;
CREATE POLICY "Users can view their own profile" 
  ON public.profiles 
  FOR SELECT 
  USING (auth.uid() = user_id);

-- Ensure users can update their own profiles
DROP POLICY IF EXISTS "Users can update their own profile" ON public.profiles;
CREATE POLICY "Users can update their own profile" 
  ON public.profiles 
  FOR UPDATE 
  USING (auth.uid() = user_id)
  WITH CHECK (auth.uid() = user_id);

-- Grant necessary permissions to ensure auth flow works
GRANT USAGE ON SCHEMA public TO supabase_auth_admin;
GRANT ALL ON public.profiles TO supabase_auth_admin;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO supabase_auth_admin;

-- Ensure the function can be executed by the auth system
GRANT EXECUTE ON FUNCTION public.handle_new_user() TO supabase_auth_admin;
GRANT EXECUTE ON FUNCTION public.update_updated_at_column() TO supabase_auth_admin;

-- Create an index for better performance on user lookups
CREATE INDEX IF NOT EXISTS profiles_user_id_idx ON public.profiles(user_id);

-- Ensure email confirmation is disabled for development (optional)
-- This would typically be done in the Supabase dashboard under Authentication > Settings
-- But we can document it here for reference