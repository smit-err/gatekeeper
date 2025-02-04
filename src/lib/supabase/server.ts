import { createServerClient } from "@supabase/ssr";
import { type SupabaseClient } from "@supabase/supabase-js";
import { cookies } from "next/headers";

export default async function createClient(): Promise<SupabaseClient> {
  if (
    !process.env.NEXT_PUBLIC_SUPABASE_URL ||
    !process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY
  ) {
    throw new Error("Missing Supabase environment variables");
  }

  const cookieStore = await cookies();

  try {
    const client = createServerClient(
      process.env.NEXT_PUBLIC_SUPABASE_URL,
      process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY,
      {
        cookies: {
          getAll: () => cookieStore.getAll(),

          setAll: (cookiesToSet) => {
            try {
              cookiesToSet.forEach(({ name, value, options }) => {
                cookieStore.set(name, value, options);
              });
            } catch (error) {
              console.error("Error setting multiple cookies:", error);
              throw new Error("Failed to set cookies");
            }
          },
        },
        auth: {
          detectSessionInUrl: true,
          persistSession: true,
        },
      }
    );

    return client;
  } catch (error) {
    console.error("Error creating Supabase client:", error);
    throw new Error("Failed to initialize Supabase client");
  }
}
