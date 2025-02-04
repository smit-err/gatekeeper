"use server";

import { z } from "zod";

import { SignUpFormSchema } from "../validation/auth-schema";
import { SignInFormSchema } from "../validation/auth-schema";
import { ResetPasswordSchema } from "../validation/auth-schema";
import { ForgotPasswordSchema } from "../validation/auth-schema";
import { AuthError, Provider, User } from "@supabase/supabase-js";

import { createClient } from "@/lib/supabase/server";

type AuthResponse = {
  success: boolean;
  message: string;
  zod_errors?: z.inferFlattenedErrors<typeof SignUpFormSchema>["fieldErrors"];
};

type AuthSessionResponse = {
  success: boolean;
  message: string;
  user: User | null;
};

// sign up action
export async function signup(
  values: z.infer<typeof SignUpFormSchema>
): Promise<AuthResponse> {
  try {
    const validatedFields = SignUpFormSchema.safeParse(values);

    if (!validatedFields.success) {
      return {
        success: false,
        message: "Form validation error",
        zod_errors: validatedFields.error.flatten().fieldErrors,
      };
    }

    const supabase = await createClient();
    const { error } = await supabase.auth.signUp(validatedFields.data);

    if (error) throw error;

    return {
      success: true,
      message: "Account creation successful. Check email to verify.",
    };
  } catch (error) {
    console.error("[Auth] Error while sign up", error);
    return {
      success: false,
      message:
        error instanceof AuthError ? error.message : "Error while sign up",
    };
  }
}

// sign in action
export async function signin(
  values: z.infer<typeof SignInFormSchema>
): Promise<AuthResponse> {
  try {
    const validatedFields = SignInFormSchema.safeParse(values);

    if (!validatedFields.success) {
      return {
        success: false,
        message: "Form validation error",
        zod_errors: validatedFields.error.flatten().fieldErrors,
      };
    }

    const supabase = await createClient();

    const { error } = await supabase.auth.signInWithPassword(values);

    if (error) throw error;

    return {
      success: true,
      message: "Sign in successful",
    };
  } catch (error) {
    console.error("[Auth] Sign in failed", error);
    return {
      success: false,
      message: error instanceof AuthError ? error.message : "Sign in failed",
    };
  }
}

// sign in/up with OAuth
export async function signOAuth(provider: Provider): Promise<AuthResponse> {
  try {
    const supabase = await createClient();
    const { data, error } = await supabase.auth.signInWithOAuth({
      provider: provider,
      options: {
        redirectTo: "",
      },
    });

    if (error) throw error;

    if (!data) {
      return {
        success: false,
        message: "Failed to initiate OAuth signin",
      };
    }

    return {
      success: true,
      message: "OAuth signin successful",
    };
  } catch (error) {
    console.error("[Auth] OAuth signin error", error);
    return {
      success: false,
      message:
        error instanceof AuthError ? error.message : "OAuth signin error",
    };
  }
}

// forgot password (send reset link asking email)
export async function forgotPassword(
  email: z.infer<typeof ForgotPasswordSchema>
): Promise<AuthResponse> {
  try {
    const supabase = await createClient();

    const { error } = await supabase.auth.resetPasswordForEmail(email.email, {
      redirectTo: `${process.env.NEXT_PUBLIC_APP_URL}/reset-password`,
    });

    if (error) throw error;

    return {
      success: true,
      message: "Reset link sent. Please check.",
    };
  } catch (error) {
    console.error(
      "[Auth] Error occured while sending reset password link",
      error
    );
    return {
      success: false,
      message:
        error instanceof AuthError
          ? error.message
          : "Error occured while sending reset password link",
    };
  }
}

// reset password (update user, take new password as input)
export async function resetPassword(
  newPassword: z.infer<typeof ResetPasswordSchema>
): Promise<AuthResponse> {
  try {
    const supabase = await createClient();

    const { error } = await supabase.auth.updateUser({
      password: newPassword.password,
    });

    if (error) throw error;

    return {
      success: true,
      message: "Password reset successful. Please Sign in.",
    };
  } catch (error) {
    console.error("[Auth] Error while updating password", error);

    return {
      success: false,
      message:
        error instanceof AuthError
          ? error.message
          : "Error while updating password",
    };
  }
}

// sign out
export async function signout(): Promise<AuthResponse> {
  try {
    const supabase = await createClient();
    const { error } = await supabase.auth.signOut();

    if (error) throw error;

    return {
      success: true,
      message: "Sign out successful",
    };
  } catch (error) {
    console.error("[Auth] Error occured while sign out", error);
    return {
      success: false,
      message:
        error instanceof AuthError
          ? error.message
          : "Error occured while sign out",
    };
  }
}

// get current session on server
export async function getSession(): Promise<AuthSessionResponse> {
  try {
    const supabase = await createClient();

    const {
      data: { user },
      error,
    } = await supabase.auth.getUser();

    if (error) throw error;

    return {
      success: true,
      message: "Fetching user sesssion successful",
      user: user,
    };
  } catch (error) {
    console.error("[Auth] Error fetching session", error);
    return {
      success: false,
      message:
        error instanceof AuthError ? error.message : "Error fetching session",
      user: null,
    };
  }
}
