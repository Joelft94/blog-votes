import { supabase } from '../supabaseClient.js';
import bcrypt from 'bcrypt';
import crypto from 'crypto';

const SALT_ROUNDS = 12;

// Store for failed attempts (in production, use Redis or a database)
const loginAttempts = new Map();

// Track failed login attempts
const trackFailedAttempt = (email) => {
  const attempts = loginAttempts.get(email) || { count: 0, lastAttempt: Date.now() };
  attempts.count += 1;
  attempts.lastAttempt = Date.now();
  loginAttempts.set(email, attempts);
  return attempts.count;
};

// Reset attempts for an email
const resetAttempts = (email) => {
  loginAttempts.delete(email);
};

// Check if user is blocked
const isBlocked = (email) => {
  const attempts = loginAttempts.get(email);
  if (!attempts) return false;
  if (Date.now() - attempts.lastAttempt > 15 * 60 * 1000) {
    resetAttempts(email);
    return false;
  }
  return attempts.count >= 5;
};

export const getRegisterForm = (req, res) => {
  res.render('register', { csrfToken: req.csrfToken() });
};

export const registerUser = async (req, res) => {
  const { email, password } = req.body;
  
  try {
    if (!password || password.length < 8) {
      throw new Error('Password must be at least 8 characters long');
    }

    // First sign up with Supabase auth
    const { data: authData, error: authError } = await supabase.auth.signUp({
      email,
      password,
    });
    
    if (authError) throw authError;

    // Check if user already exists in the users table
    const { data: existingUser, error: checkError } = await supabase
      .from('users')
      .select('id')
      .eq('id', authData.user.id)
      .single();

    if (!existingUser) {
      // Insert into users table if not exists
      const { error: userError } = await supabase
        .from('users')
        .insert([{
          id: authData.user.id,
          email: email,
          created_at: new Date().toISOString()
        }]);

      if (userError) throw userError;

      // Insert into user_roles table
      const { error: roleError } = await supabase
        .from('user_roles')
        .insert([{
          user_id: authData.user.id,
          role: 'user'
        }]);

      if (roleError) throw roleError;
    }

    res.redirect('/login?message=Registration successful. Please log in.');
  } catch (error) {
    console.error('Registration error:', error);
    
    // If there was an error, try to clean up any partial registration
    if (error.code === '23505') { // Duplicate key error
      res.status(400).render('register', {
        error: 'This email is already registered',
        csrfToken: req.csrfToken()
      });
    } else {
      res.status(500).render('register', {
        error: 'Registration failed. Please try again.',
        csrfToken: req.csrfToken()
      });
    }
  }
};

export const getLoginForm = (req, res) => {
  res.render('login', {
    error: undefined,
    message: req.query.message,
    csrfToken: req.csrfToken()
  });
};

export const loginUser = async (req, res) => {
  const { email, password } = req.body;
  
  try {
    if (isBlocked(email)) {
      return res.status(429).render('login', {
        error: 'Account temporarily locked. Please try again after 15 minutes',
        csrfToken: req.csrfToken()
      });
    }

    const { data, error } = await supabase.auth.signInWithPassword({
      email,
      password,
    });
    
    if (error) {
      const attempts = trackFailedAttempt(email);
      const remainingAttempts = 5 - attempts;
      
      return res.status(401).render('login', {
        error: `Invalid credentials. ${remainingAttempts} attempts remaining before temporary lockout.`,
        csrfToken: req.csrfToken()
      });
    }

    resetAttempts(email);

    res.cookie('access_token', data.session.access_token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    });

    res.redirect('/');
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).render('login', {
      error: error.message,
      csrfToken: req.csrfToken()
    });
  }
};


export const logoutUser = async (req, res) => {
  try {
    const { error } = await supabase.auth.signOut();
    if (error) throw error;

    // Clear all cookies
    res.clearCookie('access_token');
    res.clearCookie('XSRF-TOKEN');

    res.clearCookie('access_token');
    res.clearCookie('refresh_token');

    res.redirect('/login');
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).send('Error logging out');
  }
};

// Password reset functions
export const getRequestResetForm = (req, res) => {
  res.render('request-reset', {
    csrfToken: req.csrfToken()
  });
};

export const requestPasswordReset = async (req, res) => {
  const { email } = req.body;

  try {
    const { error } = await supabase.auth.resetPasswordForEmail(email, {
      redirectTo: `${process.env.APP_URL}/reset-password`,
    });

    if (error) throw error;

    // Using a generic message for security
    res.render('request-reset', {
      message: 'If an account exists with this email, password reset instructions will be sent.',
      csrfToken: req.csrfToken()
    });
  } catch (error) {
    console.error('Password reset request error:', error);
    res.status(500).render('request-reset', {
      error: 'There was an error processing your request. Please try again.',
      csrfToken: req.csrfToken()
    });
  }
};

export const getResetPasswordForm = (req, res) => {
  const { code } = req.query;

  if (!code) {
    return res.redirect('/request-reset-password');
  }

  res.render('reset-password', {
    csrfToken: req.csrfToken(),
    code
  });
};

export const resetPassword = async (req, res) => {
  const { password, confirmPassword } = req.body;

  try {

    if (password !== confirmPassword) {
      throw new Error('Passwords do not match');
    }

    if (password.length < 8) {
      throw new Error('Password must be at least 8 characters long');
    }


    const { error } = await supabase.auth.updateUser({
      password: password
    });

    if (error) throw error;

    res.render('login', {
      message: 'Password has been reset successfully. Please login with your new password.',
      csrfToken: req.csrfToken()
    });
  } catch (error) {
    console.error('Password reset error:', error);
    res.status(500).render('reset-password', {
      error: error.message,
      csrfToken: req.csrfToken()
    });
  }
};
