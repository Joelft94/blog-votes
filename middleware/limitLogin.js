import rateLimit from 'express-rate-limit';
import { supabase } from '../supabaseClient.js';


const loginAttempts = new Map();


const trackFailedAttempt = (email) => {
  const attempts = loginAttempts.get(email) || { count: 0, lastAttempt: Date.now() };
  attempts.count += 1;
  attempts.lastAttempt = Date.now();
  loginAttempts.set(email, attempts);
  
  return attempts.count;
};


const resetAttempts = (email) => {
  loginAttempts.delete(email);
};


const isBlocked = (email) => {
  const attempts = loginAttempts.get(email);
  if (!attempts) return false;

  // Reset attempts if 15 minutes have passed since last attempt
  if (Date.now() - attempts.lastAttempt > 15 * 60 * 1000) {
    resetAttempts(email);
    return false;
  }

  return attempts.count >= 5;
};


export const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit 100 x ip per window
  message: 'Too many requests from this IP, please try again later',
  standardHeaders: true,
  legacyHeaders: false,
});

export const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts per window
  message: 'Too many login attempts, please try again after 15 minutes',
  standardHeaders: true,
  legacyHeaders: false,
});


export const loginAttemptMiddleware = async (req, res, next) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).render('login', {
      error: 'Email is required',
      csrfToken: req.csrfToken()
    });
  }

  
  if (isBlocked(email)) {
    return res.status(429).render('login', {
      error: 'Account temporarily locked. Please try again after 15 minutes',
      csrfToken: req.csrfToken()
    });
  }

  
  const originalLogin = req.login;

  
  req.login = async function(email, password) {
    try {
      const { data, error } = await supabase.auth.signInWithPassword({
        email,
        password,
      });

      if (error) {
        const attempts = trackFailedAttempt(email);
        console.log(`Failed login attempt ${attempts} for email: ${email}`);
        
        if (attempts >= 5) {
          return {
            error: 'Account temporarily locked. Please try again after 15 minutes'
          };
        }
        
        return {
          error: `Invalid credentials. ${5 - attempts} attempts remaining`
        };
      }

      // Success - reset attempts
      resetAttempts(email);
      return { data };
    } catch (error) {
      console.error('Login error:', error);
      return { error: 'An error occurred during login' };
    }
  };

  next();
};