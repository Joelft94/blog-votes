import rateLimit from 'express-rate-limit';
import csrf from 'csurf';
import { supabase } from '../supabaseClient.js';


const parseJWT = (token) => {
  try {
    return JSON.parse(atob(token.split('.')[1]));
  } catch (e) {
    return null;
  }
};


// CSRF Protection middleware
export const csrfProtection = csrf({ 
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict'
  }
});

// Rate limiter for login attempts
export const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts per window
  message: 'Too many login attempts, please try again after 15 minutes',
  standardHeaders: true,
  legacyHeaders: false,
});

// Store for failed attempts (in production, use Redis or a database)
const loginAttempts = new Map();

// Function to track failed attempts
const trackFailedAttempt = (email) => {
  const attempts = loginAttempts.get(email) || { count: 0, lastAttempt: Date.now() };
  attempts.count += 1;
  attempts.lastAttempt = Date.now();
  loginAttempts.set(email, attempts);
  return attempts.count;
};

// Function to reset attempts
const resetAttempts = (email) => {
  loginAttempts.delete(email);
};

// Function to check if user is blocked
const isBlocked = (email) => {
  const attempts = loginAttempts.get(email);
  if (!attempts) return false;

  // Reset attempts if 15 minutes have passed
  if (Date.now() - attempts.lastAttempt > 15 * 60 * 1000) {
    resetAttempts(email);
    return false;
  }

  return attempts.count >= 5;
};

// Login attempt tracking middleware
export const loginAttemptMiddleware = (req, res, next) => {
  const { email } = req.body;

  if (email && isBlocked(email)) {
    return res.status(429).render('login', {
      error: 'Account temporarily locked. Please try again after 15 minutes',
      csrfToken: req.csrfToken()
    });
  }

  // Attach helper functions to req object
  req.trackFailedAttempt = () => trackFailedAttempt(email);
  req.resetAttempts = () => resetAttempts(email);
  
  next();
};

// Session middleware with enhanced role checking
export const sessionMiddleware = async (req, res, next) => {
  const token = req.cookies.access_token;
  
  if (!token) {
    req.user = null;
    res.locals.user = null;
    return next();
  }

  try {
    // Get user from auth
    const { data: { user }, error: authError } = await supabase.auth.getUser(token);
    
    if (authError) {
      console.error('Auth error:', authError);
      res.clearCookie('access_token');
      res.clearCookie('refresh_token');
      req.user = null;
      res.locals.user = null;
      return next();
    }

    // Get role using direct SQL query to avoid RLS
    const { data: roleData, error: roleError } = await supabase
      .rpc('get_user_role', { input_user_id: user.id });

    console.log('Role fetch result:', { roleData, roleError });

    // Create sanitized user object
    const fullUser = {
      id: user.id,
      email: user.email,
      role: roleData || 'user',
      emailConfirmed: user.email_confirmed_at,
      lastSignIn: user.last_sign_in_at,
      created_at: user.created_at,
    };

    console.log('Session user constructed:', {
      id: fullUser.id,
      email: fullUser.email,
      role: fullUser.role
    });

    req.user = fullUser;
    res.locals.user = fullUser;

  } catch (error) {
    console.error('Session middleware error:', error);
    res.clearCookie('access_token');
    res.clearCookie('refresh_token');
    req.user = null;
    res.locals.user = null;
  }
  
  next();
};
// Generic role requirement middleware
export const requireRole = (requiredRole) => {
  return async (req, res, next) => {
    console.log('Starting role check:', {
      required: requiredRole,
      userRole: req.user?.role,
      userId: req.user?.id
    });

    if (!req.user) {
      return res.redirect('/login');
    }

    try {
      // Use RPC to check role
      const { data: userRole } = await supabase
        .rpc('get_user_role', { input_user_id: req.user.id });

      if (userRole !== requiredRole && userRole !== 'admin') {
        return res.status(403).render('error', {
          message: `Access denied: ${requiredRole} role required`,
          user: req.user
        });
      }

      next();
    } catch (error) {
      console.error('Role check error:', error);
      return res.status(500).render('error', {
        message: 'Error checking user role',
        user: req.user
      });
    }
  };
};
// Helper middleware to check admin role
export const requireAdmin = async (req, res, next) => {
  console.log('Starting admin check:', {
    userId: req.user?.id,
    currentRole: req.user?.role
  });

  if (!req.user) {
    return res.redirect('/login');
  }

  try {
    const { data: roleData, error: roleError } = await supabase
      .from('user_roles')
      .select('role')
      .eq('user_id', req.user.id)
      .single();

    if (roleError) {
      console.error('Admin role check error:', roleError);
      throw roleError;
    }

    const userRole = roleData?.role;
    console.log('Admin database role check:', userRole);

    // Update session role
    req.user.role = userRole;
    res.locals.user.role = userRole;

    if (userRole !== 'admin') {
      console.log('Admin access denied');
      return res.status(403).render('error', {
        message: 'Access denied: Admin privileges required',
        user: req.user
      });
    }

    console.log('Admin check passed');
    next();
  } catch (error) {
    console.error('Admin check error:', error);
    return res.status(500).render('error', {
      message: 'Error checking admin privileges',
      user: req.user
    });
  }
};
// Utility middleware to check token expiration
export const checkTokenExpiration = async (req, res, next) => {
  try {
    const token = req.cookies?.access_token;
    
    if (!token) {
      return next();
    }

    const tokenData = parseJWT(token);
    
    if (!tokenData) {
      res.clearCookie('access_token');
      return res.redirect('/login');
    }

    const expirationTime = tokenData.exp * 1000;
    
    // If token is expired or expires in 5 minutes
    if (Date.now() >= expirationTime - 5 * 60 * 1000) {
      const { data, error } = await supabase.auth.refreshSession({
        refresh_token: req.cookies?.refresh_token
      });
      
      if (data?.session) {
        // Set both access and refresh tokens
        res.cookie('access_token', data.session.access_token, {
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
          sameSite: 'strict',
          maxAge: 3600 * 1000 // 1 hour
        });
        
        res.cookie('refresh_token', data.session.refresh_token, {
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
          sameSite: 'strict',
          maxAge: 7 * 24 * 3600 * 1000 // 7 days
        });
      } else {
        // Clear cookies and redirect to login on refresh failure
        res.clearCookie('access_token');
        res.clearCookie('refresh_token');
        return res.redirect('/login');
      }
    }
  } catch (error) {
    // Clear cookies and redirect on any error
    res.clearCookie('access_token');
    res.clearCookie('refresh_token');
    return res.redirect('/login');
  }
  
  next();
};

// Security headers middleware
export const securityHeaders = (req, res, next) => {
  // Security headers
  const headers = {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',
    'Content-Security-Policy': "default-src 'self'; img-src 'self' data: https:; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';"
  };

  // Apply all headers
  Object.entries(headers).forEach(([key, value]) => {
    res.setHeader(key, value);
  });

  next();
};

const createRoleFunction = async () => {
  const { error } = await supabase.sql`
    CREATE OR REPLACE FUNCTION get_user_role(input_user_id UUID)
    RETURNS TEXT
    LANGUAGE plpgsql
    SECURITY DEFINER
    SET search_path = public
    AS $$
    DECLARE
      user_role TEXT;
    BEGIN
      SELECT role INTO user_role
      FROM user_roles
      WHERE user_id = input_user_id;
      RETURN COALESCE(user_role, 'user');
    END;
    $$;
  `;
  
  if (error) {
    console.error('Error creating role function:', error);
  }
};