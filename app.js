import express from 'express';
import expressLayouts from 'express-ejs-layouts';
import bodyParser from 'body-parser';
import cookieParser from 'cookie-parser';
import helmet from 'helmet';
import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';
import { supabase } from './supabaseClient.js';
import { securityMiddleware } from './middleware/security.js';
import {
  getAllPosts,
  getPost,
  votePost,
  getCreatePostForm,
  createPost,
  getUpdatePostForm,
  updatePost,
  deletePost
} from './controllers/postController.js';
import {
  getRegisterForm,
  registerUser,
  getLoginForm,
  loginUser,
  logoutUser,
  requestPasswordReset,
  getRequestResetForm,  
  getResetPasswordForm, 
  resetPassword,        
} from './controllers/authController.js';
import {
  getDashboard,
  getUsersList,
  updateUserRole,
  deleteUser,
  getSecurityLogs
} from './controllers/adminController.js';
import { 
  loginLimiter, 
  loginAttemptMiddleware,
  csrfProtection,
  sessionMiddleware,
  requireRole,
  requireAdmin,
  securityHeaders,
  checkTokenExpiration,
} from './middleware/auth.js';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

// Security middleware
securityMiddleware(app);

// Helmet configuration
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:', 'https:'],
      connectSrc: ["'self'", process.env.SUPABASE_URL],
    },
  },
  xssFilter: true,
  noSniff: true,
  referrerPolicy: { policy: 'same-origin' }
}));

// View engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');
app.use(expressLayouts);
app.set('layout', 'layouts/layout');

// Essential middleware
app.use(cookieParser());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));

// Security middleware
app.use(securityHeaders);
app.use(sessionMiddleware);
app.use(checkTokenExpiration);
app.use(csrfProtection);

// Make CSRF token available to views
app.use((req, res, next) => {
  res.locals.csrfToken = req.csrfToken();
  next();
});

// Debug routes
app.get('/debug-role', (req, res) => {
  res.json({
    user: req.user,
    locals: res.locals.user,
    hasUser: !!req.user,
    role: req.user?.role
  });
});

app.get('/debug-auth-state', async (req, res) => {
  try {
    const { data: roleData } = await supabase
      .from('user_roles')
      .select('role')
      .eq('user_id', req.user?.id)
      .single();

    res.json({
      user: req.user,
      databaseRole: roleData?.role,
      sessionRole: req.user?.role,
      isAuthenticated: !!req.user,
      cookies: {
        hasAccessToken: !!req.cookies.access_token,
        hasRefreshToken: !!req.cookies.refresh_token
      }
    });
  } catch (error) {
    res.json({ error: error.message });
  }
});

// Auth routes
app.get('/register', getRegisterForm);
app.post('/register', csrfProtection, registerUser);
app.get('/login', getLoginForm);
app.post('/login', 
  loginLimiter,
  loginAttemptMiddleware,
  csrfProtection,
  loginUser
);
app.get('/logout', logoutUser);

// Password reset routes
app.get('/request-reset-password', getRequestResetForm);
app.post('/request-reset-password', csrfProtection, requestPasswordReset);
app.get('/reset-password', getResetPasswordForm);
app.post('/reset-password', csrfProtection, resetPassword);

// Admin routes
app.get('/admin/*', requireRole('admin'));
app.get('/admin/dashboard', requireAdmin, getDashboard);
app.get('/admin/users', requireAdmin, getUsersList);
app.post('/admin/users/:userId/role', requireAdmin, csrfProtection, updateUserRole);
app.post('/admin/users/:userId/delete', requireAdmin, csrfProtection, deleteUser);
app.get('/admin/security-logs', requireAdmin, getSecurityLogs);

// Post routes
app.get('/', getAllPosts);
app.get('/post/:id', getPost);
app.post('/post/:id/vote', csrfProtection, sessionMiddleware, votePost);
app.get('/create', sessionMiddleware, getCreatePostForm);
app.post('/create', csrfProtection, sessionMiddleware, createPost);
app.get('/post/:id/update', sessionMiddleware, getUpdatePostForm);
app.post('/post/:id/update', csrfProtection, sessionMiddleware, updatePost);
app.post('/post/:id/delete', csrfProtection, sessionMiddleware, deletePost);

// Error handler
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(err.status || 500).render('error', { 
    message: err.message || 'Something went wrong!',
    user: req.user
  });
});

// Simple server start
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port http://localhost:${PORT}`);
});

export default app;