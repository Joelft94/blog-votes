import express from 'express';
import expressLayouts from 'express-ejs-layouts';
import bodyParser from 'body-parser';
import cookieParser from 'cookie-parser';
import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';
import { supabase } from './supabaseClient.js';
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
  logoutUser
} from './controllers/authController.js';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();


app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

app.use(expressLayouts);
app.set('layout', 'layouts/layout');

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// Auth middleware
app.use(async (req, res, next) => {
  const token = req.cookies.access_token;
  if (token) {
    const { data: { user }, error } = await supabase.auth.getUser(token);
    if (error) {
      console.error('Error fetching user:', error);
      res.clearCookie('access_token');
    } else {
      req.user = user;
    }
  }
  next();
});

app.use(express.static(path.join(__dirname, 'public')));

// Auth routes
app.get('/register', getRegisterForm);
app.post('/register', registerUser);
app.get('/login', getLoginForm);
app.post('/login', loginUser);
app.get('/logout', logoutUser);

// Post routes
app.get('/', getAllPosts);
app.get('/post/:id', getPost);
app.post('/post/:id/vote', votePost);
app.get('/create', getCreatePostForm);
app.post('/create', createPost);
app.get('/post/:id/update', getUpdatePostForm);
app.post('/post/:id/update', updatePost);
app.post('/post/:id/delete', deletePost);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port http://localhost:${PORT}`);
});