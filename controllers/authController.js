import { supabase } from '../supabaseClient.js';

export const getRegisterForm = (req, res) => {
  res.render('register');
};

export const registerUser = async (req, res) => {
  const { email, password } = req.body;
  try {
    const { data, error } = await supabase.auth.signUp({
      email,
      password,
    });
    if (error) throw error;
    console.log('User registration data:', data);
    res.redirect('/login');
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).render('register', { error: error.message });
  }
};

export const getLoginForm = (req, res) => {
  res.render('login');
};

export const loginUser = async (req, res) => {
  const { email, password } = req.body;
  try {
    const { data, error } = await supabase.auth.signInWithPassword({
      email,
      password,
    });
    if (error) throw error;
    res.cookie('access_token', data.session.access_token, { httpOnly: true });
    res.redirect('/');
  } catch (error) {
    res.status(500).render('login', { error: error.message });
  }
};

export const logoutUser = async (req, res) => {
  try {
    const { error } = await supabase.auth.signOut();
    if (error) throw error;
    res.clearCookie('access_token');
    res.redirect('/login');
  } catch (error) {
    res.status(500).send('Error logging out');
  }
};