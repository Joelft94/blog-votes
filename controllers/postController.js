import Post from '../models/Post.js';

export const getAllPosts = async (req, res) => {
  try {
    const posts = await Post.getAll();
    res.render('index', { 
      posts, 
      user: req.user,
      layout: './layouts/layout'
    });

    console.log('Fetched posts:', posts);

  } catch (error) {
    console.error('Error fetching posts:', error);
    res.status(500).render('error', { 
      message: 'Error fetching posts', 
      user: req.user,
      layout: './layouts/layout'
    });
  }
};

export const getPost = async (req, res) => {
  try {
    const post = await Post.getById(req.params.id);
    if (!post) {
      return res.status(404).render('error', { 
        message: 'Post not found', 
        user: req.user,
        layout: './layouts/layout'
      });
    }
    res.render('post', { 
      post, 
      user: req.user,
      layout: './layouts/layout'
    });
  } catch (error) {
    console.error('Error fetching post:', error);
    res.status(500).render('error', { 
      message: 'Error fetching post', 
      user: req.user,
      layout: './layouts/layout'
    });
  }
};

export const getCreatePostForm = (req, res) => {
  if (!req.user) {
    return res.status(401).redirect('/login');
  }
  res.render('create', { 
    user: req.user,
    layout: './layouts/layout'
  });
};

export const createPost = async (req, res) => {
  if (!req.user) {
    return res.status(401).redirect('/login');
  }
  try {
    const { title, content } = req.body;
    const newPost = await Post.create(title, content, req.user.id);
    console.log('Created post:', data);
    res.redirect(`/post/${newPost.id}`);
  } catch (error) {
    console.error('Error creating post:', error);
    res.status(500).render('error', { 
      message: 'Error creating post', 
      user: req.user,
      layout: './layouts/layout'
    });
  }
};

export const getUpdatePostForm = async (req, res) => {
  if (!req.user) {
    return res.status(401).redirect('/login');
  }
  try {
    const post = await Post.getById(req.params.id);
    if (!post) {
      return res.status(404).render('error', { 
        message: 'Post not found', 
        user: req.user,
        layout: './layouts/layout'
      });
    }
    if (post.user_id !== req.user.id) {
      return res.status(403).render('error', { 
        message: 'You can only update your own posts', 
        user: req.user,
        layout: './layouts/layout'
      });
    }
    res.render('update', { 
      post, 
      user: req.user,
      layout: './layouts/layout'
    });
  } catch (error) {
    console.error('Error fetching post for update:', error);
    res.status(500).render('error', { 
      message: 'Error fetching post for update', 
      user: req.user,
      layout: './layouts/layout'
    });
  }
};

export const updatePost = async (req, res) => {
  if (!req.user) {
    return res.status(401).redirect('/login');
  }
  try {
    const { id } = req.params;
    const post = await Post.getById(id);
    if (!post) {
      return res.status(404).render('error', { 
        message: 'Post not found', 
        user: req.user,
        layout: './layouts/layout'
      });
    }
    if (post.user_id !== req.user.id) {
      return res.status(403).render('error', { 
        message: 'You can only update your own posts', 
        user: req.user,
        layout: './layouts/layout'
      });
    }
    const { title, content } = req.body;
    const updatedPost = await Post.update(id, title, content);
    res.redirect(`/post/${updatedPost.id}`);
  } catch (error) {
    console.error('Error updating post:', error);
    res.status(500).render('error', { 
      message: 'Error updating post', 
      user: req.user,
      layout: './layouts/layout'
    });
  }
};

export const deletePost = async (req, res) => {
  if (!req.user) {
    return res.status(401).redirect('/login');
  }
  try {
    const { id } = req.params;
    const post = await Post.getById(id);
    if (!post) {
      return res.status(404).render('error', { 
        message: 'Post not found', 
        user: req.user,
        layout: './layouts/layout'
      });
    }
    if (post.user_id !== req.user.id) {
      return res.status(403).render('error', { 
        message: 'You can only delete your own posts', 
        user: req.user,
        layout: './layouts/layout'
      });
    }
    await Post.delete(id);
    res.redirect('/');
  } catch (error) {
    console.error('Error deleting post:', error);
    res.status(500).render('error', { 
      message: 'Error deleting post', 
      user: req.user,
      layout: './layouts/layout'
    });
  }
};

export const votePost = async (req, res) => {
  console.log('User attempting to vote:', req.user);
  if (!req.user) {
    return res.status(401).json({ error: 'You must be logged in to vote' });
  }
  try {
    const updatedPost = await Post.vote(req.params.id);
    console.log('Vote successful, returning updated post:', updatedPost);
    
    // Check if it's an AJAX request
    if (req.xhr || req.headers.accept.indexOf('json') > -1) {
      return res.json({ votes: updatedPost.votes });
    } else {
      // For non-AJAX requests, redirect
      return res.redirect(`/post/${updatedPost.id}`);
    }
    
  } catch (error) {
    console.error('Error voting for post:', error);
    if (error.message.includes('not found')) {
      return res.status(404).json({ error: 'Post not found' });
    }
    if (req.xhr || req.headers.accept.indexOf('json') > -1) {
      return res.status(500).json({ error: error.message || 'An error occurred while voting for the post' });
    } else {
      return res.status(500).render('error', { message: error.message || 'An error occurred while voting for the post' });
    }
  }
};