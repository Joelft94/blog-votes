import { supabase } from '../supabaseClient.js';

export const getDashboard = async (req, res) => {
  try {
    // Get total users count
    const { count: totalUsers, error: usersError } = await supabase
      .from('users')
      .select('*', { count: 'exact' });

    if (usersError) throw usersError;

    // Get total posts count
    const { count: totalPosts, error: postsError } = await supabase
      .from('posts')
      .select('*', { count: 'exact' });

    if (postsError) throw postsError;

    // Get recent signups
    const { data: recentSignups, error: signupsError } = await supabase
      .from('users')
      .select('id, email, created_at, user_roles(role)')
      .order('created_at', { ascending: false })
      .limit(10);

    if (signupsError) throw signupsError;

    res.render('admin/layout', {
      page: 'dashboard',
      stats: {
        totalUsers,
        totalPosts,
        recentSignups
      },
      user: req.user,
      csrfToken: req.csrfToken()
    });
  } catch (error) {
    console.error('Error fetching dashboard stats:', error);
    res.status(500).render('admin/layout', {
      page: 'dashboard',
      messages: { error: 'Error fetching dashboard statistics' },
      stats: { totalUsers: 0, totalPosts: 0, recentSignups: [] },
      user: req.user,
      csrfToken: req.csrfToken()
    });
  }
};

export const getUsersList = async (req, res) => {
  try {
    // Get all users with their roles
    const { data: users, error } = await supabase
      .from('users')
      .select(`
        *,
        user_roles (
          role
        )
      `);
    
    if (error) throw error;
    
    // Get any success/error messages from query params
    const messages = {
      success: req.query.success,
      error: req.query.error
    };

    res.render('admin/layout', { 
      page: 'users',
      users,
      messages,
      user: req.user,
      csrfToken: req.csrfToken()
    });
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).render('admin/layout', {
      page: 'users',
      users: [],
      messages: { error: error.message },
      user: req.user,
      csrfToken: req.csrfToken()
    });
  }
};

export const updateUserRole = async (req, res) => {
  const { userId } = req.params;
  const { newRole } = req.body;
  
  try {
    const { error: updateError } = await supabase
      .from('user_roles')
      .update({ role: newRole })
      .eq('user_id', userId);

    if (updateError) throw updateError;

    res.redirect('/admin/users?success=Role updated successfully');
  } catch (error) {
    console.error('Error updating role:', error);
    res.redirect('/admin/users?error=' + encodeURIComponent(error.message));
  }
};

export const deleteUser = async (req, res) => {
  const { userId } = req.params;
  
  try {
    // Delete user's posts
    await supabase
      .from('posts')
      .delete()
      .eq('user_id', userId);

    // Delete user's role
    await supabase
      .from('user_roles')
      .delete()
      .eq('user_id', userId);

    // Delete user
    const { error: deleteError } = await supabase.auth.admin.deleteUser(userId);
    if (deleteError) throw deleteError;

    res.redirect('/admin/users?success=User deleted successfully');
  } catch (error) {
    console.error('Error deleting user:', error);
    res.redirect('/admin/users?error=' + encodeURIComponent(error.message));
  }
};

export const getSecurityLogs = async (req, res) => {
  try {
    // Get failed login attempts
    const loginAttempts = global.loginAttempts || new Map();
    const failedLogins = Array.from(loginAttempts.entries()).map(([email, data]) => ({
      email,
      attempts: data.count,
      lastAttempt: new Date(data.lastAttempt).toLocaleString()
    }));

    // Get activity logs
    const { data: activityLogs, error: logsError } = await supabase
      .from('user_activity_logs')
      .select('*')
      .order('created_at', { ascending: false })
      .limit(100);

    if (logsError) throw logsError;

    res.render('admin/layout', {
      page: 'security-logs',
      failedLogins,
      activityLogs: activityLogs || [],
      user: req.user,
      csrfToken: req.csrfToken()
    });
  } catch (error) {
    console.error('Error fetching security logs:', error);
    res.status(500).render('admin/layout', {
      page: 'security-logs',
      failedLogins: [],
      activityLogs: [],
      messages: { error: 'Error fetching security logs' },
      user: req.user,
      csrfToken: req.csrfToken()
    });
  }
};