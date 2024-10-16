import { supabase } from '../supabaseClient.js';

class Post {
  static async getAll() {
    const { data, error } = await supabase
      .from('posts')
      .select('*')
      .order('votes', { ascending: false });

    if (error) throw error;
    return data;
  }

  static async getById(id) {
    const { data, error } = await supabase
      .from('posts')
      .select('*')
      .eq('id', id)
      .single();

    if (error) throw error;
    return data;
  }

  static async create(title, content, userId) {
    const { data, error } = await supabase
      .from('posts')
      .insert([{ title, content, user_id: userId }])
      .select();

    if (error) throw error;
    return data[0];
  }

  static async update(id, title, content) {
    const { data, error } = await supabase
      .from('posts')
      .update({ title, content })
      .eq('id', id)
      .select();

    if (error) throw error;
    return data[0];
  }

  static async delete(id) {
    const { error } = await supabase
      .from('posts')
      .delete()
      .eq('id', id);

    if (error) throw error;
  }

  static async vote(id) {
    console.log('Attempting to vote for post:', id);
  
    const { data, error } = await supabase
      .rpc('increment_votes', { input_post_id: id });
  
    if (error) {
      console.error('Error in vote method:', error);
      throw error;
    }
  
    if (!data || data.length === 0) {
      console.error('No data returned from increment_votes function');
      throw new Error('Vote failed: No data returned');
    }
  
    const updatedPost = {
      id: data[0].post_id,
      title: data[0].post_title,
      content: data[0].post_content,
      votes: data[0].post_votes,
      user_id: data[0].post_user_id,
      created_at: data[0].post_created_at,
      updated_at: data[0].post_updated_at
    };
  
    console.log('Vote successful, updated post:', updatedPost);
    return updatedPost;
  }
}

export default Post;